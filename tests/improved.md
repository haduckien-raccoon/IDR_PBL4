Bạn đang chạy 1 hàng đợi chung cho nhiều thread, nên reassembly sẽ bị “lệch” khi đa luồng. Dưới đây là bản triển khai worker pool 4 worker kiểu Snort 3.x: dispatcher shard theo flow và mỗi worker có IDS + TCPReassembler riêng. Mặc định chạy 4 worker; bạn có thể đổi bằng --workers.

1) Sửa IDS để bật/tắt watcher theo worker
````python
# ...existing code...
class IDS:
    def __init__(self, rules_path: Path, enable_decode: bool = False, payload_bytes: int = 4096, start_rules_watcher: bool = True):
        self._last_rules_event_time = 0
        self.rules_path = rules_path
        self.rules_raw = load_rules(rules_path)
        self.compiled = compile_rules(self.rules_raw)
        self.aho, self.aho_map = build_aho(self.compiled)
        self.enable_decode = enable_decode
        self.payload_bytes = int(payload_bytes)
        self.reasm = TCPReassembler()
        self.last_alerts: Dict[str, float] = {}
        self.alert_throttle = 2.0
        self.logged_payloads = set()
        self._logged_payloads_lock = threading.Lock()
        self._last_alerts_lock = threading.Lock()
        self.logged_payloads_cleanup_interval = 60
        self._last_cleanup = time.time()
        self.rules: Dict[str, Dict[str, Any]] = {rule_id(r): r for r in self.rules_raw}
        self.rules_map = {(r.get("uuid") or rule_id(r)): r for r in self.rules_raw}
        self.compiled_map = {}
        if start_rules_watcher:
            self._start_rules_watcher()
        self.http_parser = HTTPParser()
# ...existing code...
````

2) Thêm dispatcher shard theo flow + worker loop per-shard + khởi động pool
````python
# ...existing code...

# ============== FLOW HASH & DISPATCHER (MULTI-WORKER) ==============
def _flow_key(pkt) -> Optional[Tuple[Tuple[str,int], Tuple[str,int]]]:
    if IP not in pkt or TCP not in pkt:
        return None
    ip = pkt[IP]; t = pkt[TCP]
    a = (str(ip.src), int(t.sport))
    b = (str(ip.dst), int(t.dport))
    return (a, b) if a <= b else (b, a)

def _shard_for(pkt, shards: int) -> int:
    key = _flow_key(pkt)
    if key is None or shards <= 0:
        return 0
    return (hash(key) & 0x7fffffff) % shards

def _ingest_callback_factory(worker_queues: List["queue.Queue"], metrics: Dict[str, List[int]]):
    def ingest(pkt):
        s = _shard_for(pkt, len(worker_queues))
        q = worker_queues[s]
        try:
            q.put_nowait(pkt)
            metrics["enq"][s] += 1
        except queue.Full:
            metrics["drop"][s] += 1
    return ingest

def _worker_loop_shard(worker_id: int, ids: "IDS", q: "queue.Queue", stop_event: threading.Event, metrics: Dict[str, List[int]]):
    allowed_ports = {80}
    console_logger.info("Worker %d started", worker_id)
    while not stop_event.is_set():
        try:
            pkt = q.get(timeout=0.5)
        except queue.Empty:
            try:
                ids.reasm._cleanup()
            except Exception:
                pass
            continue
        try:
            if IP not in pkt:
                continue
            ip_pkt = pkt[IP]
            if TCP in ip_pkt:
                out = ids.reasm.feed(ip_pkt)
                if out:
                    assembled_bytes, conn_key = out
                    src, dst, sport, dport = conn_key
                    if int(dport) not in allowed_ports:
                        continue
                    meta = {"src": src, "dst": dst, "sport": int(sport), "dport": int(dport), "proto": "TCP"}
                    ids.match_payload(assembled_bytes, meta)
                else:
                    t = ip_pkt[TCP]
                    raw_payload = bytes(t.payload) if Raw in t and bytes(t.payload) else b""
                    if raw_payload and int(t.dport) in allowed_ports:
                        meta = {"src": ip_pkt.src, "dst": ip_pkt.dst, "sport": int(t.sport), "dport": int(t.dport), "proto": "TCP"}
                        ids.match_payload(raw_payload, meta)
                metrics["proc"][worker_id] += 1
        except Exception:
            console_logger.exception("Worker %d loop exception", worker_id)
        finally:
            try:
                q.task_done()
            except Exception:
                pass

def start_pool(primary_ids: "IDS", iface: str, bpf: str, num_workers: int):
    worker_queues: List["queue.Queue"] = [queue.Queue(maxsize=20000) for _ in range(num_workers)]
    metrics = {"enq": [0]*num_workers, "drop": [0]*num_workers, "proc": [0]*num_workers}
    stop_event = threading.Event()
    workers: List[threading.Thread] = []

    for i in range(num_workers):
        ids = IDS(RULES_PATH, enable_decode=primary_ids.enable_decode, payload_bytes=primary_ids.payload_bytes, start_rules_watcher=(i == 0))
        # chia sẻ artifacts đã compile (read-only)
        ids.compiled = primary_ids.compiled
        ids.aho, ids.aho_map = primary_ids.aho, primary_ids.aho_map
        ids.rules_raw = primary_ids.rules_raw
        ids.rules = primary_ids.rules
        ids.rules_map = primary_ids.rules_map

        th = threading.Thread(target=_worker_loop_shard, args=(i, ids, worker_queues[i], stop_event, metrics), daemon=True)
        th.start()
        workers.append(th)

    ingest = _ingest_callback_factory(worker_queues, metrics)

    console_logger.info("Starting sniffer - iface=%s filter=%s workers=%d", iface, bpf or "(none)", num_workers)
    try:
        sniff(iface=iface, filter=bpf, prn=ingest, store=False)
    except KeyboardInterrupt:
        console_logger.info("Stopping...")
    finally:
        stop_event.set()
        for th in workers:
            th.join(timeout=2.0)
        total_enq = sum(metrics["enq"])
        total_proc = sum(metrics["proc"])
        total_drop = sum(metrics["drop"])
        console_logger.info("Metrics: enq=%d proc=%d drop=%d", total_enq, total_proc, total_drop)
# ...existing code...
````

3) Sửa main để chạy 4 worker (mặc định) và dùng start_pool
````python
# ...existing code...
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--filter", default="tcp port 80")
    p.add_argument("--payload-bytes", type=int, default=8192)
    p.add_argument("--no-decode", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()

    if args.verbose:
        ch.setLevel(logging.DEBUG)
        console_logger.setLevel(logging.DEBUG)

    # IDS primary compile rules 1 lần
    primary = IDS(RULES_PATH, enable_decode=not args.no_decode, payload_bytes=args.payload_bytes, start_rules_watcher=True)
    # chạy pool với N worker (mặc định 4)
    start_pool(primary, args.iface, args.filter, args.workers)

if __name__ == "__main__":
    main()
# ...existing code...
````

Gợi ý chạy 4 worker trên Linux:
- Terminal:
  - sudo python ids_realtime_wkp.py --iface lo --filter "tcp port 80" --workers 4

Lưu ý:
- Mỗi worker có TCPReassembler riêng → an toàn reassembly đa luồng.
- Watcher rules chỉ bật ở worker 0 (primary clone), các worker khác dùng artifacts đã compile.
- Khối pkt_queue/enqueue/worker_loop cũ hiện không dùng nữa (giữ lại cũng không ảnh hưởng). Bạn có thể xóa để gọn.