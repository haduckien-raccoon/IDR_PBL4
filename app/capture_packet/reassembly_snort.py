from collections import deque
from typing import Dict, Tuple, List, Optional
import time

BUFID = Tuple[str, str, int, int]  # src_ip, dst_ip, sport, dport
SEQ_MAX = 0xFFFFFFFF

# ----------------- SEQ helpers -----------------
def seq_lt(a, b): return ((a - b) & 0xFFFFFFFF) >> 31 == 1
def seq_leq(a, b): return seq_lt(a, b) or a == b
def seq_gt(a, b): return seq_lt(b, a)
def seq_geq(a, b): return seq_gt(a, b) or a == b

# ----------------- Segment -----------------
class Segment:
    def __init__(self, seq: int, payload: bytes, flags: int, ts: float):
        self.seq = seq
        self.payload = payload
        self.flags = flags
        self.ts = ts

# ----------------- Flow -----------------
class Flow:
    def __init__(self, bufid: BUFID):
        self.bufid = bufid
        self.segments: deque[Segment] = deque()
        self.isn: Optional[int] = None
        self.last_active = time.time()
        self.assembled: bytearray = bytearray()
        self.holes: List[Tuple[int,int]] = []
        self.state: str = 'new'  # new, established, teardown

    def add_segment(self, seg: Segment, policy='linux'):
        # older-wins (Linux) overlap policy
        inserted = False
        for i, s in enumerate(self.segments):
            s_start, s_end = s.seq, s.seq + len(s.payload)
            seg_start, seg_end = seg.seq, seg.seq + len(seg.payload)
            if seq_lt(seg_end, s_start):
                self.segments.insert(i, seg)
                inserted = True
                break
            elif seq_gt(seg_start, s_end):
                continue
            else:
                # overlap handling: Linux older-wins
                prefix_len = max(0, s_start - seg_start)
                if prefix_len > 0:
                    new_seg = Segment(seg.seq, seg.payload[:prefix_len], seg.flags, seg.ts)
                    self.segments.insert(i, new_seg)
                inserted = True
                break
        if not inserted:
            self.segments.append(seg)
        self.last_active = time.time()
        # update flow state
        if seg.flags & 0x02:  # SYN
            self.state = 'established'
        if seg.flags & (0x01 | 0x04):  # FIN or RST
            self.state = 'teardown'

    def assemble(self, depth=20480) -> bytes:
        if not self.segments:
            return b''
        self.segments = deque(sorted(self.segments, key=lambda x: x.seq))
        assembled = bytearray()
        expected_seq = self.segments[0].seq
        for seg in self.segments:
            gap = seg.seq - expected_seq
            if gap > 0:
                assembled.extend(b'\x00' * gap)
            append_len = min(len(seg.payload), depth - len(assembled))
            assembled.extend(seg.payload[:append_len])
            expected_seq = seg.seq + len(seg.payload)
            if len(assembled) >= depth:
                break
        self.assembled = assembled
        return bytes(assembled)

# ----------------- Flow Tracker -----------------
class FlowTracker:
    def __init__(self, timeout=30, memcap=33554432):
        self.flows: Dict[BUFID, Flow] = {}
        self.timeout = timeout
        self.memcap = memcap

    def get_flow(self, bufid: BUFID) -> Optional[Flow]:
        return self.flows.get(bufid)

    def add_segment(self, bufid: BUFID, seq: int, payload: bytes, flags: int, policy='linux') -> Flow:
        if bufid not in self.flows:
            self.flows[bufid] = Flow(bufid)
        flow = self.flows[bufid]
        seg = Segment(seq, payload, flags, time.time())
        flow.add_segment(seg, policy=policy)
        return flow

    def prune_stale(self):
        now = time.time()
        stale = [bufid for bufid, f in self.flows.items() if now - f.last_active > self.timeout]
        for bufid in stale:
            del self.flows[bufid]

    def flush_flow(self, bufid: BUFID, depth=20480) -> Optional[Tuple[bytes, BUFID]]:
        flow = self.flows.get(bufid)
        if flow:
            assembled = flow.assemble(depth)
            del self.flows[bufid]
            return assembled, bufid
        return None

# ----------------- Stream5 Reassembler with Flow Tracker -----------------
class Stream5Reassembler:
    def __init__(self, os_policy='linux', reassembly_depth=20480, min_segment_size=3,
                 max_queued_segs=262144, midstream_pickup=False, timeout=30, memcap=33554432):
        self.policy = os_policy
        self.depth = reassembly_depth
        self.min_segment_size = min_segment_size
        self.max_queued_segs = max_queued_segs
        self.midstream_pickup = midstream_pickup
        self.flow_tracker = FlowTracker(timeout, memcap)

    def feed(self, bufid: BUFID, seq: int, payload: bytes, flags: int) -> Optional[Tuple[bytes, BUFID]]:
        # midstream pickup
        if not self.midstream_pickup and not (flags & 0x02) and bufid not in self.flow_tracker.flows:
            return None
        flow = self.flow_tracker.add_segment(bufid, seq, payload, flags, self.policy)
        # flush on FIN or RST
        if flags & (0x01 | 0x04):
            return self.flow_tracker.flush_flow(bufid, self.depth)
        return None

    def prune(self):
        self.flow_tracker.prune_stale()

    def flush_all(self) -> List[Tuple[bytes, BUFID]]:
        results = []
        for bufid in list(self.flow_tracker.flows.keys()):
            res = self.flow_tracker.flush_flow(bufid, self.depth)
            if res:
                results.append(res)
        return results
