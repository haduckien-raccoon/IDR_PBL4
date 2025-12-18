import socket
import sys
import threading
import time

try:
    import pcapy
except Exception as e:
    pcapy = None
    _PCAPY_IMPORT_ERROR = e

from .csv_writer import CSVWriter
from .flow import Flow
from .packet_parser import PacketScratch, parse_ipv4_tcp_udp_into

CSV_FILE = "data/live_flow.csv"

_FLOW_ACTIVITY_TIMEOUT_US = 1_000_000
_FLOW_TIMEOUT_S = 30.0  # max lifetime 30s
_SYN_FLUSH_PKT_THRESHOLD = 50
_CLEANUP_INTERVAL_S = 5.0


class FastSniffer:
    """Attack-aware flow sniffer (SYN-flood safe, CIC compatible)"""

    def __init__(self, bind_ip=None, iface=None, csv_file=CSV_FILE,
                 debug_print=False, stats=False, port_filter=None,
                 ai_callback=None):
        if not iface and not bind_ip:
            raise ValueError("You must specify iface or bind_ip")

        self.bind_ip = bind_ip
        self.iface = iface
        self._port_filter = port_filter

        self.flows = {}
        self.lock = threading.Lock()
        self.running = False

        self.cap = None
        self.dev = None
        self._datalink = None

        self.csv_writer = CSVWriter(csv_file, buffer_size=500)
        self._scratch = PacketScratch()

        self._debug_print = debug_print
        self._stats = stats

        self.ai_callback = ai_callback

    # ================= PCAP =================

    def _open_pcap(self, dev):
        return pcapy.open_live(dev, 65536, 1, 100)

    def _ipv4_view_from_l2(self, raw_data: bytes) -> memoryview:
        mv = memoryview(raw_data)
        datalink = int(self._datalink) if self._datalink is not None else 0

        if datalink == 1:  # Ethernet
            if len(mv) < 14:
                raise ValueError("frame too short for Ethernet")
            eth_type = (mv[12] << 8) | mv[13]
            offset = 14
            if eth_type == 0x8100:
                if len(mv) < 18:
                    raise ValueError("frame too short for VLAN")
                eth_type = (mv[16] << 8) | mv[17]
                offset = 18
            if eth_type != 0x0800:
                raise ValueError("non-IPv4 ethertype")
            return mv[offset:]
        if datalink == 113:  # Linux SLL
            if len(mv) < 16:
                raise ValueError("frame too short for Linux SLL")
            proto = (mv[14] << 8) | mv[15]
            if proto != 0x0800:
                raise ValueError("non-IPv4 SLL protocol")
            return mv[16:]
        if datalink == 12:  # RAW IP
            return mv
        if datalink == 0:  # NULL
            if len(mv) < 4:
                raise ValueError("frame too short for NULL")
            return mv[4:]
        return mv

    def _select_device_and_filter(self):
        devs = pcapy.findalldevs()
        if not devs:
            raise RuntimeError("No capture devices found")

        if self.iface:
            for d in devs:
                if self.iface.lower() in d.lower():
                    filt = f"host {self.bind_ip}" if self.bind_ip else None
                    return d, filt
            raise RuntimeError(f"Interface not found: {self.iface}")

        if self._port_filter:
            port_num = int(self._port_filter)
            port_filter_str = f"port {port_num}"
        else:
            port_filter_str = None

        if self.bind_ip and self.bind_ip in devs:
            return self.bind_ip, None

        raise RuntimeError("IP filter provided but no interface selected. Use --iface <name> together with IP.")

    # ================= START =================

    def start(self):
        try:
            self.dev, cap_filter = self._select_device_and_filter()
            self.cap = self._open_pcap(self.dev)
            self._datalink = int(self.cap.datalink())
            if cap_filter:
                self.cap.setfilter(cap_filter)
            self.running = True
        except Exception as e:
            print(f"❌ PCAP error: {e}", file=sys.stderr)
            return

        print(f"🚀 Sniffing on {self.dev}", file=sys.stderr)
        if cap_filter:
            print(f"🔎 Filter: {cap_filter}", file=sys.stderr)

        threading.Thread(target=self._flush_loop, daemon=True).start()

        while self.running:
            try:
                _, raw = self.cap.next()
                if not raw:
                    continue
                self._process_packet(raw)
            except Exception:
                break

        self._shutdown_flush()

    # ================= PACKET PROCESS =================

    def _process_packet(self, raw):
        try:
            ip_view = self._ipv4_view_from_l2(raw)
            parse_ipv4_tcp_udp_into(ip_view, self._scratch)

            now = time.time()
            proto = self._scratch.protocol
            tcp_flags = self._scratch.tcp_flags

            if self._port_filter is not None:
                port_num = int(self._port_filter)
                if (proto in (6, 17)) and (self._scratch.src_port != port_num and self._scratch.dst_port != port_num):
                    return

            if self._debug_print:
                print(
                    f"[PKT] {socket.inet_ntoa(self._scratch.src_ip_bytes)}:{self._scratch.src_port} "
                    f"→ {socket.inet_ntoa(self._scratch.dst_ip_bytes)}:{self._scratch.dst_port} "
                    f"proto={proto} len={self._scratch.payload_len} flags={tcp_flags}",
                    file=sys.stderr,
                )

            key = (self._scratch.src_ip_int, self._scratch.dst_ip_int, 0, proto)
            is_syn_only = (proto == 6 and (tcp_flags & 0x02) and not (tcp_flags & 0x10))
            flow_to_flush = None

            with self.lock:
                flow = self.flows.get(key)
                if not flow:
                    flow = Flow(
                        timestamp=now,
                        src_ip=socket.inet_ntoa(self._scratch.src_ip_bytes),
                        dst_ip=socket.inet_ntoa(self._scratch.dst_ip_bytes),
                        src_port=0,
                        dst_port=self._scratch.dst_port,
                        protocol=proto,
                        activity_timeout=_FLOW_ACTIVITY_TIMEOUT_US,
                    )
                    self.flows[key] = flow

                flow.update_primitives(
                    timestamp=now,
                    payload_len=self._scratch.payload_len,
                    header_len=self._scratch.header_len,
                    tcp_flags=tcp_flags,
                    protocol=proto,
                    is_forward=True,
                )

                # SYN flood early flush
                if is_syn_only and flow.fwd_pkts >= _SYN_FLUSH_PKT_THRESHOLD:
                    flow.is_terminated = True
                    flow_to_flush = self.flows.pop(key, None)

            if flow_to_flush:
                self.csv_writer.write_flow(flow_to_flush, "[SYN-FLOOD]")
                if self.ai_callback:
                    self.ai_callback(flow_to_flush)
                if self._debug_print:
                    self.csv_writer.flush()

        except Exception as e:
            if self._debug_print:
                print(f"[DEBUG] Packet parse/process failed: {type(e).__name__}: {e}", file=sys.stderr)

    # ================= FLUSH LOOP =================

    def _flush_loop(self):
        self.csv_writer.initialize()
        while self.running:
            time.sleep(_CLEANUP_INTERVAL_S)
            now = time.time()

            expired = []
            with self.lock:
                for k, f in list(self.flows.items()):
                    if now - f.last_time > _FLOW_TIMEOUT_S:
                        expired.append(self.flows.pop(k))

            for f in expired:
                self.csv_writer.write_flow(f, "[Timeout]")
                if self.ai_callback:
                    self.ai_callback(f)

            self.csv_writer.flush()

    # ================= SHUTDOWN =================

    def _shutdown_flush(self):
        with self.lock:
            flows = list(self.flows.values())
            self.flows.clear()

        for f in flows:
            self.csv_writer.write_flow(f, "[Shutdown]")
            if self.ai_callback:
                self.ai_callback(f)

        self.csv_writer.flush()
        self.csv_writer.close()

    def stop(self):
        self.running = False
        self._shutdown_flush()
