"""
Minimal Scapy-based TCP reassembly (realtime)

- Reassembles TCP payloads per session BUFID = (src, dst, sport, dport)
- Maintains HDL (hole descriptor list) in absolute sequence number space
- Handles SYN (reset previous session), and FIN/RST (flush session -> produce datagram)
- API:
    r = TCPReassembly()
    r.process_packet(pkt, index=frame_no)   # call for each captured packet
    datagrams = r.get_datagrams()            # reassembled datagrams produced so far
    r.clear_datagrams()
    r.flush_all()                            # flush and produce for all buffers
"""
from scapy.all import sniff, IP, TCP
from scapy.utils import hexdump 
import sys
from typing import Dict, Tuple, List, Any, Optional

BUFID = Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)

class TCPReassembly:
    def __init__(self):
        # buffer[BUFID] = {
        #   'hdl': [ {'first': int_seq, 'last': int_seq}, ... ],
        #   ack_num (int): {
        #       'ind': [indexes],
        #       'isn': int,    # initial sequence number for this ack-buffer
        #       'len': int,    # current length of raw
        #       'raw': bytearray,
        #   }, ...
        # }
        self._buffer: Dict[BUFID, Dict] = {}
        # produced datagrams (list of dict)
        self._datagrams: List[Dict[str, Any]] = []

    # ---------- public helpers ----------
    def process_packet(self, pkt, index: Optional[int] = None):
        """Process a Scapy packet for reassembly. Call this for each captured packet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        if tcp.dport != 80:
            return
        
        payload = bytes(tcp.payload)
        has_payload = len(payload) > 0

        BUFID = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
        DSN = int(tcp.seq)
        ACK = int(tcp.ack)
        SYN = bool(tcp.flags & 0x02)
        FIN = bool(tcp.flags & 0x01)
        RST = bool(tcp.flags & 0x04)
        FIRST = DSN
        LAST = DSN + len(payload)

        # If SYN and an existing buffer exists => flush previous and delete
        if SYN and BUFID in self._buffer:
            self._submit_and_delete(BUFID, reason='syn_reset')

        # If buffer not exist, create new one
        if BUFID not in self._buffer:
            # Create HDL such that after first received fragment, missing region starts at DSN+len(payload)
            # We initialize HDL as wide open; we'll update after inserting fragment
            self._buffer[BUFID] = {
                'hdl': [],  # will set when first fragment arrives
            }

        # If no payload, still record ACK entry (to keep indices) and flush on FIN/RST if present
        if not has_payload:
            # ensure an ACK entry exists
            if ACK not in self._buffer[BUFID]:
                self._buffer[BUFID][ACK] = {
                    'ind': [index] if index is not None else [],
                    'isn': DSN,
                    'len': 0,
                    'raw': bytearray(),
                }
            else:
                if index is not None:
                    self._buffer[BUFID][ACK]['ind'].append(index)
            if FIN or RST:
                self._submit_and_delete(BUFID, reason='fin_or_rst_no_payload')
            return

        # Insert payload into ACK-specific block
        if ACK not in self._buffer[BUFID]:
            # create new block; set ISN to DSN and raw to payload
            self._buffer[BUFID][ACK] = {
                'ind': [index] if index is not None else [],
                'isn': DSN,
                'len': len(payload),
                'raw': bytearray(payload),
            }
            # If we just created first block in this session, initialize HDL to indicate missing after this fragment
            if not self._buffer[BUFID].get('hdl'):
                # Hole starts at LAST (next wanted seq) and is unbounded to the right
                self._buffer[BUFID]['hdl'] = [{'first': LAST, 'last': sys.maxsize}]
        else:
            # append index
            if index is not None:
                self._buffer[BUFID][ACK]['ind'].append(index)

            # merge fragment into existing raw
            block = self._buffer[BUFID][ACK]
            ISN = block['isn']
            RAW = block['raw']

            if DSN >= ISN:
                # fragment starts at or after ISN
                offset = DSN - ISN
                needed = offset + len(payload)
                if offset >= len(RAW):
                    # append gap (zeros) then payload
                    gap = offset - len(RAW)
                    if gap > 0:
                        RAW.extend(b'\x00' * gap)
                    RAW.extend(payload)
                else:
                    # overlapping or replacing bytes
                    endpos = offset + len(payload)
                    if endpos > len(RAW):
                        # extend to fit
                        RAW[offset:endpos] = payload
                    else:
                        RAW[offset:endpos] = payload
            else:
                # fragment starts before ISN -> need to prepend or overlap-left
                # compute overlap / gap relative to ISN
                delta = ISN - DSN  # bytes that fragment extends left of ISN
                if delta >= len(payload):
                    # fragment entirely before current RAW with gap
                    gap = delta - len(payload)
                    RAW = bytearray(payload + (b'\x00' * gap) + RAW)
                    block['isn'] = DSN
                else:
                    # partial overlap: prefix from payload that is before ISN, then remainder overlaps existing RAW
                    prefix = payload[:delta]
                    overlap = payload[delta:]
                    RAW = bytearray(prefix + RAW)
                    # now write overlap into RAW starting at position len(prefix)
                    pos = len(prefix)
                    need = pos + len(overlap)
                    if need > len(RAW):
                        RAW.extend(b'\x00' * (need - len(RAW)))
                    RAW[pos:pos + len(overlap)] = overlap
                    block['isn'] = DSN
            block['raw'] = RAW
            block['len'] = len(block['raw'])

        # Update HDL using RFC-815 like logic: holes described in absolute seq numbers
        HDL = self._buffer[BUFID].get('hdl', [])
        # If HDL empty, we can set a fresh hole starting after this block (LAST) if not set
        if not HDL:
            HDL = [{'first': LAST, 'last': sys.maxsize}]
            self._buffer[BUFID]['hdl'] = HDL

        # Find a hole that overlaps with [FIRST, LAST)
        for idx, hole in enumerate(list(HDL)):
            # If fragment entirely after this hole -> continue
            if FIRST > hole['last']:
                continue
            # If fragment entirely before this hole -> continue
            if LAST < hole['first']:
                continue
            # Overlap: remove current hole
            try:
                HDL.pop(idx)
            except Exception:
                # safe fallback: rebuild without this hole
                HDL = [h for h in HDL if h is not hole]
            # left leftover
            if FIRST > hole['first']:
                left = {'first': hole['first'], 'last': FIRST - 1}
                HDL.insert(idx, left)
                idx += 1
            # right leftover (only create if fragment does not finalize and not FIN/RST)
            if (LAST < hole['last']) and (not FIN) and (not RST):
                right = {'first': LAST + 1, 'last': hole['last']}
                HDL.insert(idx, right)
            break
        # store HDL back
        self._buffer[BUFID]['hdl'] = HDL

        # If FIN or RST present, flush session
        if FIN or RST:
            self._submit_and_delete(BUFID, reason='fin_or_rst')

    def _submit_and_delete(self, bufid: BUFID, reason: str = 'flush'):
        """Build datagrams from buffer[bufid] and remove the buffer."""
        if bufid not in self._buffer:
            return
        buf = self._buffer[bufid]
        HDL = buf.get('hdl', [])
        # iterate all ack-keys in buf (ints)
        for key, block in list(buf.items()):
            if key == 'hdl':
                continue
            if not isinstance(key, int):
                continue
            raw = block.get('raw', None)
            if not raw:
                continue
            payload_bytes = bytes(raw)
            datagram = {
                'NotImplemented': (len(HDL) != 0),  # True if holes remain
                'id': {
                    'src': (bufid[0], bufid[2]),
                    'dst': (bufid[1], bufid[3]),
                    'ack': key,
                },
                'index': tuple(block.get('ind', [])),
                'payload': payload_bytes,
                'packets': None,
                'flush_reason': reason,
            }
            self._datagrams.append(datagram)
        # finally delete buffer
        try:
            del self._buffer[bufid]
        except KeyError:
            pass

    def get_datagrams(self) -> List[Dict[str, Any]]:
        """Return list of produced datagrams (and keep them)."""
        return list(self._datagrams)

    def clear_datagrams(self):
        """Clear stored datagrams."""
        self._datagrams.clear()

    def flush_all(self):
        """Flush all active buffers (force produce datagrams) and clear buffers."""
        bufids = list(self._buffer.keys())
        for b in bufids:
            self._submit_and_delete(b, reason='manual_flush')

    def get_buffer_snapshot(self) -> Dict:
        """Debug helper: snapshot of current buffers and HDL."""
        snap = {}
        for k, v in self._buffer.items():
            snap[k] = {
                'hdl': v.get('hdl'),
                'acks': [x for x in v.keys() if isinstance(x, int)],
            }
        return snap

# ---------- Example runtime snippet ----------
def run_realtime(iface: str, bpf_filter: str = "tcp", timeout: Optional[int] = None):
    """Start sniffing on iface and reassemble TCP streams in realtime."""
    reasm = TCPReassembly()
    def handler(pkt):
        try:
            reasm.process_packet(pkt)
        except Exception:
            pass
    sniff(iface=iface, filter="tcp port 80", prn=handler, store=False, timeout=timeout)
    # After sniff finishes (or interrupted), you can get datagrams
    return reasm

# # If module executed directly, run quick example (requires root)
# if __name__ == "__main__":
#     import argparse, json, os

#     parser = argparse.ArgumentParser(description="Realtime TCP reassembly (Scapy).")
#     parser.add_argument("-i", "--iface", required=True, help="interface to sniff on (e.g. eth0)")
#     parser.add_argument("-t", "--timeout", type=int, default=None, help="sniff timeout seconds (optional)")
#     parser.add_argument("-o", "--output", default="example.log", help="log file path")
#     args = parser.parse_args()

#     log_file = args.output
#     # ensure log folder exists
#     os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

#     r = run_realtime(args.iface, timeout=args.timeout)

#     # with open(log_file, "w", encoding="utf-8") as f:
#     #     for d in r.get_datagrams():
#     #         entry = {
#     #             'id': d['id'],
#     #             'len': len(d['payload']),
#     #             'NotImplemented': d['NotImplemented'],
#     #             'reason': d.get('flush_reason'),
#     #             'payload_preview': d['payload'].decode('utf-8', errors='replace')  # chỉ ghi 200 byte đầu tiên, tránh quá dài
#     #         }
#     #         f.write(json.dumps(entry) + "\n")
#     #         # cũng in ra console
#     #         print("Logged:", entry)
#     for d in r.get_datagrams():
#         payload = d['payload']
#         if payload:
#             print(f"--- Datagram {d['id']} ---")
#             # in hexdump
#             hexdump(payload)
#             # in raw bytes nếu muốn
#             print("Raw bytes:", payload)
#             print()