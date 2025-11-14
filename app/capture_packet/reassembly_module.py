from __future__ import annotations
import sys
import os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
import argparse
import threading
import queue
import time
import logging
import re
import binascii
import math
import base64
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, Raw
from pathlib import Path
import json
import hashlib
from urllib.parse import unquote_plus
from typing import Dict, Any, Tuple, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
from typing import Deque
from collections import deque
import sys
import threading
from app.capture_packet.flowtracker_module import FlowTracker

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
        #Flow tracker can be added here if needed for advanced state tracking
        self.flow_tracker = FlowTracker()

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

        BUFID = (str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport))
        self.flow_tracker.update(BUFID, tcp, ip)
        DSN = int(tcp.seq)
        ACK = int(tcp.ack)
        SYN = bool(tcp.flags & 0x02)
        FIN = bool(tcp.flags & 0x01)
        RST = bool(tcp.flags & 0x04)
        FIRST = DSN
        LAST = DSN + len(payload)

        try: 
            self.flow_tracker.update(BUFID, tcp, ip)
        except Exception:
            pass

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
        # fetch all fragments (acks) and produce datagrams
        # pass pkt tuple None for now; can be extended if needed
        flow_info = self.flow_tracker.get_flow_safe(bufid, pkt=None)

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
                'flow': flow_info,
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

# ---------- Wrapper to expose feed(ip_pkt) API ----------
class TCPReassembler:
    """
    Wrapper around TCPReassembly that exposes `feed(ip_pkt)` returning either
    (assembled_bytes, (src, dst, sport, dport)) or None.
    It buffers multiple produced datagrams internally and returns one per call.
    """
    def __init__(self, timeout: int = 120):
        self.reasm = TCPReassembly()
        self.lock = threading.Lock()
        self._outq: Deque[Tuple[bytes, Tuple[str,str,int,int]]] = deque()
        # optional timeout attribute kept for compatibility with old class
        self.timeout = timeout

    def feed(self, ip_pkt) -> Optional[Tuple[bytes, Tuple[str,str,int,int]]]:
        # return any queued assembled datagram first
        with self.lock:
            if self._outq:
                return self._outq.popleft()

            # process incoming packet via standard reassembly
            try:
                self.reasm.process_packet(ip_pkt)
            except Exception:
                # avoid blowing up worker loop on unexpected pkt shapes
                # log if needed, but keep behavior silent here
                pass

            datagrams = self.reasm.get_datagrams()
            if not datagrams:
                return None

            # push all datagrams into outq (as (payload, key)), then clear
            for d in datagrams:
                payload = d.get('payload', b'')
                # datagram id: 'src': (ip, port), 'dst': (ip, port)
                idinfo = d.get('id', {})
                src = idinfo.get('src', (None, None))
                dst = idinfo.get('dst', (None, None))
                try:
                    key = (str(src[0]), str(dst[0]), int(src[1]), int(dst[1]) if dst[1] is not None else None)
                except Exception:
                    # fallback to values from packet if id formatting unexpected
                    try:
                        t = ip_pkt[TCP]
                        key = (str(ip_pkt[IP].src), str(ip_pkt[IP].dst), int(t.sport), int(t.dport))
                    except Exception:
                        key = (None, None, None, None)
                self._outq.append((payload, key))

            # clear datagrams stored in TCPReassembly to avoid duplication
            self.reasm.clear_datagrams()

            if self._outq:
                return self._outq.popleft()
            return None

    def _cleanup(self):
        # kept for API parity; reassembly uses internal cleanup via sys.maxsize holes,
        # you can implement timed connection culling here if needed.
        pass