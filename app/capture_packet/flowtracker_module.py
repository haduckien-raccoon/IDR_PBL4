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

BUFID = Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)

# ----------------- FlowTracker class -----------------
class FlowTracker:
    """
    Lightweight flow-state engine.
    - canonicalizes connection key across both directions
    - discovers client (initiator) from SYN (SYN w/o ACK), or first-seen endpoint as fallback
    - state transitions: unknown -> syn_sent -> syn_ack -> established -> teardown
    - direction relative to client: to_server / to_client
    """
    def __init__(self, stale_timeout: int = 300):
        # key: conn_key = ((ip,port),(ip,port)) ordered tuple
        # value: {
        #   'client': (ip,port),
        #   'server': (ip,port),
        #   'state': 'unknown'|'syn_sent'|'syn_ack'|'established'|'teardown',
        #   'last_seen': epoch,
        # }
        self._flows: Dict[Tuple[Tuple[str,int], Tuple[str,int]], Dict[str, Any]] = {}
        self.stale_timeout = stale_timeout
        self._lock = threading.Lock()

    # helpers
    def _normalize_conn(self, bufid: BUFID):
        src_ep = (bufid[0], bufid[2])
        dst_ep = (bufid[1], bufid[3])
        # deterministic ordering
        if src_ep <= dst_ep:
            return (src_ep, dst_ep), src_ep, dst_ep
        else:
            return (dst_ep, src_ep), dst_ep, src_ep

    def update(self, bufid: BUFID, tcp_pkt: TCP, ip_pkt: IP):
        """Update flow state from a packet. Thread-safe."""
        now = time.time()
        conn_key, ep_a, ep_b = self._normalize_conn(bufid)
        src_ep = (ip_pkt.src, int(tcp_pkt.sport))
        dst_ep = (ip_pkt.dst, int(tcp_pkt.dport))

        SYN = bool(tcp_pkt.flags & 0x02)
        ACK = bool(tcp_pkt.flags & 0x10)
        FIN = bool(tcp_pkt.flags & 0x01)
        RST = bool(tcp_pkt.flags & 0x04)

        with self._lock:
            flow = self._flows.get(conn_key)
            # create if not exist
            if not flow:
                # assume client is the endpoint that initiated SYN without ACK, otherwise the first-seen src_ep
                client_ep = src_ep if SYN and not ACK else src_ep
                server_ep = dst_ep if client_ep == src_ep else src_ep if client_ep == dst_ep else dst_ep
                init_state = 'syn_sent' if SYN and not ACK else 'unknown'
                flow = {
                    'client': client_ep,
                    'server': server_ep,
                    'state': init_state,
                    'last_seen': now,
                }
                self._flows[conn_key] = flow
            else:
                # if we see a SYN without ACK later, set client if unknown
                if SYN and not ACK and flow.get('state') == 'unknown':
                    flow['client'] = src_ep
                    flow['server'] = dst_ep
                    flow['state'] = 'syn_sent'

            # state machine transitions
            st = flow.get('state', 'unknown')
            # If we saw SYN (from client) -> syn_sent (already set above)
            if st == 'syn_sent':
                # expecting SYN+ACK from server (server->client carrying SYN+ACK)
                if SYN and ACK and src_ep == flow.get('server'):
                    flow['state'] = 'syn_ack'
                # or if we see client's final ACK (ACK without SYN) -> established
                if ACK and not SYN and src_ep == flow.get('client'):
                    flow['state'] = 'established'
            elif st == 'syn_ack':
                # after syn_ack, expect final ack from client
                if ACK and not SYN and src_ep == flow.get('client'):
                    flow['state'] = 'established'
            elif st == 'unknown':
                # if we see ACK-only traffic, promote to established (best-effort)
                if ACK and not SYN:
                    flow['state'] = 'established'
            # any FIN or RST => teardown
            if FIN or RST:
                flow['state'] = 'teardown'

            flow['last_seen'] = now
            # store back
            self._flows[conn_key] = flow
            return flow.copy()

    def get_flow(self, bufid: BUFID) -> Optional[Dict[str, Any]]:
        """Return flow dict for this bufid (may be None)."""
        conn_key, _, _ = self._normalize_conn(bufid)
        with self._lock:
            f = self._flows.get(conn_key)
            if not f:
                return None
            # compute direction relative to client
            return {
                'client': f['client'],
                'server': f['server'],
                'state': f['state'],
                'direction': None,  # caller can compute based on packet if needed
                'last_seen': f['last_seen'],
            }

    def get_flow_safe(self, bufid: BUFID, pkt: Optional[Tuple[IP,TCP]] = None) -> Dict[str, Any]:
        """
        Return a non-None flow dict. If no flow exists, return default 'unknown'.
        If pkt provided, compute 'direction' field relative to client using pkt IP/TCP.
        """
        default = {'client': None, 'server': None, 'state': 'unknown', 'direction': 'unknown', 'last_seen': None}
        f = self.get_flow(bufid)
        if not f:
            return default
        if pkt is not None:
            ip_pkt, tcp_pkt = pkt
            src_ep = (ip_pkt.src, int(tcp_pkt.sport))
            f['direction'] = 'to_server' if src_ep == f['client'] else 'to_client'
        else:
            f['direction'] = 'unknown'
        return f

    def delete_flow(self, bufid: BUFID):
        conn_key, _, _ = self._normalize_conn(bufid)
        with self._lock:
            try:
                del self._flows[conn_key]
            except KeyError:
                pass

    def prune_stale(self):
        """Remove flows not seen for stale_timeout seconds."""
        cutoff = time.time() - self.stale_timeout
        with self._lock:
            stale = [k for k, v in self._flows.items() if v.get('last_seen', 0) < cutoff]
            for k in stale:
                del self._flows[k]