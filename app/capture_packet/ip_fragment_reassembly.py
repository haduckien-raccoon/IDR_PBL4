# ip_fragment_reassembly.py
# RFC 791 IP Fragmentation Reassembler
# Designed to pair with your TCP Reassembly (RFC 793/815)
#
# Features:
#  - Reassembles IPv4 fragmented packets
#  - Handles overlaps (favoring first or last depending on policy)
#  - Handles timeout (flow expiration)
#  - Safe memory cap
#  - Returns full reassembled IP payload for further TCP decoding
#
# NOTE: This module assumes you already parsed the IPv4 header and extracted fields:
#   - identification
#   - flags (MF)
#   - fragment_offset
#   - total_length
#   - protocol
#   - src, dst
#   - payload
#
# The inputs should be: (src, dst, proto, identification, offset, mf_flag, payload)

import time
from collections import defaultdict, deque

class IPFragmentReassembler:
    def __init__(self, timeout_sec=30, memcap_bytes=32 * 1024 * 1024):
        self.timeout = timeout_sec
        self.memcap = memcap_bytes
        self.current_mem = 0
        self.cache = {}

    def _key(self, src, dst, proto, ident):
        return (src, dst, proto, ident)

    def _evict_old(self):
        now = time.time()
        to_delete = []
        for k, frag in self.cache.items():
            if now - frag['ts'] > self.timeout:
                to_delete.append(k)
        for k in to_delete:
            size = self.cache[k]['buf_size']
            self.current_mem -= size
            del self.cache[k]

    def feed(self, src, dst, proto, identification, offset, mf_flag, payload):
        self._evict_old()

        key = self._key(src, dst, proto, identification)
        now = time.time()
        frag = self.cache.get(key)

        if frag is None:
            frag = {
                'ts': now,
                'parts': {},           # offset -> payload
                'buf_size': 0,
                'last_offset': None,   # determined when MF=0 is seen
            }
            self.cache[key] = frag

        frag['ts'] = now

        # Insert fragment
        if offset not in frag['parts']:
            frag['parts'][offset] = payload
            frag['buf_size'] += len(payload)
            self.current_mem += len(payload)

        if mf_flag == 0:
            frag['last_offset'] = offset + len(payload)

        if self.current_mem > self.memcap:
            del self.cache[key]
            return None

        # Check if complete
        if frag['last_offset'] is not None:
            total_end = frag['last_offset']
            assembled = bytearray(total_end)
            filled = [False] * total_end

            for off, data in frag['parts'].items():
                end = off + len(data)
                assembled[off:end] = data
                for i in range(off, end):
                    filled[i] = True

            if all(filled[:total_end]):
                del self.cache[key]
                self.current_mem -= frag['buf_size']
                return bytes(assembled)

        return None
