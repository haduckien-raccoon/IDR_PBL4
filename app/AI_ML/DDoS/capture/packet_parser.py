"""Fast IPv4 TCP/UDP packet parsing utilities.

This module is intentionally small and allocation-light:
- Uses cached struct.Struct instances
- Works with memoryview to avoid copying
"""

from __future__ import annotations

import struct


_IPV4_HDR = struct.Struct("!BBHHHBBH4s4s")
_TCP_HDR = struct.Struct("!HHLLBBHHH")
_UDP_HDR = struct.Struct("!HHHH")
_U32 = struct.Struct("!I")


class PacketScratch:
    """Reusable parsed-packet container.

    Mutable by design to allow reuse (zero allocation per packet).
    """

    __slots__ = (
        "protocol",
        "src_ip_bytes",
        "dst_ip_bytes",
        "src_ip_int",
        "dst_ip_int",
        "src_port",
        "dst_port",
        "header_len",
        "payload_len",
        "tcp_flags",
    )

    def __init__(self) -> None:
        self.protocol = 0
        self.src_ip_bytes = b"\x00\x00\x00\x00"
        self.dst_ip_bytes = b"\x00\x00\x00\x00"
        self.src_ip_int = 0
        self.dst_ip_int = 0
        self.src_port = 0
        self.dst_port = 0
        self.header_len = 0
        self.payload_len = 0
        self.tcp_flags = 0


def parse_ipv4_tcp_udp_into(packet: memoryview, out: PacketScratch) -> None:
    """Parse an IPv4 TCP/UDP packet into `out`.

    Raises:
        ValueError: If the packet is too short or not TCP/UDP.
    """
    if len(packet) < 20:
        raise ValueError("packet too short for IPv4 header")

    v_ihl, _tos, total_len, _id, _flags_frag, _ttl, protocol, _checksum, src_ip, dst_ip = _IPV4_HDR.unpack_from(
        packet, 0
    )
    ihl = v_ihl & 0x0F
    ip_header_len = ihl * 4
    if ip_header_len < 20:
        raise ValueError(f"invalid IPv4 IHL: {ihl}")
    if len(packet) < ip_header_len:
        raise ValueError("packet too short for IPv4 IHL")

    if protocol == 6:
        if len(packet) < ip_header_len + 20:
            raise ValueError("packet too short for TCP header")
        src_port, dst_port, _seq, _ack, data_offset_byte, flags, _win, _sum, _urp = _TCP_HDR.unpack_from(
            packet, ip_header_len
        )
        tcp_header_len = (data_offset_byte >> 4) * 4
        if tcp_header_len < 20:
            raise ValueError(f"invalid TCP data offset: {data_offset_byte >> 4}")
        header_len = ip_header_len + tcp_header_len
        tcp_flags = flags
    elif protocol == 17:
        if len(packet) < ip_header_len + 8:
            raise ValueError("packet too short for UDP header")
        src_port, dst_port, _udp_len, _udp_sum = _UDP_HDR.unpack_from(packet, ip_header_len)
        header_len = ip_header_len + 8
        tcp_flags = 0
    else:
        raise ValueError(f"unsupported protocol: {protocol}")

    effective_total_len = total_len if total_len > 0 else len(packet)
    if effective_total_len < header_len:
        raise ValueError("IPv4 total_len smaller than header_len")
    payload_len = effective_total_len - header_len

    out.protocol = protocol
    out.src_ip_bytes = src_ip
    out.dst_ip_bytes = dst_ip
    out.src_ip_int = _U32.unpack(src_ip)[0]
    out.dst_ip_int = _U32.unpack(dst_ip)[0]
    out.src_port = src_port
    out.dst_port = dst_port
    out.header_len = header_len
    out.payload_len = payload_len
    out.tcp_flags = tcp_flags
