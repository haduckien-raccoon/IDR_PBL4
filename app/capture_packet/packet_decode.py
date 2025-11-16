from scapy.all import Ether, IP, TCP, UDP, Raw, sniff

class NormalizedPacket:
    """
    Chuẩn hóa packet:
    - Ethernet → IP → TCP/UDP → payload
    - Chuẩn hóa flags, seq/ack, ports, protocol, header lengths, packet.len
    """
    def __init__(self, pkt):
        self.raw_pkt = pkt
        self.valid = False
        self.parse()

    def parse(self):
        try:
            # Ethernet layer
            self.eth_src = self.raw_pkt.src if Ether in self.raw_pkt else None
            self.eth_dst = self.raw_pkt.dst if Ether in self.raw_pkt else None
            self.eth_type = self.raw_pkt.type if Ether in self.raw_pkt else None

            # IP layer
            if IP not in self.raw_pkt:
                return
            ip = self.raw_pkt[IP]
            self.src_ip = ip.src
            self.dst_ip = ip.dst
            self.ip_proto = ip.proto
            self.ip_len = ip.len
            self.ip_hl = ip.ihl * 4  # header length in bytes
            self.valid = True

            # TCP/UDP layer
            self.tcp_flags = None
            self.src_port = None
            self.dst_port = None
            self.seq = None
            self.ack = None
            self.tcp_hl = None
            self.payload = b""
            self.payload_len = 0

            if TCP in self.raw_pkt:
                tcp = self.raw_pkt[TCP]
                self.src_port = tcp.sport
                self.dst_port = tcp.dport
                self.seq = tcp.seq
                self.ack = tcp.ack
                self.tcp_flags = {
                    "FIN": bool(tcp.flags & 0x01),
                    "SYN": bool(tcp.flags & 0x02),
                    "RST": bool(tcp.flags & 0x04),
                    "PSH": bool(tcp.flags & 0x08),
                    "ACK": bool(tcp.flags & 0x10),
                    "URG": bool(tcp.flags & 0x20),
                    "ECE": bool(tcp.flags & 0x40),
                    "CWR": bool(tcp.flags & 0x80),
                }
                self.tcp_hl = tcp.dataofs * 4
                self.payload = bytes(tcp.payload) if Raw in tcp else b""
                self.payload_len = len(self.payload)

            elif UDP in self.raw_pkt:
                udp = self.raw_pkt[UDP]
                self.src_port = udp.sport
                self.dst_port = udp.dport
                self.payload = bytes(udp.payload) if Raw in udp else b""
                self.payload_len = len(self.payload)

            # Total packet length
            self.total_len = len(self.raw_pkt)
        except Exception:
            self.valid = False

    def is_valid(self):
        return self.valid

    def is_syn(self):
        return self.tcp_flags.get("SYN", False) if self.tcp_flags else False

    def is_fin(self):
        return self.tcp_flags.get("FIN", False) if self.tcp_flags else False

    def is_rst(self):
        return self.tcp_flags.get("RST", False) if self.tcp_flags else False

    def summary(self):
        if not self.valid:
            return "Invalid packet"
        return (f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
                f"proto={self.ip_proto} flags={self.tcp_flags} "
                f"len={self.total_len} payload_len={self.payload_len}")

# Example usage
# def test_normalized_packet(iface="lo", count=1, bpf_filter="tcp"):
#     """
#     Bắt gói tin, tạo NormalizedPacket và in thông tin chuẩn hóa
#     """
#     print(f"[+] Sniffing {count} packet(s) on {iface} with filter '{bpf_filter}'...")
#     packets = sniff(count=count, iface=iface, filter=bpf_filter)

#     for i, pkt in enumerate(packets, 1):
#         print(f"\n=== Packet #{i} ===")
#         norm_pkt = NormalizedPacket(pkt)
#         if norm_pkt.is_valid():
#             print(norm_pkt.summary())
#             print(f"  Ethernet: src={norm_pkt.eth_src}, dst={norm_pkt.eth_dst}, type={norm_pkt.eth_type}")
#             print(f"  IP: header_len={norm_pkt.ip_hl}, total_len={norm_pkt.ip_len}, proto={norm_pkt.ip_proto}")
#             if norm_pkt.tcp_flags:
#                 print(f"  TCP Flags: {norm_pkt.tcp_flags}")
#                 print(f"  Seq={norm_pkt.seq}, Ack={norm_pkt.ack}, TCP header len={norm_pkt.tcp_hl}")
#             print(f"  Payload len={norm_pkt.payload_len}")
#         else:
#             print("Invalid or non-IP packet")

# if __name__ == "__main__":
#     # Ví dụ: bắt 1 gói tin TCP trên loopback
#     test_normalized_packet(iface="lo", count=1, bpf_filter="tcp")
