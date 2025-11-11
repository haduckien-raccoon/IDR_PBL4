#!/usr/bin/env python3
"""
ids_realtime.py
Simple IDS-like packet sniffer:
 - producer: scapy.sniff(...) puts packets into a queue
 - consumer worker: pulls packets and runs rule matching
Usage:
 sudo python3 ids_realtime.py --iface eth0 --filter "tcp port 80 or udp port 53"
"""

import argparse
import threading
import queue
import time
import re
import logging
from scapy.all import sniff, TCP, UDP, IP, Raw

# -----------------------------
# Simple rules (same as yours)
# -----------------------------
RULES = [
    {"proto": "TCP", "src_port": None, "dst_port": 80,
     "payload_pattern": r"(?:union\s+select|drop\s+table|or\s+1=1)",
     "message": "Possible SQL injection attempt"},
    {"proto": "UDP", "src_port": None, "dst_port": 53,
     "payload_pattern": None, "message": "DNS traffic detected"},
    {"proto": "TCP", "src_port": None, "dst_port": 22,
     "payload_pattern": None, "message": "SSH connection attempt"},
]

# -----------------------------
# Config logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ids_alerts.log", encoding="utf-8")
    ]
)

# -----------------------------
# Packet queue and worker
# -----------------------------
pkt_queue = queue.Queue(maxsize=10000)

def match_rules(pkt):
    """Return list of matched rule messages (empty if none)."""
    matches = []
    if IP not in pkt:
        return matches

    proto = None
    sport = dport = None
    payload = None

    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        proto = "IP"

    if Raw in pkt:
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
        except Exception:
            payload = None

    for rule in RULES:
        if rule["proto"] != "ANY" and rule["proto"] != proto:
            continue
        if rule["src_port"] and rule["src_port"] != sport:
            continue
        if rule["dst_port"] and rule["dst_port"] != dport:
            continue
        if rule["payload_pattern"]:
            if not payload:
                continue
            if not re.search(rule["payload_pattern"], payload, re.IGNORECASE):
                continue
        # matched
        matches.append(rule["message"])
    return matches

def worker(stop_event: threading.Event):
    """Consume packets from queue and analyze them."""
    while not stop_event.is_set():
        try:
            pkt = pkt_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            hits = match_rules(pkt)
            if hits:
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt.sport if hasattr(pkt, "sport") else getattr(pkt.payload, "sport", None)
                dport = pkt.dport if hasattr(pkt, "dport") else getattr(pkt.payload, "dport", None)
                for h in hits:
                    msg = f"{h} | {src}:{sport} -> {dst}:{dport}"
                    logging.info(msg)
            # free queue slot
        except Exception as e:
            logging.exception("Error processing packet: %s", e)
        finally:
            pkt_queue.task_done()

# -----------------------------
# Producer callback — called in sniff thread
# -----------------------------
def enqueue(pkt):
    try:
        pkt_queue.put_nowait(pkt)
    except queue.Full:
        # if queue full, drop packet (or you can count drops)
        logging.warning("Packet queue full, dropping packet")

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default=None, help="Interface to sniff (e.g., eth0)")
    parser.add_argument("--filter", default=None, help="BPF filter for sniffing (pcap filter)")
    args = parser.parse_args()

    stop_event = threading.Event()
    th = threading.Thread(target=worker, args=(stop_event,), daemon=True)
    th.start()

    logging.info("Starting sniffer - interface=%s filter=%s (CTRL+C to stop)", args.iface, args.filter)
    try:
        sniff(iface=args.iface, prn=enqueue, store=False, filter=args.filter)
    except PermissionError:
        logging.error("Permission denied. Run as root or give CAP_NET_RAW to python.")
    except KeyboardInterrupt:
        logging.info("Stopping...")
    finally:
        stop_event.set()
        th.join(timeout=2)
        logging.info("Exited.")

if __name__ == "__main__":
    main()

#sudo conda run -n base --no-capture-output python ids_realtime.py --iface wlx40ae30551234 --filter "tcp port 80 or udp port 53"
#sudo /media/haduckien/E/Tool/miniconda3/bin/conda run -n base --no-capture-output python ids_realtime.py --iface wlx40ae30551234 --filter "tcp port 80 or udp port 53"
