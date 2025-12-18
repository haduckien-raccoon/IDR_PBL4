"""Fast Sniffer - Command-line interface for network packet capture."""

import ipaddress
import sys

from capture import FastSniffer, get_local_ips, init_feature_names
from capture import utils


def main():
    if len(sys.argv) < 2:
        local_ips = get_local_ips()
        print(
            f"Usage: python {sys.argv[0]} <ip_filter?> [--iface <iface>] "
            "[--print] [--stats] [--header short|cic2017] [--port <port_filter>]",
            file=sys.stderr,
        )
        if local_ips:
            print(f"Available IPs: {', '.join(local_ips)}", file=sys.stderr)
        sys.exit(1)

    # ---------------- ARG PARSING ----------------
    args = sys.argv[1:]

    bind_ip = None
    iface = None
    port_filter = None

    if "--iface" in args:
        idx = args.index("--iface")
        if idx + 1 >= len(args):
            raise ValueError("Missing value after --iface")
        iface = args[idx + 1]
        args.pop(idx + 1)
        args.pop(idx)

    if "--port" in args:
        idx = args.index("--port")
        if idx + 1 >= len(args):
            raise ValueError("Missing value after --port")
        port_filter = args[idx + 1]
        args.pop(idx + 1)
        args.pop(idx)
    
    if port_filter:
        # Validate port filter
        try:
            port_num = int(port_filter)
            if not (0 < port_num < 65536):
                raise ValueError()
        except ValueError:
            raise ValueError("Port filter must be a valid port number (1-65535)")

    if args and not args[0].startswith("-"):
        bind_ip = args[0]

    debug_print = "--print" in args
    stats = "--stats" in args

    # ---------------- HEADER STYLE ----------------
    header_style = "short"
    if "--header" in args:
        idx = args.index("--header")
        if idx + 1 >= len(args):
            raise ValueError("Missing value after --header")
        header_style = args[idx + 1].lower()

    if header_style not in ("short", "cic2017"):
        raise ValueError("Invalid --header value")

    utils.CSV_HEADER_STYLE = header_style
    print(f"[DEBUG] CSV header style: {header_style}", file=sys.stderr)

    # ---------------- INIT FEATURES ----------------
    init_feature_names()

    # ---------------- START SNIFFER ----------------
    sniffer = FastSniffer(
        bind_ip=bind_ip,
        iface=iface,
        debug_print=debug_print,
        stats=stats,
        port_filter=port_filter,
    )

    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffer...", file=sys.stderr)
        sniffer.stop()
        print("✅ Sniffer stopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
