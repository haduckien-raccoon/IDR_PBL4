import datetime
from typing import Dict, Union
from .statistics import StatisticsAccumulator as OnlineStats
from .flow_feature import FlowFeature


class Flow:
    """
    Bidirectional Flow – CICFlowMeter compatible
    Timestamp unit: seconds (float)
    Internal timing stats: microseconds
    """

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        activity_timeout: int = 1_000_000,  # microseconds
    ):
        # ================= BASIC =================
        self.start_time = timestamp
        self.last_time = timestamp

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        # ================= COUNTERS =================
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_header_len = 0
        self.bwd_header_len = 0

        # ================= FLAGS =================
        self.fwd_fin_flags = 0
        self.bwd_fin_flags = 0
        self.fwd_syn_flags = 0
        self.bwd_syn_flags = 0
        self.fwd_rst_flags = 0
        self.bwd_rst_flags = 0
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_ack_flags = 0
        self.bwd_ack_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fwd_ece_flags = 0
        self.bwd_ece_flags = 0
        self.fwd_cwr_flags = 0
        self.bwd_cwr_flags = 0

        # ================= IAT =================
        self.last_fwd_time = None
        self.last_bwd_time = None

        self.fwd_iat_stats = OnlineStats()
        self.bwd_iat_stats = OnlineStats()
        self.flow_iat_stats = OnlineStats()

        # ================= PACKET LEN =================
        self.fwd_pkt_len_stats = OnlineStats()
        self.bwd_pkt_len_stats = OnlineStats()
        self.flow_length_stats = OnlineStats()

        # ================= ACTIVE / IDLE =================
        self.activity_timeout = activity_timeout / 1_000_000.0
        self.start_active_time = timestamp
        self.end_active_time = timestamp
        self._last_activity_time = timestamp

        self.active_stats = OnlineStats()
        self.idle_stats = OnlineStats()

        # ================= SUBFLOW =================
        self.sf_last_packet_ts = -1
        self.sf_count = 1

        # ================= BULK =================
        self.fbulk_packet_count = 0
        self.fbulk_size_total = 0
        self.fbulk_state_count = 0
        self.fbulk_duration = 0

        self.bbulk_packet_count = 0
        self.bbulk_size_total = 0
        self.bbulk_state_count = 0
        self.bbulk_duration = 0

        self.fbulk_start_helper = 0
        self.fbulk_packet_count_helper = 0
        self.fbulk_size_helper = 0
        self.flast_bulk_ts = 0

        self.bbulk_start_helper = 0
        self.bbulk_packet_count_helper = 0
        self.bbulk_size_helper = 0
        self.blast_bulk_ts = 0

        # ================= TCP EXTRA =================
        self.act_data_pkt_forward = 0
        self.min_seg_size_forward = None
        self.fwd_init_win_bytes = 0
        self.bwd_init_win_bytes = 0

        self.is_terminated = False

    # ======================================================
    # INTERNAL HELPERS
    # ======================================================

    def _detect_update_subflows(self, ts: float):
        """
        Detect subflows using CICFlowMeter rule:
        - If the inter-arrival gap between two packets > 1 second
        => a new subflow is created.
        - Subflow detection also affects Active/Idle statistics.
        
        Parameters
        ----------
        ts : float
            Packet timestamp in seconds
        """

        # First packet of the flow
        if self.sf_last_packet_ts == -1:
            self.sf_last_packet_ts = ts
            return

        # Gap between current packet and last packet (microseconds)
        gap_us = (ts - self.sf_last_packet_ts) * 1_000_000

        # CIC rule: new subflow if gap > 1,000,000 us (1 second)
        if gap_us > 1_000_000:
            self.sf_count += 1

        # IMPORTANT:
        # Subflow break is treated as activity boundary
        # => update active / idle stats
        self._update_active_idle_time(ts)

        # Update last packet timestamp
        self.sf_last_packet_ts = ts

    def _end_active_idle_time(self, end_time: float, timeout: float):
        """
        Finalize active / idle time when flow ends.
        This is required for CICFlowMeter compatibility.
        All time stored in microseconds.
        """

        if self._last_activity_time is None:
            return

        diff = end_time - self._last_activity_time

        if diff <= 0:
            return

        diff_us = diff * 1_000_000

        # CIC rule:
        # If gap > timeout => idle
        if diff > timeout:
            self.idle_stats.add_value(diff_us)
        else:
            self.active_stats.add_value(diff_us)


    def _update_active_idle_time(self, ts: float):
        ts_us = ts * 1_000_000
        end_us = self.end_active_time * 1_000_000
        start_us = self.start_active_time * 1_000_000

        gap = ts_us - end_us
        if gap > self.activity_timeout * 1_000_000:
            if end_us > start_us:
                self.active_stats.add_value(end_us - start_us)
            self.idle_stats.add_value(gap)
            self.start_active_time = ts
            self.end_active_time = ts
        else:
            self.end_active_time = ts

    def _update_forward_bulk(self, size: int, ts: float):
        if size <= 0:
            return

        if self.blast_bulk_ts > self.fbulk_start_helper:
            self.fbulk_start_helper = 0

        if self.fbulk_start_helper == 0:
            self.fbulk_start_helper = ts
            self.fbulk_packet_count_helper = 1
            self.fbulk_size_helper = size
            self.flast_bulk_ts = ts
            return

        gap = (ts - self.flast_bulk_ts)
        if gap > 1:
            self.fbulk_start_helper = ts
            self.fbulk_packet_count_helper = 1
            self.fbulk_size_helper = size
        else:
            self.fbulk_packet_count_helper += 1
            self.fbulk_size_helper += size

            if self.fbulk_packet_count_helper == 4:
                self.fbulk_state_count += 1
                self.fbulk_packet_count += 4
                self.fbulk_size_total += self.fbulk_size_helper
                self.fbulk_duration += (ts - self.fbulk_start_helper) * 1_000_000
            elif self.fbulk_packet_count_helper > 4:
                self.fbulk_packet_count += 1
                self.fbulk_size_total += size
                self.fbulk_duration += gap * 1_000_000

        self.flast_bulk_ts = ts

    def _update_backward_bulk(self, size: int, ts: float):
        if size <= 0:
            return

        if self.flast_bulk_ts > self.bbulk_start_helper:
            self.bbulk_start_helper = 0

        if self.bbulk_start_helper == 0:
            self.bbulk_start_helper = ts
            self.bbulk_packet_count_helper = 1
            self.bbulk_size_helper = size
            self.blast_bulk_ts = ts
            return

        gap = (ts - self.blast_bulk_ts)
        if gap > 1:
            self.bbulk_start_helper = ts
            self.bbulk_packet_count_helper = 1
            self.bbulk_size_helper = size
        else:
            self.bbulk_packet_count_helper += 1
            self.bbulk_size_helper += size

            if self.bbulk_packet_count_helper == 4:
                self.bbulk_state_count += 1
                self.bbulk_packet_count += 4
                self.bbulk_size_total += self.bbulk_size_helper
                self.bbulk_duration += (ts - self.bbulk_start_helper) * 1_000_000
            elif self.bbulk_packet_count_helper > 4:
                self.bbulk_packet_count += 1
                self.bbulk_size_total += size
                self.bbulk_duration += gap * 1_000_000

        self.blast_bulk_ts = ts

    # ======================================================
    # MAIN UPDATE
    # ======================================================

    def update_primitives(
        self,
        timestamp: float,
        payload_len: int,
        header_len: int,
        tcp_flags: int,
        protocol: int,
        is_forward: bool,
    ):
        # ---------- Flow IAT ----------
        if self.last_time is not None:
            self.flow_iat_stats.add_value((timestamp - self.last_time) * 1_000_000)
        self.last_time = timestamp

        # ---------- Subflow ----------
        self._detect_update_subflows(timestamp)

        # ---------- Active / Idle ----------
        self._update_active_idle_time(timestamp)

        # ---------- Direction ----------
        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += payload_len
            self.fwd_header_len += header_len
            self.fwd_pkt_len_stats.add_value(payload_len)
            self.flow_length_stats.add_value(payload_len)

            if self.last_fwd_time is not None:
                self.fwd_iat_stats.add_value((timestamp - self.last_fwd_time) * 1_000_000)
            self.last_fwd_time = timestamp

            if payload_len > 0:
                self.act_data_pkt_forward += 1
                self.min_seg_size_forward = (
                    payload_len
                    if self.min_seg_size_forward is None
                    else min(self.min_seg_size_forward, payload_len)
                )

            self._update_forward_bulk(payload_len, timestamp)

        else:
            self.bwd_pkts += 1
            self.bwd_bytes += payload_len
            self.bwd_header_len += header_len
            self.bwd_pkt_len_stats.add_value(payload_len)
            self.flow_length_stats.add_value(payload_len)

            if self.last_bwd_time is not None:
                self.bwd_iat_stats.add_value((timestamp - self.last_bwd_time) * 1_000_000)
            self.last_bwd_time = timestamp

            self._update_backward_bulk(payload_len, timestamp)

        # ---------- TCP FLAGS ----------
        if protocol == 6:
            if tcp_flags & 0x01:
                self.fwd_fin_flags += is_forward
                self.bwd_fin_flags += not is_forward
            if tcp_flags & 0x02:
                self.fwd_syn_flags += is_forward
                self.bwd_syn_flags += not is_forward
            if tcp_flags & 0x04:
                self.fwd_rst_flags += is_forward
                self.bwd_rst_flags += not is_forward
            if tcp_flags & 0x08:
                self.fwd_psh_flags += is_forward
                self.bwd_psh_flags += not is_forward
            if tcp_flags & 0x10:
                self.fwd_ack_flags += is_forward
                self.bwd_ack_flags += not is_forward
            if tcp_flags & 0x20:
                self.fwd_urg_flags += is_forward
                self.bwd_urg_flags += not is_forward
            if tcp_flags & 0x40:
                self.fwd_ece_flags += is_forward
                self.bwd_ece_flags += not is_forward
            if tcp_flags & 0x80:
                self.fwd_cwr_flags += is_forward
                self.bwd_cwr_flags += not is_forward

    # ======================================================
    # EXPORT
    # ======================================================

    def to_features(self) -> Dict[str, Union[str, int, float]]:
        feat = FlowFeature.calculate(self)

        flow_id = f"{self.src_ip}-{self.dst_ip}-{self.src_port}-{self.dst_port}-{self.protocol}"
        ts = datetime.datetime.fromtimestamp(self.start_time).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )

        meta = {
            "Flow ID": flow_id,
            "Src IP": self.src_ip,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.protocol,
            "Timestamp": ts,
        }

        return {**meta, **feat}
