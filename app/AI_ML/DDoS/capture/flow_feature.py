"""FlowFeature class for calculating features from Flow state (CICFlowMeter compatible)"""
from typing import Dict


class FlowFeature:
    """Calculate features from Flow state - separated from Flow class for better architecture"""
    
    @staticmethod
    def calculate(flow) -> Dict[str, float]:
        """
        Calculate all features matching CICFlowMeter FlowFeature enum order
        
        Args:
            flow: Flow object containing all state information
            
        Returns:
            Dictionary of feature names to values (82 features total)
        """
        # Finalize active/idle periods before calculation.
        # Training-data alignment: CICFlowMeter-derived datasets commonly use a 120s flow timeout.
        flow._end_active_idle_time(flow.last_time, 120.0)

        # Calculate flow duration
        duration = (flow.last_time - flow.start_time) * 1_000_000  # Microseconds
        if duration < 0:
            raise ValueError(
                f"Flow duration is negative ({duration}us): last_time={flow.last_time}, start_time={flow.start_time}"
            )
        # Training-data alignment: some CICFlowMeter-derived datasets use -1 for single-packet/unknown duration.
        # This avoids producing extreme rates for duration==0.
        if duration == 0:
            duration = -1.0

        # Forward IAT stats
        fwd_iat_total = flow.fwd_iat_stats.get_sum()
        fwd_mean_iat = flow.fwd_iat_stats.get_mean()
        fwd_std_iat = flow.fwd_iat_stats.get_std()
        fwd_iat_max = flow.fwd_iat_stats.get_max()
        fwd_iat_min = flow.fwd_iat_stats.get_min()

        # Backward IAT stats
        bwd_iat_total = flow.bwd_iat_stats.get_sum()
        bwd_mean_iat = flow.bwd_iat_stats.get_mean()
        bwd_std_iat = flow.bwd_iat_stats.get_std()
        bwd_iat_max = flow.bwd_iat_stats.get_max()
        bwd_iat_min = flow.bwd_iat_stats.get_min()
        # Training-data alignment: some datasets use -1 as a sentinel when a direction is missing (0 packets).
        # Keep 0 values when the direction exists but has <2 packets (no IAT samples).
        if flow.bwd_pkts == 0:
            bwd_iat_total = -1.0
            bwd_mean_iat = -1.0
            bwd_iat_max = -1.0
            bwd_iat_min = -1.0
            bwd_std_iat = 0.0

        # Flow-level IAT
        flow_iat_count = flow.flow_iat_stats.get_count()
        if flow_iat_count == 0:
            flow_mean_iat = -1.0
            flow_std_iat = 0.0
            flow_iat_max = -1.0
            flow_iat_min = -1.0
        else:
            flow_mean_iat = flow.flow_iat_stats.get_mean()
            flow_std_iat = flow.flow_iat_stats.get_std()
            flow_iat_max = flow.flow_iat_stats.get_max()
            flow_iat_min = flow.flow_iat_stats.get_min()

        total_bytes = flow.fwd_bytes + flow.bwd_bytes  # Payload bytes only
        total_packets = flow.fwd_pkts + flow.bwd_pkts

        # Forward packet statistics (payload-based)
        fwd_pkt_len_mean = flow.fwd_pkt_len_stats.get_mean()
        fwd_pkt_len_max = flow.fwd_pkt_len_stats.get_max()
        fwd_pkt_len_min = flow.fwd_pkt_len_stats.get_min()
        fwd_pkt_len_std = flow.fwd_pkt_len_stats.get_std()

        # Backward packet statistics (payload-based)
        bwd_pkt_len_mean = flow.bwd_pkt_len_stats.get_mean()
        bwd_pkt_len_max = flow.bwd_pkt_len_stats.get_max()
        bwd_pkt_len_min = flow.bwd_pkt_len_stats.get_min()
        bwd_pkt_len_std = flow.bwd_pkt_len_stats.get_std()

        # Packet length statistics (all packets, payload-based)
        if flow.flow_length_stats.get_count() > 0:
            pkt_len_min = flow.flow_length_stats.get_min()
            pkt_len_max = flow.flow_length_stats.get_max()
            pkt_len_mean = flow.flow_length_stats.get_mean()
            pkt_len_std = flow.flow_length_stats.get_std()
            pkt_len_var = flow.flow_length_stats.get_variance()
        else:
            pkt_len_min = 0.0
            pkt_len_max = 0.0
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            pkt_len_var = 0.0

        # Forward segment size (payload average)
        fwd_segment_size_avg = fwd_pkt_len_mean if flow.fwd_pkts > 0 else 0.0

        # Backward segment size (payload average)
        bwd_segment_size_avg = bwd_pkt_len_mean if flow.bwd_pkts > 0 else 0.0

        # Fwd Seg Size Min (minimum header bytes)
        fwd_seg_size_min = flow.min_seg_size_forward if flow.min_seg_size_forward is not None else 0

        # Active/Idle time statistics
        active_mean = flow.active_stats.get_mean()
        active_std = flow.active_stats.get_std()
        active_max = flow.active_stats.get_max()
        active_min = flow.active_stats.get_min()

        idle_mean = flow.idle_stats.get_mean()
        idle_std = flow.idle_stats.get_std()
        idle_max = flow.idle_stats.get_max()
        idle_min = flow.idle_stats.get_min()

        # TCP flag counts
        fin_flag_count = flow.fwd_fin_flags + flow.bwd_fin_flags
        syn_flag_count = flow.fwd_syn_flags + flow.bwd_syn_flags
        rst_flag_count = flow.fwd_rst_flags + flow.bwd_rst_flags
        psh_flag_count = flow.fwd_psh_flags + flow.bwd_psh_flags
        ack_flag_count = flow.fwd_ack_flags + flow.bwd_ack_flags
        urg_flag_count = flow.fwd_urg_flags + flow.bwd_urg_flags
        cwr_flag_count = flow.fwd_cwr_flags + flow.bwd_cwr_flags
        ece_flag_count = flow.fwd_ece_flags + flow.bwd_ece_flags

        # Compatibility columns expected by some CICFlowMeter-derived datasets/models.
        # Directional RST flags are directly available in Flow state.
        fwd_rst_flags = float(flow.fwd_rst_flags)
        bwd_rst_flags = float(flow.bwd_rst_flags)
        icmp_code = 0.0
        icmp_type = 0.0
        total_tcp_flow_time = float(duration) if int(flow.protocol) == 6 else 0.0

        # Rates
        flow_packets_per_s = (total_packets * 1_000_000) / duration if duration > 0 else 0.0
        fwd_packets_per_s = (flow.fwd_pkts * 1_000_000) / duration if duration > 0 else 0.0
        bwd_packets_per_s = (flow.bwd_pkts * 1_000_000) / duration if duration > 0 else 0.0

        # Ratios
        down_up_ratio = flow.bwd_bytes / flow.fwd_bytes if flow.fwd_bytes > 0 else 0.0
        avg_packet_size = pkt_len_mean

        # Subflow features
        sf_count = max(flow.sf_count, 1)
        subflow_fwd_packets = int(flow.fwd_pkts / sf_count) if sf_count > 0 else flow.fwd_pkts
        subflow_fwd_bytes = int(flow.fwd_bytes / sf_count) if sf_count > 0 else flow.fwd_bytes
        subflow_bwd_packets = int(flow.bwd_pkts / sf_count) if sf_count > 0 else flow.bwd_pkts
        subflow_bwd_bytes = int(flow.bwd_bytes / sf_count) if sf_count > 0 else flow.bwd_bytes

        # Bulk transfer features
        fwd_bytes_bulk_avg = int(flow.fbulk_size_total / flow.fbulk_state_count) if flow.fbulk_state_count > 0 else 0
        fwd_packet_bulk_avg = int(flow.fbulk_packet_count / flow.fbulk_state_count) if flow.fbulk_state_count > 0 else 0
        fbulk_duration_seconds = flow.fbulk_duration / 1_000_000.0 if flow.fbulk_duration > 0 else 0.0
        fwd_bulk_rate_avg = int(flow.fbulk_size_total / fbulk_duration_seconds) if fbulk_duration_seconds > 0 else 0

        bwd_bytes_bulk_avg = int(flow.bbulk_size_total / flow.bbulk_state_count) if flow.bbulk_state_count > 0 else 0
        bwd_packet_bulk_avg = int(flow.bbulk_packet_count / flow.bbulk_state_count) if flow.bbulk_state_count > 0 else 0
        bbulk_duration_seconds = flow.bbulk_duration / 1_000_000.0 if flow.bbulk_duration > 0 else 0.0
        bwd_bulk_rate_avg = int(flow.bbulk_size_total / bbulk_duration_seconds) if bbulk_duration_seconds > 0 else 0

        # Return columns using the user-provided 83-column naming convention.
        # Metadata columns (Flow ID, 5-tuple, Timestamp, Protocol) are provided by Flow.to_features().
        return {
            "Flow Duration": duration,
            "Tot Fwd Pkts": flow.fwd_pkts,
            "Tot Bwd Pkts": flow.bwd_pkts,
            "TotLen Fwd Pkts": flow.fwd_bytes,
            "TotLen Bwd Pkts": flow.bwd_bytes,
            "Fwd Pkt Len Max": fwd_pkt_len_max,
            "Fwd Pkt Len Min": fwd_pkt_len_min,
            "Fwd Pkt Len Mean": fwd_pkt_len_mean,
            "Fwd Pkt Len Std": fwd_pkt_len_std,
            "Bwd Pkt Len Max": bwd_pkt_len_max,
            "Bwd Pkt Len Min": bwd_pkt_len_min,
            "Bwd Pkt Len Mean": bwd_pkt_len_mean,
            "Bwd Pkt Len Std": bwd_pkt_len_std,
            "Flow Byts/s": (total_bytes * 1_000_000) / duration if duration > 0 else 0.0,
            "Flow Pkts/s": flow_packets_per_s,
            "Flow IAT Mean": flow_mean_iat,
            "Flow IAT Std": flow_std_iat,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Tot": fwd_iat_total,
            "Fwd IAT Mean": fwd_mean_iat,
            "Fwd IAT Std": fwd_std_iat,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Tot": bwd_iat_total,
            "Bwd IAT Mean": bwd_mean_iat,
            "Bwd IAT Std": bwd_std_iat,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": flow.fwd_psh_flags,
            "Bwd PSH Flags": flow.bwd_psh_flags,
            "Fwd URG Flags": flow.fwd_urg_flags,
            "Bwd URG Flags": flow.bwd_urg_flags,
            "Fwd Header Len": flow.fwd_header_len,
            "Bwd Header Len": flow.bwd_header_len,
            "Fwd Pkts/s": fwd_packets_per_s,
            "Bwd Pkts/s": bwd_packets_per_s,
            "Pkt Len Min": pkt_len_min,
            "Pkt Len Max": pkt_len_max,
            "Pkt Len Mean": pkt_len_mean,
            "Pkt Len Std": pkt_len_std,
            "Pkt Len Var": pkt_len_var,
            "FIN Flag Cnt": fin_flag_count,
            "SYN Flag Cnt": syn_flag_count,
            "RST Flag Cnt": rst_flag_count,
            "PSH Flag Cnt": psh_flag_count,
            "ACK Flag Cnt": ack_flag_count,
            "URG Flag Cnt": urg_flag_count,
            "CWE Flag Count": cwr_flag_count,
            "ECE Flag Cnt": ece_flag_count,
            "Down/Up Ratio": down_up_ratio,
            "Pkt Size Avg": avg_packet_size,
            "Fwd Seg Size Avg": fwd_segment_size_avg,
            "Bwd Seg Size Avg": bwd_segment_size_avg,
            "Fwd Byts/b Avg": fwd_bytes_bulk_avg,
            "Fwd Pkts/b Avg": fwd_packet_bulk_avg,
            "Fwd Blk Rate Avg": fwd_bulk_rate_avg,
            "Bwd Byts/b Avg": bwd_bytes_bulk_avg,
            "Bwd Pkts/b Avg": bwd_packet_bulk_avg,
            "Bwd Blk Rate Avg": bwd_bulk_rate_avg,
            "Subflow Fwd Pkts": subflow_fwd_packets,
            "Subflow Fwd Byts": subflow_fwd_bytes,
            "Subflow Bwd Pkts": subflow_bwd_packets,
            "Subflow Bwd Byts": subflow_bwd_bytes,
            "Init Fwd Win Byts": flow.fwd_init_win_bytes,
            "Init Bwd Win Byts": flow.bwd_init_win_bytes,
            "Fwd Act Data Pkts": flow.act_data_pkt_forward,
            "Fwd Seg Size Min": fwd_seg_size_min,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,

            "Fwd RST Flags": fwd_rst_flags,
            "Bwd RST Flags": bwd_rst_flags,
            "ICMP Code": icmp_code,
            "ICMP Type": icmp_type,
            "Total TCP Flow Time": total_tcp_flow_time,
        }

