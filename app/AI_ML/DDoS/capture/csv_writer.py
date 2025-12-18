"""CSV writer module for flow feature export (separated from sniffer for better architecture)."""

from __future__ import annotations

import csv
import os
import sys
import threading
from typing import List, Optional
from .flow import Flow
from . import utils


class CSVWriter:
    """
    Handles CSV file operations for flow features.
    Separated from sniffer for better separation of concerns.
    """
    
    def __init__(self, csv_file: str, buffer_size: int):
        """
        Initialize CSV writer.
        
        Args:
            csv_file: Path to CSV file for writing flow features
        """
        self.csv_file = csv_file
        self.initialized = False
        self._buffer_size = buffer_size
        self._buffer: List[List[object]] = []
        self._file: Optional[object] = None
        self._writer: Optional[csv.writer] = None
        self._lock = threading.RLock()

    def _get_schema(self) -> tuple[List[str], List[str]]:
        header_style = utils.CSV_HEADER_STYLE
        header_names, source_keys = utils.get_csv_schema(header_style)
        return header_names, source_keys

    def close(self) -> None:
        """Flush pending rows and close the underlying file handle."""
        with self._lock:
            try:
                self.flush()
            finally:
                if self._file is not None:
                    self._file.close()
                self._file = None
                self._writer = None
    
    def initialize(self) -> bool:
        """
        Initialize CSV file with headers.
        
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                if self.initialized:
                    return True

                header_names, _source_keys = self._get_schema()

                # Ensure directory exists
                os.makedirs(os.path.dirname(self.csv_file), exist_ok=True)

                # Open once and keep handle for lifetime
                self._file = open(self.csv_file, mode="w", newline="", encoding="utf-8")
                self._writer = csv.writer(self._file)
                self._writer.writerow(header_names)

                self.initialized = True
                print(
                    f"📄 CSV initialized: {self.csv_file} "
                    f"({len(header_names)} features, header_style={utils.CSV_HEADER_STYLE})",
                    file=sys.stderr,
                )
                return True
            except Exception as e:
                print(f"⚠️ Error initializing CSV: {type(e).__name__}: {e}", file=sys.stderr)
                return False

    def flush(self) -> bool:
        """Write buffered rows to disk."""
        with self._lock:
            try:
                if not self.initialized:
                    self.initialize()
                if self._writer is None or self._file is None:
                    raise RuntimeError("CSV writer not initialized")
                if not self._buffer:
                    return True
                self._writer.writerows(self._buffer)
                self._file.flush()
                self._buffer.clear()
                return True
            except Exception as e:
                print(f"⚠️ Error flushing CSV: {type(e).__name__}: {e}", file=sys.stderr)
                return False
    
    def write_flow(self, flow: Flow, reason: str = "") -> bool:
        """
        Write a single flow to CSV file.
        
        Args:
            flow: Flow object to write
            reason: Optional reason string for logging
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                # Ensure CSV is initialized
                if not self.initialized:
                    self.initialize()

                # Update subflow snapshot before calculating features
                flow.subflow_fwd_packets = flow.fwd_pkts
                flow.subflow_fwd_bytes = flow.fwd_bytes
                flow.subflow_bwd_packets = flow.bwd_pkts
                flow.subflow_bwd_bytes = flow.bwd_bytes

                # Calculate features
                feat = flow.to_features()

                _header_names, source_keys = self._get_schema()
                row = [feat.get(col, 0) for col in source_keys]

                self._buffer.append(row)
                if len(self._buffer) >= self._buffer_size:
                    self.flush()

                return True
            except Exception as e:
                import traceback
                print(f"⚠️ Error writing flow to CSV: {type(e).__name__}: {e}", file=sys.stderr)
                print(f"   Traceback: {traceback.format_exc()[:300]}", file=sys.stderr)
                return False
    
    def get_csv_file(self) -> str:
        """Get CSV file path"""
        return self.csv_file
    
    def set_csv_file(self, csv_file: str):
        """Set CSV file path (resets initialized flag)"""
        with self._lock:
            self.close()
            self.csv_file = csv_file
            self.initialized = False

