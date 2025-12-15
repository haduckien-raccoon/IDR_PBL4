# %%
"""
Lite real-time DDoS Detection System (file watcher).

Uses the reduced feature set (11-12 cols) from train_lite_model.py:
- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Total Length of Fwd Packets
- Total Length of Bwd Packets
- Fwd Packet Length Max
- Fwd Packet Length Min
- Fwd Packet Length Mean
- Flow IAT Mean
- Fwd IAT Mean
- Fwd Header Length
- Optional if present: Flow IAT Std, Flow Bytes/s

Destination Port is NOT used.

Usage:
  python lite_detection_system.py --csv-path data/live_flow.csv
  python lite_detection_system.py --csv-path data/live_flow.csv --poll
"""

# %%
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List
from io import StringIO

import joblib
import numpy as np
import pandas as pd
from tensorflow import keras
from colorama import Fore, Style, init as colorama_init

colorama_init()

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


MODELS_DIR = "models"


# %%
def load_artifacts(models_dir: str = MODELS_DIR):
    model_path = os.path.join(models_dir, "cnn_lite_model.h5")
    scaler_path = os.path.join(models_dir, "cnn_lite_scaler.pkl")
    feature_names_path = os.path.join(models_dir, "cnn_lite_feature_names.pkl")

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")
    if not os.path.exists(feature_names_path):
        raise FileNotFoundError(f"Feature names not found: {feature_names_path}")

    print(f"Debug: Loading lite model from {model_path}")
    model = keras.models.load_model(model_path)
    scaler = joblib.load(scaler_path)
    feature_names = joblib.load(feature_names_path)

    return model, scaler, feature_names


# %%
def rigid_preprocess_lite(df: pd.DataFrame, feature_names: List[str], scaler) -> np.ndarray:
    # Align to lite feature order; fill missing with 0; drop extras
    df_aligned = pd.DataFrame(index=df.index)
    for col in feature_names:
        df_aligned[col] = df[col] if col in df.columns else 0.0

    df_scaled = scaler.transform(df_aligned.to_numpy(dtype=np.float32))
    feature_count = df_scaled.shape[1]
    return df_scaled.reshape(-1, feature_count, 1)


# %%
def predict_batch(model, batch_array: np.ndarray):
    proba = model.predict(batch_array, verbose=0).flatten()
    preds = (proba > 0.5).astype(int)
    return preds, proba


# %%
class CSVAppendHandler(FileSystemEventHandler):
    def __init__(self, csv_path, process_fn):
        super().__init__()
        self.csv_path = csv_path
        self.offset = 0
        self.process_fn = process_fn
        self.file_size = 0

    def on_modified(self, event):
        if event.src_path != os.path.abspath(self.csv_path):
            return
        
        # Kiểm tra nếu file bị truncate/recreate (size giảm)
        try:
            current_size = os.path.getsize(self.csv_path)
            if current_size < self.file_size:
                # File bị recreate, reset offset
                print(f"Debug: CSV file recreated (size: {self.file_size} -> {current_size}), resetting offset")
                self.offset = 0
            self.file_size = current_size
        except Exception:
            pass
        
        self._process_new_lines()

    def on_created(self, event):
        if event.src_path != os.path.abspath(self.csv_path):
            return
        print("Debug: CSV file created, resetting offset")
        self.offset = 0
        self.file_size = 0
        # Không process ngay khi file được tạo (chờ có data)

    def _process_new_lines(self):
        try:
            # Kiểm tra file size trước
            try:
                current_size = os.path.getsize(self.csv_path)
            except Exception:
                return
            
            # Nếu offset lớn hơn file size, file đã bị recreate
            if self.offset > current_size:
                print(f"Debug: Offset ({self.offset}) > file size ({current_size}), file recreated. Resetting offset.")
                self.offset = 0
            
            with open(self.csv_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.offset)
                new_data = f.read()
                new_offset = f.tell()
                
                # Nếu không đọc được gì mới, return
                if new_offset == self.offset:
                    return
                
                self.offset = new_offset
            
            if not new_data.strip():
                return
            
            lines = [l for l in new_data.splitlines() if l.strip()]
            if lines:
                print(f"Debug: Read {len(lines)} new line(s) from CSV (offset: {self.offset})")
            self.process_fn(lines)
        except Exception as e:
            print(f"⚠️ Error reading CSV: {e}")


# %%
def run_watcher(csv_path: str, batch_size: int, poll: bool, model, scaler, feature_names):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    buffer: List[str] = []

    def process_lines(lines: List[str]):
        nonlocal buffer
        for line in lines:
            buffer.append(line)
        
        # Flush khi buffer đủ batch_size hoặc khi có nhiều dòng mới
        # (để xử lý batch hiệu quả hơn)
        if len(buffer) >= batch_size:
            flush_buffer()

    def flush_buffer():
        nonlocal buffer
        if not buffer:
            return
        
        # Lưu buffer hiện tại và clear ngay để tránh duplicate processing
        local_lines = buffer.copy()
        buffer = []
        
        if not local_lines:
            return
            
        try:
            # Đọc header từ CSV file một lần
            header_df = pd.read_csv(csv_path, nrows=0)
            header_first_col = header_df.columns[0]
            
            # Loại bỏ header nếu có trong buffer
            if local_lines and local_lines[0].split(",")[0].strip() == header_first_col:
                local_lines = local_lines[1:]
            
            if not local_lines:
                return

            # Parse tất cả dòng trong buffer cùng lúc
            df_new = pd.read_csv(StringIO("\n".join(local_lines)), header=None)
            
            # Kiểm tra số cột có khớp với header không
            if len(df_new.columns) != len(header_df.columns):
                print(f"⚠️ Column mismatch: Expected {len(header_df.columns)} cols, got {len(df_new.columns)}. Skipping batch.")
                return
            
            df_new.columns = header_df.columns
            
            # Debug: In số lượng flows được xử lý
            num_flows = len(df_new)
            if num_flows > 0:
                print(f"Debug: Processing {num_flows} flow(s) in batch")
            
            # Predict tất cả flows cùng lúc (batch inference)
            preds, proba = infer_dataframe(df_new)
            
            # Hybrid Detection: Xử lý từng flow trong batch với 3 quy tắc
            for i in range(len(df_new)):
                # Lấy số gói tin từ dataframe
                pkt_count = df_new.iloc[i]['Total Fwd Packets']
                ai_proba = proba[i]
                
                # Quy tắc 1: Low Traffic Filter (< 100 packets)
                if pkt_count < 100:
                    print(f"{Fore.GREEN}✅ Normal (Low Traffic) - Pkts: {pkt_count:.0f} - Proba: {ai_proba:.4f}{Style.RESET_ALL}")
                
                # Quy tắc 2: High Rate Rule (> 5000 packets)
                elif pkt_count > 5000:
                    print(f"{Fore.RED}🚨 DDoS DETECTED! (High Rate Rule) - Pkts: {pkt_count:.0f} - Proba: {ai_proba:.4f}{Style.RESET_ALL}")
                
                # Quy tắc 3: AI Verification (100 <= packets <= 5000)
                else:
                    # Nâng ngưỡng tin cậy: chỉ báo DDoS nếu proba > 0.8
                    if ai_proba > 0.8:
                        print(f"{Fore.RED}🚨 DDoS DETECTED! (AI Model) - Pkts: {pkt_count:.0f} - Proba: {ai_proba:.4f}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}✅ Normal - Pkts: {pkt_count:.0f} - Proba: {ai_proba:.4f}{Style.RESET_ALL}")
        except Exception as exc:  # noqa: BLE001
            print(f"⚠️ Error processing batch ({len(local_lines)} lines): {exc}")
            import traceback
            traceback.print_exc()

    def infer_dataframe(df_chunk: pd.DataFrame):
        df_proc = rigid_preprocess_lite(df_chunk, feature_names, scaler)
        return predict_batch(model, df_proc)

    if poll or not HAS_WATCHDOG:
        print("Debug: Running in polling mode (watchdog unavailable or poll=True)")
        offset = 0
        last_size = 0
        while True:
            if os.path.exists(csv_path):
                try:
                    current_size = os.path.getsize(csv_path)
                    # Kiểm tra nếu file bị recreate (size giảm)
                    if current_size < last_size:
                        print(f"Debug: CSV file recreated (size: {last_size} -> {current_size}), resetting offset")
                        offset = 0
                    last_size = current_size
                    
                    if current_size > offset:
                        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(offset)
                            new_data = f.read()
                            new_offset = f.tell()

                            if new_offset > offset:
                                lines = [l for l in new_data.splitlines() if l.strip()]
                                try:
                                    if lines:
                                        process_lines(lines)
                                except Exception as exc:  # noqa: BLE001
                                    # Advance offset even when processing fails to avoid reprocessing bad data
                                    print(f"⚠️ Error processing lines at offset {offset}: {exc}")
                                finally:
                                    offset = new_offset
                except Exception as e:
                    print(f"⚠️ Error in polling mode: {e}")
            time.sleep(1.0)
    else:
        print("Debug: Running with watchdog file observer")
        event_handler = CSVAppendHandler(csv_path, process_lines)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(os.path.abspath(csv_path)) or ".", recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


# %%
def main():
    parser = argparse.ArgumentParser(description="Lite real-time DDoS Detection System (file watcher)")
    parser.add_argument("--csv-path", default="data/live_flow.csv", help="CSV path produced by sniffer/export")
    parser.add_argument("--batch-size", type=int, default=1, help="Batch size for inference")
    parser.add_argument("--poll", action="store_true", help="Force polling mode instead of watchdog")
    args, unknown = parser.parse_known_args()
    if unknown:
        print(f"Debug: Ignoring unknown args (likely from Jupyter/IPython): {unknown}")

    model, scaler, feature_names = load_artifacts()
    run_watcher(args.csv_path, args.batch_size, args.poll, model, scaler, feature_names)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)



# %%