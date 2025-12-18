# import os
# import time
# import threading
# import pandas as pd
# import numpy as np
# import joblib

# # Paths setup
# DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
# MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
# LIVE_FLOW_CSV = os.path.join(DATA_DIR, 'live_flow.csv')
# PREDICT_CSV = os.path.join(DATA_DIR, 'predict.csv')

# # Files required from the notebook training
# MODEL_PATH = os.path.join(MODELS_DIR, 'rf_ddos_model.pkl')
# SCALER_PATH = os.path.join(MODELS_DIR, 'rf_scaler.pkl') # Added Scaler
# COLUMNS_PATH = os.path.join(MODELS_DIR, 'rf_feature_columns.pkl')
# MEDIANS_PATH = os.path.join(MODELS_DIR, 'rf_feature_medians.pkl')
# UPPER_BOUNDS_PATH = os.path.join(MODELS_DIR, 'rf_feature_upper_bounds.pkl')

# class LivePredictor:
#     def __init__(self):
#         self.model = None
#         self.scaler = None
#         self.feature_columns = None
#         self.medians = None
#         self.upper_bounds = None
#         self.load_model_and_features()
#         self.lock = threading.Lock()
        
#         # Ensure predict.csv exists with header
#         if not os.path.exists(PREDICT_CSV):
#             with open(PREDICT_CSV, 'w', encoding='utf-8') as f:
#                 f.write('timestamp,prediction,raw_data\n')

#     def load_model_and_features(self):
#         print("[LivePredictor] Loading model and assets...")
#         try:
#             self.model = joblib.load(MODEL_PATH)
#             self.scaler = joblib.load(SCALER_PATH) # Load the scaler
#             self.feature_columns = joblib.load(COLUMNS_PATH)
#             self.medians = joblib.load(MEDIANS_PATH)
#             self.upper_bounds = joblib.load(UPPER_BOUNDS_PATH)
#             print("[LivePredictor] Model loaded successfully.")
#         except Exception as e:
#             print(f"[LivePredictor] Error loading model files: {e}")
#             exit(1)

#     def preprocess(self, row_dict):
#         """
#         Follows the exact preprocessing steps from DDoS_ML.ipynb:
#         1. Construct DataFrame with correct columns (fill missing with 0).
#         2. Replace Inf/-Inf with Median.
#         3. Clip negative values to 0.
#         4. Cap outliers using Upper Bounds.
#         5. Scale data using loaded StandardScaler.
#         """
#         # Convert single row dictionary to DataFrame
#         data = pd.DataFrame([row_dict])
        
#         # Strip whitespace from columns if keys have spaces
#         data.columns = data.columns.str.strip()

#         # Create X with only the features the model expects
#         X = pd.DataFrame()
#         for col in self.feature_columns:
#             if col in data.columns:
#                 # Convert to numeric, force errors to NaN
#                 X[col] = pd.to_numeric(data[col], errors='coerce')
#             else:
#                 # Missing columns filled with 0 as per notebook logic
#                 X[col] = 0.0
        
#         # Ensure correct order
#         X = X[self.feature_columns]

#         # Apply cleaning logic from notebook
#         for col in self.feature_columns:
#             median_val = self.medians.get(col, 0)
            
#             # 1. Replace Inf/NaN with Median
#             X[col] = X[col].replace([np.inf, -np.inf], median_val)
#             X[col] = X[col].fillna(median_val)
            
#             # 2. Clip negative values to 0
#             X[col] = X[col].clip(lower=0)
            
#             # 3. Cap outliers (Upper Bound)
#             if col in self.upper_bounds:
#                 upper = self.upper_bounds[col]
#                 X[col] = np.where(X[col] > upper, upper, X[col])

#         # 4. Scale data (Crucial step missing in original code)
#         X_scaled = self.scaler.transform(X)
        
#         return X_scaled

#     def predict_and_write(self, row_dict, raw_line):
#         try:
#             # Preprocess
#             X_scaled = self.preprocess(row_dict)
            
#             # Predict
#             pred_label = self.model.predict(X_scaled)[0]
            
#             # Map label (assuming 0=BENIGN, 1=DDoS based on notebook)
#             label_map = {0: 'BENIGN', 1: 'DDoS'}
#             pred_str = label_map.get(pred_label, str(pred_label))
            
#             ts = time.strftime('%Y-%m-%d %H:%M:%S')
            
#             print(f"[Predict] {ts} -> {pred_str}")
            
#             with self.lock:
#                 with open(PREDICT_CSV, 'a', encoding='utf-8') as f:
#                     f.write(f'{ts},{pred_str},"{raw_line.strip()}"\n')
                    
#         except Exception as e:
#             print(f"[LivePredictor] Prediction Error: {e}")

#     def watch_file(self):
#         """
#         Uses a persistent file handle to 'tail' the file. 
#         This is more robust for reading new lines as they are written.
#         """
#         print(f'[LivePredictor] Waiting for file: {LIVE_FLOW_CSV}')
#         while not os.path.exists(LIVE_FLOW_CSV):
#             time.sleep(1)

#         print(f'[LivePredictor] Watching {LIVE_FLOW_CSV}...')
        
#         with open(LIVE_FLOW_CSV, 'r', encoding='utf-8') as f:
#             # 1. Read and Parse Header
#             header_line = f.readline()
#             while not header_line:
#                 time.sleep(1)
#                 f.seek(0)
#                 header_line = f.readline()
            
#             # Clean header keys
#             header = [h.strip() for h in header_line.strip().split(',')]
            
#             # 2. Loop forever reading new lines
#             while True:
#                 line = f.readline()
#                 if line:
#                     if line.strip(): # Ignore empty lines
#                         try:
#                             row_data = line.strip().split(',')
#                             # Match header length
#                             if len(row_data) == len(header):
#                                 row_dict = dict(zip(header, row_data))
#                                 self.predict_and_write(row_dict, line)
#                         except Exception as e:
#                             print(f"Error parsing line: {e}")
#                 else:
#                     # No new data, sleep briefly to prevent high CPU usage
#                     time.sleep(0.1)

#     def start(self):
#         t = threading.Thread(target=self.watch_file, daemon=True)
#         t.start()
#         print('[LivePredictor] Thread started. Press Ctrl+C to exit.')
#         try:
#             while True:
#                 time.sleep(1)
#         except KeyboardInterrupt:
#             print('\n[LivePredictor] Stopped.')

# if __name__ == '__main__':
#     predictor = LivePredictor()
#     predictor.start()
import base64
import os
import time
import threading
import pandas as pd
import numpy as np
import joblib
from datetime import datetime, timedelta
import requests

# Paths setup
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
LIVE_FLOW_CSV = os.path.join(DATA_DIR, 'live_flow.csv')
PREDICT_CSV = os.path.join(DATA_DIR, 'predict.csv')

# Files required from the notebook training
MODEL_PATH = os.path.join(MODELS_DIR, 'rf_ddos_model.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'rf_scaler.pkl')
COLUMNS_PATH = os.path.join(MODELS_DIR, 'rf_feature_columns.pkl')
MEDIANS_PATH = os.path.join(MODELS_DIR, 'rf_feature_medians.pkl')
UPPER_BOUNDS_PATH = os.path.join(MODELS_DIR, 'rf_feature_upper_bounds.pkl')

# Placeholder for API call
def send_alert(ip_src, payload)-> int:
    # Gọi API với payload
    from app.workers.blocker import enqueue_block
    enqueue_block(ip_src, reason="DDoS detected by LivePredictor")
    response = requests.post("http://localhost:8000/api/alerts/raw", json=payload, timeout=60)
    if response.status_code == 200 or response.status_code == 201:
        print(f"[ALERT] Alert sent for {ip_src}")
    elif response.status_code == 422:
        print(f"[ALERT] Alert for {ip_src} already exists (422 Unprocessable Entity)")
        print(f"[ALERT] Payload: {payload}")
    else:
        print(f"[ALERT] Failed to send alert for {ip_src}: {response.status_code}")
    # print(f"[ALERT] Sending alert for {ip_src}: {payload}")


class LivePredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.medians = None
        self.upper_bounds = None
        self.load_model_and_features()
        self.lock = threading.Lock()
        self.black_list = {}  # {ip_src: datetime}

        # Ensure predict.csv exists with header
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(PREDICT_CSV):
            with open(PREDICT_CSV, 'w', encoding='utf-8') as f:
                f.write('timestamp,prediction,raw_data\n')

    def load_model_and_features(self):
        print("[LivePredictor] Loading model and assets...")
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.feature_columns = joblib.load(COLUMNS_PATH)
            self.medians = joblib.load(MEDIANS_PATH)
            self.upper_bounds = joblib.load(UPPER_BOUNDS_PATH)
            print("[LivePredictor] Model loaded successfully.")
        except Exception as e:
            print(f"[LivePredictor] Error loading model files: {e}")
            exit(1)

    def preprocess(self, row_dict):
        data = pd.DataFrame([row_dict])
        data.columns = data.columns.str.strip()
        X = pd.DataFrame()
        for col in self.feature_columns:
            X[col] = pd.to_numeric(data[col], errors='coerce') if col in data.columns else 0.0
        X = X[self.feature_columns]
        for col in self.feature_columns:
            median_val = self.medians.get(col, 0)
            X[col] = X[col].replace([np.inf, -np.inf], median_val).fillna(median_val)
            X[col] = X[col].clip(lower=0)
            if col in self.upper_bounds:
                X[col] = np.where(X[col] > self.upper_bounds[col], self.upper_bounds[col], X[col])
        return self.scaler.transform(X)

    def predict_and_write(self, row_dict, raw_line):
        try:
            X_scaled = self.preprocess(row_dict)
            pred_label = self.model.predict(X_scaled)[0]
            label_map = {0: 'BENIGN', 1: 'DDoS'}
            pred_str = label_map.get(pred_label, str(pred_label))
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"[Predict] {ts} -> {pred_str}")

            # Ghi vào CSV
            with self.lock:
                with open(PREDICT_CSV, 'a', encoding='utf-8') as f:
                    f.write(f'{ts},{pred_str},"{raw_line.strip()}"\n')

                # --- Blacklist handling ---
                ip_src = row_dict.get('src') or row_dict.get('Src IP') or row_dict.get('SourceIP')
                print(ip_src + "Hello")
                if pred_str == 'DDoS' and ip_src:
                    now = datetime.now()
                    if ip_src not in self.black_list:
                        # Chưa tồn tại → block 4 phút + gửi alert
                        self.black_list[ip_src] = now + timedelta(minutes=4)
                        payload ={
                                "rid": "DDoS-001",
                                "message": "DDoS attack detected",
                                "src": ip_src,
                                "dst": row_dict.get('dst') or row_dict.get('Dst IP') or row_dict.get('DestinationIP'),
                                "sport": row_dict.get('sport') or row_dict.get('Src Port') or row_dict.get('SourcePort') or '0',
                                "dport": row_dict.get('dport') or row_dict.get('Dst Port') or row_dict.get('DestinationPort') or '80',
                                "proto": row_dict.get('proto') or row_dict.get('Protocol'),
                                "variant": "rf_model_v1",
                                "entropy": 0.0,
                                "hexdump": "",
                                "action": "block",
                                "payload": base64.b64encode(raw_line.encode('utf-8')).decode('ascii'),
                                "severity": "high"
                        }
                        send_alert(ip_src, payload)
                    else:
                        if now >= self.black_list[ip_src]:
                            # Hết block → gửi alert và reset block
                            self.black_list[ip_src] = now + timedelta(minutes=1)
                            payload ={
                                "rid": "DDoS-001",
                                "message": "DDoS attack detected",
                                "src": ip_src,
                                "dst": row_dict.get('dst') or row_dict.get('Dst IP') or row_dict.get('DestinationIP'),
                                "sport": row_dict.get('sport') or row_dict.get('Src Port') or row_dict.get('SourcePort') or '0',
                                "dport": row_dict.get('dport') or row_dict.get('Dst Port') or row_dict.get('DestinationPort') or '80',
                                "proto": row_dict.get('proto') or row_dict.get('Protocol'),
                                "variant": "rf_model_v1",
                                "entropy": 0.0,
                                "hexdump": "",
                                "action": "block",
                                "payload": base64.b64encode(raw_line.encode('utf-8')).decode('ascii'),
                                "severity": "high"
                            }
                            send_alert(ip_src, payload)
                        else:
                            # Đang block, không gửi
                            pass

        except Exception as e:
            print(f"[LivePredictor] Prediction Error: {e}")

    def watch_file(self):
        print(f'[LivePredictor] Waiting for file: {LIVE_FLOW_CSV}')
        while not os.path.exists(LIVE_FLOW_CSV):
            time.sleep(1)
        print(f'[LivePredictor] Watching {LIVE_FLOW_CSV}...')

        with open(LIVE_FLOW_CSV, 'r', encoding='utf-8') as f:
            header_line = f.readline()
            while not header_line:
                time.sleep(1)
                f.seek(0)
                header_line = f.readline()
            header = [h.strip() for h in header_line.strip().split(',')]

            while True:
                line = f.readline()
                if line and line.strip():
                    try:
                        row_data = line.strip().split(',')
                        if len(row_data) == len(header):
                            row_dict = dict(zip(header, row_data))
                            self.predict_and_write(row_dict, line)
                    except Exception as e:
                        print(f"Error parsing line: {e}")
                else:
                    time.sleep(0.1)

    def start(self):
        t = threading.Thread(target=self.watch_file, daemon=True)
        t.start()
        print('[LivePredictor] Thread started. Press Ctrl+C to exit.')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('\n[LivePredictor] Stopped.')


if __name__ == '__main__':
    predictor = LivePredictor()
    predictor.start()
