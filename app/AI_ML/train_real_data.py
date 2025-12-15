# %%
import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
)
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt

# %%
# --- CẤU HÌNH ---
# Option 1: Đọc từ file đã gộp sẵn (nếu đã chạy combine_datasets.py)
COMBINED_DATASET_PATH = os.path.join("data", "final_dataset_shuffled.csv")

# Option 2: Đọc từ 2 file riêng biệt
ATTACK_PATH = os.path.join("data", "attack_hping3.csv")
NORMAL_PATH = os.path.join("data", "normal_web.csv")

# Thư mục lưu model
MODELS_DIR = "models"

# Chọn mode: "combined" (đọc từ file đã gộp) hoặc "separate" (đọc từ 2 file riêng)
LOAD_MODE = "combined"  # Thay đổi thành "separate" nếu muốn đọc từ 2 file riêng

# 12 Feature chuẩn của Lite Model (Khớp với Sniffer và Detector)
SELECTED_FEATURES = [
    "Flow Duration", 
    "Total Fwd Packets", 
    "Total Backward Packets",
    "Total Length of Fwd Packets", 
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max", 
    "Fwd Packet Length Min", 
    "Fwd Packet Length Mean",
    "Flow IAT Mean", 
    "Fwd IAT Mean", 
    "Fwd Header Length",
    "Flow IAT Std"
]

# %%
def load_and_process_data():
    print("="*50)
    print("BƯỚC 1: TẢI VÀ GÁN NHÃN DỮ LIỆU")
    print("="*50)

    # Kiểm tra mode load
    if LOAD_MODE == "combined":
        # Đọc từ file đã gộp sẵn
        if not os.path.exists(COMBINED_DATASET_PATH):
            print(f"⚠️ Không tìm thấy file đã gộp: {COMBINED_DATASET_PATH}")
            print(f"💡 Chuyển sang mode 'separate' để đọc từ 2 file riêng...")
            # Fallback to separate mode
            return load_from_separate_files()
        
        print(f"📖 Đang đọc từ file đã gộp: {COMBINED_DATASET_PATH}")
        try:
            df_merged = pd.read_csv(COMBINED_DATASET_PATH)
        except Exception as e:
            print(f"⚠️ Lỗi đọc CSV: {e}")
            return None, None, None
        
        # Kiểm tra có cột Label không
        if 'Label' not in df_merged.columns:
            print("⚠️ File không có cột 'Label'. Chuyển sang mode 'separate'...")
            return load_from_separate_files()
        
        print(f"📊 Dữ liệu từ file đã gộp: {len(df_merged)} dòng")
        print(f"   - Normal (Label=0): {(df_merged['Label'] == 0).sum()} dòng")
        print(f"   - Attack (Label=1): {(df_merged['Label'] == 1).sum()} dòng")
        
        # Lọc Feature (Chỉ giữ lại các cột cần thiết)
        for col in SELECTED_FEATURES:
            if col not in df_merged.columns:
                df_merged[col] = 0
        
        df_merged = df_merged[SELECTED_FEATURES + ['Label']]
        
        # Làm sạch dữ liệu
        df_merged.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_merged.fillna(0, inplace=True)
        
        # Cân bằng dữ liệu (nếu cần)
        normal_count = (df_merged['Label'] == 0).sum()
        attack_count = (df_merged['Label'] == 1).sum()
        
        if normal_count != attack_count:
            print(f"⚖️ Đang cân bằng dữ liệu (Normal: {normal_count}, Attack: {attack_count})...")
            if attack_count < normal_count:
                df_attack = df_merged[df_merged['Label'] == 1]
                df_normal = df_merged[df_merged['Label'] == 0]
                df_attack_balanced = resample(df_attack, replace=True, n_samples=normal_count, random_state=42)
                df_merged = pd.concat([df_attack_balanced, df_normal])
            else:
                df_attack = df_merged[df_merged['Label'] == 1]
                df_normal = df_merged[df_merged['Label'] == 0]
                df_normal_balanced = resample(df_normal, replace=True, n_samples=attack_count, random_state=42)
                df_merged = pd.concat([df_attack, df_normal_balanced])
            
            # Shuffle lại sau khi cân bằng
            df_merged = df_merged.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"✅ Tổng dữ liệu sau khi xử lý: {len(df_merged)} dòng.")
        
    else:
        # Đọc từ 2 file riêng biệt (mode cũ)
        return load_from_separate_files()
    
    X = df_merged[SELECTED_FEATURES].values
    y = df_merged['Label'].values.astype(int)
    
    return X, y, df_merged

# %%
def load_from_separate_files():
    """Load data từ 2 file riêng biệt (mode cũ)"""
    if not os.path.exists(ATTACK_PATH) or not os.path.exists(NORMAL_PATH):
        raise FileNotFoundError(f"❌ Không tìm thấy file dữ liệu. Hãy chắc chắn bạn đã có '{ATTACK_PATH}' và '{NORMAL_PATH}'.")

    # Đọc file
    try:
        df_attack = pd.read_csv(ATTACK_PATH)
        df_normal = pd.read_csv(NORMAL_PATH)
    except Exception as e:
        print(f"⚠️ Lỗi đọc CSV: {e}")
        return None, None, None

    # Gán nhãn (Labeling)
    df_attack['Label'] = 1  # 1 = DDoS
    df_normal['Label'] = 0  # 0 = Normal

    print(f"📊 Dữ liệu gốc: Attack={len(df_attack)} dòng | Normal={len(df_normal)} dòng")

    # Lọc Feature (Chỉ giữ lại các cột cần thiết để tránh lỗi thiếu cột)
    # Nếu file thiếu cột nào đó, ta điền 0 vào
    for col in SELECTED_FEATURES:
        if col not in df_attack.columns:
            df_attack[col] = 0
        if col not in df_normal.columns:
            df_normal[col] = 0
            
    df_attack = df_attack[SELECTED_FEATURES + ['Label']]
    df_normal = df_normal[SELECTED_FEATURES + ['Label']]

    # Cân bằng dữ liệu (Balancing)
    # Upsample nhóm ít hơn để cân bằng 1:1
    if len(df_attack) < len(df_normal):
        print("⚖️ Đang nhân bản dữ liệu Attack để cân bằng...")
        df_attack_balanced = resample(df_attack, replace=True, n_samples=len(df_normal), random_state=42)
        df_merged = pd.concat([df_attack_balanced, df_normal])
    else:
        print("⚖️ Đang nhân bản dữ liệu Normal để cân bằng...")
        df_normal_balanced = resample(df_normal, replace=True, n_samples=len(df_attack), random_state=42)
        df_merged = pd.concat([df_attack, df_normal_balanced])

    # Xáo trộn dữ liệu
    df_merged = df_merged.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"✅ Tổng dữ liệu sau khi cân bằng: {len(df_merged)} dòng.")
    
    X = df_merged[SELECTED_FEATURES].values
    y = df_merged['Label'].values.astype(int)
    
    return X, y, df_merged

# %%
def explore_data(df_features: pd.DataFrame, labels: np.ndarray):
    """Data Exploration: Plot feature distributions and statistics"""
    print("\n" + "="*50)
    print("BƯỚC 1.5: DATA EXPLORATION")
    print("="*50)
    
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    # Plot distribution of each feature
    n_features = len(df_features.columns)
    n_cols = 4
    n_rows = (n_features + n_cols - 1) // n_cols
    
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 4 * n_rows))
    # Fix: np.atleast_1d handles single Axes, 1D array, and 2D array cases correctly
    axes = np.atleast_1d(axes).flatten()
    
    for idx, col in enumerate(df_features.columns):
        ax = axes[idx] if idx < len(axes) else None
        if ax is None:
            continue
        
        # Plot distribution for each class
        normal_data = df_features[labels == 0][col].dropna()
        attack_data = df_features[labels == 1][col].dropna()
        
        ax.hist(normal_data, bins=50, alpha=0.5, label="Normal", density=True, color="green")
        ax.hist(attack_data, bins=50, alpha=0.5, label="Attack", density=True, color="red")
        ax.set_title(f"{col}")
        ax.set_xlabel("Value")
        ax.set_ylabel("Density")
        ax.legend()
        ax.grid(True, alpha=0.3)
    
    # Hide unused subplots
    for idx in range(n_features, len(axes)):
        axes[idx].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "feature_distributions.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("📊 Đã lưu feature_distributions.png")
    
    # Print statistics
    print("\n📈 Feature Statistics:")
    print(df_features.describe())
    
    # Class distribution
    print(f"\n📊 Class Distribution:")
    print(f"Normal: {(labels == 0).sum()} ({(labels == 0).mean() * 100:.2f}%)")
    print(f"Attack: {(labels == 1).sum()} ({(labels == 1).mean() * 100:.2f}%)")

# %%
def build_cnn_model(input_shape):
    # Kiến trúc CNN Lite giống train_lite_model.py cũ
    inputs = keras.Input(shape=(input_shape, 1))
    x = layers.Conv1D(filters=32, kernel_size=3, activation="relu", padding="same")(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(pool_size=2)(x)
    x = layers.Flatten()(x)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(rate=0.2)(x)  # Thêm Dropout để chống overfitting
    outputs = layers.Dense(1, activation="sigmoid")(x)
    
    model = keras.Model(inputs=inputs, outputs=outputs, name="cnn_lite_v2")
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

# %%
def main():
    # Load Data
    X, y, df_merged = load_and_process_data()
    if X is None:
        return

    # Data Exploration
    df_features = df_merged[SELECTED_FEATURES].copy()
    explore_data(df_features, y)

    print("\n" + "="*50)
    print("BƯỚC 2: CHUẨN BỊ TRAIN")
    print("="*50)

    # Split Train/Test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Scale Data (Quan trọng)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Reshape cho CNN (Samples, Features, 1)
    X_train_reshaped = X_train_scaled.reshape(-1, X_train_scaled.shape[1], 1)
    X_test_reshaped = X_test_scaled.reshape(-1, X_test_scaled.shape[1], 1)

    print(f"Data Shape: {X_train_reshaped.shape}")

    # Train
    print("\n" + "="*50)
    print("BƯỚC 3: TRAINING MODEL")
    print("="*50)
    
    model = build_cnn_model(X_train_reshaped.shape[1])
    history = model.fit(
        X_train_reshaped, y_train,
        epochs=15, 
        batch_size=32, 
        validation_data=(X_test_reshaped, y_test),
        verbose=1
    )

    # Evaluate
    print("\n" + "="*50)
    print("BƯỚC 4: MODEL EVALUATION")
    print("="*50)
    
    y_test_proba = model.predict(X_test_reshaped, verbose=0).flatten()
    y_test_pred = (y_test_proba > 0.5).astype(int)
    
    acc = accuracy_score(y_test, y_test_pred)
    prec = precision_score(y_test, y_test_pred)
    rec = recall_score(y_test, y_test_pred)
    f1 = f1_score(y_test, y_test_pred)
    cm = confusion_matrix(y_test, y_test_pred)
    fpr, tpr, _ = roc_curve(y_test, y_test_proba)
    roc_auc = auc(fpr, tpr)
    
    print(f"📊 Metrics trên Test Set:")
    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%")
    print(f"  Recall:    {rec*100:.2f}%")
    print(f"  F1-Score:   {f1*100:.2f}%")
    print(f"  ROC AUC:    {roc_auc:.4f}")

    # Save Artifacts
    print("\n" + "="*50)
    print("BƯỚC 5: LƯU MODEL")
    print("="*50)
    
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)

    model_path = os.path.join(MODELS_DIR, "cnn_lite_model.h5")
    scaler_path = os.path.join(MODELS_DIR, "cnn_lite_scaler.pkl")
    features_path = os.path.join(MODELS_DIR, "cnn_lite_feature_names.pkl")

    model.save(model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(SELECTED_FEATURES, features_path)

    print(f"💾 Đã lưu Model tại: {model_path}")
    print(f"💾 Đã lưu Scaler tại: {scaler_path}")
    print(f"💾 Đã lưu Feature names tại: {features_path}")

    # Save plots
    print("\n" + "="*50)
    print("BƯỚC 6: LƯU PLOTS")
    print("="*50)
    
    # Training History
    plt.figure(figsize=(12, 4))
    plt.subplot(1, 2, 1)
    plt.plot(history.history["accuracy"], label="train_acc")
    plt.plot(history.history["val_accuracy"], label="val_acc")
    plt.title("Accuracy")
    plt.xlabel("Epoch")
    plt.ylabel("Accuracy")
    plt.legend()
    plt.grid(True)
    
    plt.subplot(1, 2, 2)
    plt.plot(history.history["loss"], label="train_loss")
    plt.plot(history.history["val_loss"], label="val_loss")
    plt.title("Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "training_history.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("📊 Đã lưu training_history.png")
    
    # ROC Curve
    plt.figure(figsize=(5, 4))
    plt.plot(fpr, tpr, label=f"AUC={roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve (test)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "roc_curve.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("📊 Đã lưu roc_curve.png")
    
    # Confusion Matrix
    plt.figure(figsize=(5, 4))
    plt.imshow(cm, cmap="Blues")
    plt.title("Confusion Matrix (test)")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.xticks([0, 1], ["Normal", "Attack"])
    plt.yticks([0, 1], ["Normal", "Attack"])
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center", color="black", fontsize=14)
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "confusion_matrix.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("📊 Đã lưu confusion_matrix.png")
    
    print("\n✅ Xong! Bây giờ bạn có thể chạy 'lite_detection_system.py' để test.")

# %%
if __name__ == "__main__":
    main()
# %%