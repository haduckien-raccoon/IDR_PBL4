# %%
"""
Health Check & Multi-Model Training Script

So sánh 4 thuật toán ML để phát hiện DDoS:
- Random Forest Classifier
- Decision Tree Classifier  
- Neural Network (MLPClassifier)
- CNN (TensorFlow/Keras)

Output:
- Feature importance analysis
- Confusion matrices comparison
- ROC curves comparison
- Class distribution visualization
"""

# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_curve,
    auc,
    roc_auc_score,
)
import time
import os
from tensorflow import keras
from tensorflow.keras import layers

# %%
# --- CẤU HÌNH ---
DATASET_PATH = os.path.join("data", "final_dataset_shuffled.csv")
MODELS_DIR = "models"

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
def train_and_evaluate(name, model, X_train, X_test, y_train, y_test, use_scaled=False):
    """Train và đánh giá một model"""
    print(f"\n{'='*60}")
    print(f"🔧 ĐANG TRAIN: {name}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # Chọn dữ liệu scaled hoặc raw
    X_train_use = X_train if use_scaled else X_train
    X_test_use = X_test if use_scaled else X_test
    
    # Train
    model.fit(X_train_use, y_train)
    
    # Predict
    y_pred = model.predict(X_test_use)
    y_proba = None
    
    # Lấy probability nếu model hỗ trợ
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test_use)[:, 1]
    
    # Evaluate
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    train_time = time.time() - start_time
    
    print(f"⏱️  Thời gian train: {train_time:.2f}s")
    print(f"🏆 Accuracy:  {acc:.4%}")
    print(f"📊 Precision: {prec:.4%}")
    print(f"📊 Recall:    {rec:.4%}")
    print(f"📊 F1-Score:  {f1:.4%}")
    
    if y_proba is not None:
        roc_auc = roc_auc_score(y_test, y_proba)
        print(f"📊 ROC AUC:   {roc_auc:.4f}")
    
    print("\n--- Detailed Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)']))
    
    return y_pred, y_proba, {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'roc_auc': roc_auc if y_proba is not None else None,
        'train_time': train_time
    }

# %%
def build_cnn_model(input_shape):
    """Build CNN model giống train_real_data.py"""
    inputs = keras.Input(shape=(input_shape, 1))
    x = layers.Conv1D(filters=32, kernel_size=3, activation="relu", padding="same")(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(pool_size=2)(x)
    x = layers.Flatten()(x)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(rate=0.2)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    
    model = keras.Model(inputs=inputs, outputs=outputs, name="cnn_lite_v2")
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

# %%
# ============================================================
# BƯỚC 1: LOAD & CLEAN DATA
# ============================================================
try:
    print("="*60)
    print("🚀 BƯỚC 1: TẢI VÀ LÀM SẠCH DỮ LIỆU")
    print("="*60)
    
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"❌ Không tìm thấy file: {DATASET_PATH}\n💡 Hãy chạy combine_datasets.py trước!")
    
    print(f"📖 Đang đọc file: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"✅ Đã đọc {len(df)} dòng, {len(df.columns)} cột")
    
    # Kiểm tra cột Label
    if 'Label' not in df.columns:
        raise ValueError("❌ File không có cột 'Label'. Hãy kiểm tra lại file dữ liệu.")
    
    # Xử lý vô cực và null
    print("\n🔧 Đang làm sạch dữ liệu...")
    inf_count_before = (df == np.inf).sum().sum() + (df == -np.inf).sum().sum()
    nan_count_before = df.isna().sum().sum()
    
    if inf_count_before > 0:
        print(f"   - Phát hiện {inf_count_before} giá trị Infinity")
    if nan_count_before > 0:
        print(f"   - Phát hiện {nan_count_before} giá trị NaN")
    
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    print("✅ Đã làm sạch xong!")
    
    # ============================================================
    # BƯỚC 2: DATA DIAGNOSTICS - KIỂM TRA IMBALANCE
    # ============================================================
    print("\n" + "="*60)
    print("📊 BƯỚC 2: CHẨN ĐOÁN DỮ LIỆU (DATA DIAGNOSTICS)")
    print("="*60)
    
    counts = df['Label'].value_counts()
    total = len(df)
    normal_count = counts.get(0, 0)
    attack_count = counts.get(1, 0)
    normal_ratio = normal_count / total
    attack_ratio = attack_count / total
    
    print(f"\n📈 TỔNG QUAN DỮ LIỆU:")
    print(f"   Tổng số mẫu: {total:,}")
    print(f"   Normal (0): {normal_count:,} ({normal_ratio:.2%})")
    print(f"   Attack (1): {attack_count:,} ({attack_ratio:.2%})")
    
    # Tính Imbalance Ratio
    if normal_count > 0 and attack_count > 0:
        imbalance_ratio = max(normal_count, attack_count) / min(normal_count, attack_count)
        print(f"\n⚖️  IMBALANCE RATIO: {imbalance_ratio:.2f}:1")
        
        if imbalance_ratio > 5:
            print(f"⚠️  CẢNH BÁO: Dữ liệu bị mất cân bằng nghiêm trọng!")
            print(f"   (Tỷ lệ {imbalance_ratio:.1f}:1 có thể làm model bias)")
        elif imbalance_ratio > 2:
            print(f"⚠️  Lưu ý: Dữ liệu hơi mất cân bằng ({imbalance_ratio:.1f}:1)")
        else:
            print(f"✅ Dữ liệu tương đối cân bằng ({imbalance_ratio:.1f}:1)")
    
    # Vẽ biểu đồ phân phối class
    plt.figure(figsize=(10, 6))
    plt.subplot(1, 2, 1)
    counts.plot(kind='bar', color=['green', 'red'], alpha=0.7)
    plt.title('Class Distribution (Count)', fontsize=14, fontweight='bold')
    plt.xlabel('Label')
    plt.ylabel('Count')
    plt.xticks([0, 1], ['Normal (0)', 'Attack (1)'], rotation=0)
    plt.grid(axis='y', alpha=0.3)
    
    # Thêm số liệu lên cột
    for i, v in enumerate(counts):
        plt.text(i, v, f'{v:,}', ha='center', va='bottom', fontweight='bold')
    
    plt.subplot(1, 2, 2)
    plt.pie([normal_ratio, attack_ratio], labels=['Normal', 'Attack'], 
            colors=['green', 'red'], autopct='%1.1f%%', startangle=90)
    plt.title('Class Distribution (Percentage)', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    os.makedirs(MODELS_DIR, exist_ok=True)
    plt.savefig(os.path.join(MODELS_DIR, 'class_distribution.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\n📸 Đã lưu biểu đồ phân phối class vào: {os.path.join(MODELS_DIR, 'class_distribution.png')}")
    
    # ============================================================
    # BƯỚC 3: PREPARE DATA
    # ============================================================
    print("\n" + "="*60)
    print("🔧 BƯỚC 3: CHUẨN BỊ DỮ LIỆU")
    print("="*60)
    
    # Chọn features
    print(f"\n📋 Đang chọn {len(SELECTED_FEATURES)} features...")
    missing_features = [f for f in SELECTED_FEATURES if f not in df.columns]
    if missing_features:
        print(f"⚠️  Cảnh báo: Thiếu các features: {missing_features}")
        print("   Đang điền 0 cho các features thiếu...")
        for f in missing_features:
            df[f] = 0
    
    # Lọc features
    X = df[SELECTED_FEATURES].copy()
    y = df['Label'].copy()
    
    print(f"✅ Đã chọn {len(X.columns)} features")
    print(f"   Features: {', '.join(X.columns.tolist())}")
    
    # Split data
    print("\n🔀 Đang chia dữ liệu (Train/Test = 80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"✅ Train set: {len(X_train):,} mẫu")
    print(f"✅ Test set:  {len(X_test):,} mẫu")
    
    # Scale dữ liệu (cho Neural Network)
    print("\n📏 Đang chuẩn hóa dữ liệu (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("✅ Đã chuẩn hóa xong!")
    
    # ============================================================
    # BƯỚC 4: TRAIN CÁC MODELS
    # ============================================================
    print("\n" + "="*60)
    print("🤖 BƯỚC 4: HUẤN LUYỆN ĐA MÔ HÌNH")
    print("="*60)
    
    results = {}
    
    # Model A: Random Forest (Baseline mạnh nhất)
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    y_pred_rf, y_proba_rf, metrics_rf = train_and_evaluate(
        "Random Forest Classifier", rf_model, X_train, X_test, y_train, y_test, use_scaled=False
    )
    results['Random Forest'] = {
        'model': rf_model,
        'y_pred': y_pred_rf,
        'y_proba': y_proba_rf,
        'metrics': metrics_rf
    }
    
    # Model B: Decision Tree (Dễ giải thích)
    dt_model = DecisionTreeClassifier(random_state=42, max_depth=10)
    y_pred_dt, y_proba_dt, metrics_dt = train_and_evaluate(
        "Decision Tree Classifier", dt_model, X_train, X_test, y_train, y_test, use_scaled=False
    )
    results['Decision Tree'] = {
        'model': dt_model,
        'y_pred': y_pred_dt,
        'y_proba': y_proba_dt,
        'metrics': metrics_dt
    }
    
    # Model C: Neural Network (MLP)
    nn_model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=500,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1
    )
    y_pred_nn, y_proba_nn, metrics_nn = train_and_evaluate(
        "Neural Network (MLP)", nn_model, X_train_scaled, X_test_scaled, y_train, y_test, use_scaled=True
    )
    results['Neural Network'] = {
        'model': nn_model,
        'y_pred': y_pred_nn,
        'y_proba': y_proba_nn,
        'metrics': metrics_nn
    }
    
    # Model D: CNN (TensorFlow/Keras)
    print("\n" + "="*60)
    print("🔧 ĐANG TRAIN: CNN (TensorFlow/Keras)")
    print("="*60)
    
    start_time = time.time()
    
    # Reshape data cho CNN: (samples, features, 1)
    feature_count = X_train_scaled.shape[1]
    X_train_cnn = X_train_scaled.reshape(-1, feature_count, 1)
    X_test_cnn = X_test_scaled.reshape(-1, feature_count, 1)
    
    # Build và train CNN
    cnn_model = build_cnn_model(feature_count)
    history = cnn_model.fit(
        X_train_cnn, y_train,
        epochs=15,
        batch_size=32,
        validation_data=(X_test_cnn, y_test),
        verbose=0
    )
    
    # Predict
    y_proba_cnn = cnn_model.predict(X_test_cnn, verbose=0).flatten()
    y_pred_cnn = (y_proba_cnn > 0.5).astype(int)
    
    # Evaluate
    acc = accuracy_score(y_test, y_pred_cnn)
    prec = precision_score(y_test, y_pred_cnn)
    rec = recall_score(y_test, y_pred_cnn)
    f1 = f1_score(y_test, y_pred_cnn)
    roc_auc = roc_auc_score(y_test, y_proba_cnn)
    train_time = time.time() - start_time
    
    print(f"⏱️  Thời gian train: {train_time:.2f}s")
    print(f"🏆 Accuracy:  {acc:.4%}")
    print(f"📊 Precision: {prec:.4%}")
    print(f"📊 Recall:    {rec:.4%}")
    print(f"📊 F1-Score:  {f1:.4%}")
    print(f"📊 ROC AUC:   {roc_auc:.4f}")
    
    print("\n--- Detailed Classification Report ---")
    print(classification_report(y_test, y_pred_cnn, target_names=['Normal (0)', 'Attack (1)']))
    
    results['CNN'] = {
        'model': cnn_model,
        'y_pred': y_pred_cnn,
        'y_proba': y_proba_cnn,
        'metrics': {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1,
            'roc_auc': roc_auc,
            'train_time': train_time
        }
    }
    
    # ============================================================
    # BƯỚC 5: SO SÁNH KẾT QUẢ
    # ============================================================
    print("\n" + "="*60)
    print("📊 BƯỚC 5: SO SÁNH KẾT QUẢ")
    print("="*60)
    
    # Tạo bảng so sánh
    comparison_df = pd.DataFrame({
        'Model': list(results.keys()),
        'Accuracy': [r['metrics']['accuracy'] for r in results.values()],
        'Precision': [r['metrics']['precision'] for r in results.values()],
        'Recall': [r['metrics']['recall'] for r in results.values()],
        'F1-Score': [r['metrics']['f1'] for r in results.values()],
        'ROC AUC': [r['metrics']['roc_auc'] if r['metrics']['roc_auc'] else 0 for r in results.values()],
        'Train Time (s)': [r['metrics']['train_time'] for r in results.values()]
    })
    
    print("\n📋 BẢNG SO SÁNH CÁC MODELS:")
    print(comparison_df.to_string(index=False))
    
    # Tìm model tốt nhất
    best_model_name = comparison_df.loc[comparison_df['F1-Score'].idxmax(), 'Model']
    print(f"\n🏆 MODEL TỐT NHẤT (theo F1-Score): {best_model_name}")
    print(f"   F1-Score: {comparison_df.loc[comparison_df['F1-Score'].idxmax(), 'F1-Score']:.4%}")
    
    # ============================================================
    # BƯỚC 6: FEATURE IMPORTANCE ANALYSIS
    # ============================================================
    print("\n" + "="*60)
    print("🔍 BƯỚC 6: PHÂN TÍCH FEATURE IMPORTANCE")
    print("="*60)
    
    print("\n📊 Random Forest - Feature Importance:")
    print("(Model này dựa vào cột nào để quyết định?)")
    
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("\nTop Features quan trọng nhất:")
    for i in range(len(SELECTED_FEATURES)):
        idx = indices[i]
        print(f"  {i+1:2d}. {SELECTED_FEATURES[idx]:30s}: {importances[idx]:.4f} ({importances[idx]*100:.2f}%)")
    
    # Vẽ biểu đồ Feature Importance
    plt.figure(figsize=(12, 8))
    plt.barh(range(len(SELECTED_FEATURES)), importances[indices], align="center", color='steelblue')
    plt.yticks(range(len(SELECTED_FEATURES)), [SELECTED_FEATURES[i] for i in indices])
    plt.xlabel('Importance Score', fontsize=12, fontweight='bold')
    plt.title('Feature Importance - Random Forest Classifier', fontsize=14, fontweight='bold')
    plt.grid(axis='x', alpha=0.3)
    
    # Thêm giá trị lên cột
    for i, v in enumerate(importances[indices]):
        plt.text(v, i, f' {v:.3f}', va='center', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, 'feature_importance.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\n📸 Đã lưu biểu đồ Feature Importance vào: {os.path.join(MODELS_DIR, 'feature_importance.png')}")

    # ============================================================
    # BƯỚC 7: VISUALIZATION - CONFUSION MATRICES
    # ============================================================
    print("\n" + "="*60)
    print("📊 BƯỚC 7: VẼ CONFUSION MATRICES")
    print("="*60)
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 12))
    axes = axes.flatten()
    
    models_info = [
        ('Random Forest', y_pred_rf, 'Blues'),
        ('Decision Tree', y_pred_dt, 'Greens'),
        ('Neural Network', y_pred_nn, 'Oranges'),
        ('CNN', y_pred_cnn, 'Reds')
    ]
    
    for idx, (name, y_pred, cmap) in enumerate(models_info):
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap=cmap, ax=axes[idx],
                   xticklabels=['Normal', 'Attack'],
                   yticklabels=['Normal', 'Attack'])
        axes[idx].set_title(f'{name}\nAccuracy: {accuracy_score(y_test, y_pred):.2%}', 
                           fontsize=11, fontweight='bold')
        axes[idx].set_xlabel('Predicted', fontsize=9)
        axes[idx].set_ylabel('Actual', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, 'comparison_confusion_matrices.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"📸 Đã lưu Confusion Matrices so sánh vào: {os.path.join(MODELS_DIR, 'comparison_confusion_matrices.png')}")
    
    # ============================================================
    # BƯỚC 8: VISUALIZATION - ROC CURVES
    # ============================================================
    print("\n" + "="*60)
    print("📊 BƯỚC 8: VẼ ROC CURVES")
    print("="*60)
    
    plt.figure(figsize=(10, 8))
    
    for name, result in results.items():
        if result['y_proba'] is not None:
            fpr, tpr, _ = roc_curve(y_test, result['y_proba'])
            roc_auc = result['metrics']['roc_auc']
            plt.plot(fpr, tpr, label=f'{name} (AUC = {roc_auc:.4f})', linewidth=2)
    
    plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier', linewidth=1)
    plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')
    plt.title('ROC Curves Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, 'comparison_roc_curves.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"📸 Đã lưu ROC Curves so sánh vào: {os.path.join(MODELS_DIR, 'comparison_roc_curves.png')}")
    
    # ============================================================
    # BƯỚC 9: VISUALIZATION - METRICS COMPARISON
    # ============================================================
    print("\n" + "="*60)
    print("📊 BƯỚC 9: VẼ BIỂU ĐỒ SO SÁNH METRICS")
    print("="*60)
    
    metrics_to_plot = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC']
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    axes = axes.flatten()
    
    # Mapping từ tên metric hiển thị sang key trong dict
    metric_key_map = {
        'Accuracy': 'accuracy',
        'Precision': 'precision',
        'Recall': 'recall',
        'F1-Score': 'f1',  # Key là 'f1' không phải 'f1_score'
        'ROC AUC': 'roc_auc'
    }
    
    for idx, metric in enumerate(metrics_to_plot):
        if metric == 'ROC AUC':
            values = [r['metrics']['roc_auc'] if r['metrics']['roc_auc'] else 0 for r in results.values()]
        else:
            key = metric_key_map[metric]
            values = [r['metrics'][key] for r in results.values()]
        
        bars = axes[idx].bar(results.keys(), values, color=['steelblue', 'forestgreen', 'darkorange', 'crimson'], alpha=0.7)
        axes[idx].set_title(metric, fontsize=12, fontweight='bold')
        axes[idx].set_ylabel('Score', fontsize=10)
        axes[idx].set_ylim([0, 1.1])
        axes[idx].grid(axis='y', alpha=0.3)
        
        # Thêm giá trị lên cột
        for bar, val in zip(bars, values):
            height = bar.get_height()
            axes[idx].text(bar.get_x() + bar.get_width()/2., height,
                          f'{val:.3f}', ha='center', va='bottom', fontweight='bold')
    
    # Ẩn subplot thừa
    axes[5].axis('off')
    
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, 'comparison_metrics.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"📸 Đã lưu biểu đồ so sánh metrics vào: {os.path.join(MODELS_DIR, 'comparison_metrics.png')}")
    
    print("\n" + "="*60)
    print("✅ HOÀN TẤT!")
    print("="*60)
    print(f"\n📁 Tất cả plots đã được lưu trong thư mục: {MODELS_DIR}/")
    print("   - class_distribution.png")
    print("   - feature_importance.png")
    print("   - comparison_confusion_matrices.png")
    print("   - comparison_roc_curves.png")
    print("   - comparison_metrics.png")
    print("\n💡 Kết luận:")
    if 'best_model_name' in locals():
        print(f"   - Model tốt nhất: {best_model_name}")
    if 'indices' in locals():
        print(f"   - Feature quan trọng nhất: {SELECTED_FEATURES[indices[0]]}")
    if 'imbalance_ratio' in locals():
        print(f"   - Imbalance ratio: {imbalance_ratio:.2f}:1")

except FileNotFoundError as e:
    print(f"\n❌ LỖI: Không tìm thấy file.")
    print(f"Chi tiết: {e}")
    print(f"\n💡 Hãy chạy combine_datasets.py trước để tạo file {DATASET_PATH}")
except Exception as e:
    print(f"\n❌ LỖI KHÔNG XÁC ĐỊNH: {e}")
    import traceback
    traceback.print_exc()



# %%
