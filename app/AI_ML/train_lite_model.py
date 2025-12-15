# %% [markdown]
"""
Train a lightweight CNN model using a reduced, leakage-safe feature set.

Features (Destination Port excluded):
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
- Optional: Flow IAT Std or Flow Bytes/s if present (to reach 12 features).

Outputs:
- models/cnn_lite_model.h5
- models/cnn_lite_scaler.pkl
- models/cnn_lite_feature_names.pkl
"""

# %%
from __future__ import annotations

import os
import sys
from typing import Iterable, List, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
)
import matplotlib.pyplot as plt
from tensorflow import keras
from tensorflow.keras import layers


MODELS_DIR = "models"
CSV_PATH = os.path.join("data", "DDoS.csv")
RANDOM_STATE = 42
TEST_SIZE = 0.2
EPOCHS = 10
BATCH_SIZE = 128


def normalize_column_names(raw_columns: Iterable[str]) -> List[str]:
    return [col.strip() for col in raw_columns]


# %%
def select_features(
    df: pd.DataFrame,
    base_features: Sequence[str],
    optional_features: Sequence[str],
) -> List[str]:
    present_optional = [f for f in optional_features if f in df.columns]
    selected = [f for f in base_features if f in df.columns] + present_optional
    if len(selected) < len(base_features):
        missing = [f for f in base_features if f not in df.columns]
        raise ValueError(f"Missing required features: {missing}")
    return selected


def load_and_clean(csv_path: str, feature_names: Sequence[str]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    df = pd.read_csv(csv_path)
    df.columns = normalize_column_names(df.columns)
    cleaned = df.replace([np.inf, -np.inf], np.nan).dropna()
    selected = select_features(
        cleaned,
        feature_names,
        ["Flow IAT Std", "Flow Bytes/s"],
    )
    features = cleaned[selected]
    labels = cleaned["Label"].apply(lambda v: 0 if str(v).upper() == "BENIGN" else 1)
    return features.to_numpy(dtype=np.float32), labels.to_numpy(dtype=np.int32), selected


# %%
def build_model(input_length: int) -> keras.Model:
    inputs = keras.Input(shape=(input_length, 1), name="flow_features")
    x = layers.Conv1D(filters=32, kernel_size=3, activation="relu")(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.MaxPooling1D(pool_size=2)(x)
    x = layers.Flatten()(x)
    x = layers.Dense(64, activation="relu")(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    model = keras.Model(inputs=inputs, outputs=outputs, name="cnn_lite")
    model.compile(
        optimizer=keras.optimizers.Adam(),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


# %%
def main() -> None:
    print("Debug: Loading data for lite training")
    base_features = [
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
    ]
    raw_x, y, selected_features = load_and_clean(CSV_PATH, base_features)
    print(f"Debug: Selected features: {selected_features}")

    x_train_raw, x_val_raw, y_train, y_val = train_test_split(
        raw_x,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
        shuffle=True,
    )

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train_raw)
    x_val_scaled = scaler.transform(x_val_raw)

    feature_count = x_train_scaled.shape[1]
    x_train = x_train_scaled.reshape(-1, feature_count, 1)
    x_val = x_val_scaled.reshape(-1, feature_count, 1)

    model = build_model(feature_count)
    print("Debug: Starting training")
    history = model.fit(
        x_train,
        y_train,
        validation_data=(x_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=2,
    )
    val_loss = history.history["val_loss"][-1]
    val_acc = history.history["val_accuracy"][-1]
    print(f"Debug: Training finished. val_loss={val_loss:.4f}, val_acc={val_acc:.4f}")

    # Simple evaluation on validation split (for artifacts)
    y_val_proba = model.predict(x_val, verbose=0).flatten()
    y_val_pred = (y_val_proba > 0.5).astype(int)
    acc = accuracy_score(y_val, y_val_pred)
    prec = precision_score(y_val, y_val_pred)
    rec = recall_score(y_val, y_val_pred)
    f1 = f1_score(y_val, y_val_pred)
    cm = confusion_matrix(y_val, y_val_pred)
    fpr, tpr, _ = roc_curve(y_val, y_val_proba)
    roc_auc = auc(fpr, tpr)
    print(f"Debug: Val metrics acc={acc:.4f} prec={prec:.4f} rec={rec:.4f} f1={f1:.4f} auc={roc_auc:.4f}")

    os.makedirs(MODELS_DIR, exist_ok=True)
    model_path = os.path.join(MODELS_DIR, "cnn_lite_model.h5")
    scaler_path = os.path.join(MODELS_DIR, "cnn_lite_scaler.pkl")
    feature_path = os.path.join(MODELS_DIR, "cnn_lite_feature_names.pkl")
    model.save(model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(selected_features, feature_path)
    print(f"Debug: Saved model to {model_path}")
    print(f"Debug: Saved scaler to {scaler_path}")
    print(f"Debug: Saved feature names to {feature_path}")

    # Save plots similar to archived notebook
    plt.figure(figsize=(10, 4))
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
    print("Debug: Saved training_history.png")

    plt.figure(figsize=(5, 4))
    plt.plot(fpr, tpr, label=f"AUC={roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve (val)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "roc_curve.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("Debug: Saved roc_curve.png")

    plt.figure(figsize=(5, 4))
    plt.imshow(cm, cmap="Blues")
    plt.title("Confusion Matrix (val)")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center", color="black")
    plt.tight_layout()
    plt.savefig(os.path.join(MODELS_DIR, "confusion_matrix.png"), dpi=300, bbox_inches="tight")
    plt.close()
    print("Debug: Saved confusion_matrix.png")


# %%
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)


# %%
