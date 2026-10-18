"""
SENTRIX — AI-Powered URL Threat Intelligence
Model Training & Evaluation Script

This script:
1. Loads the labelled dataset and verifies column structure and three-class labels.
2. Extracts 21 pure-lexical and heuristic features for each URL using feature_extractor.py.
3. Splits data into stratified Train (80%) and Test (20%) sets.
4. Trains a Random Forest Classifier on the extracted features.
5. Computes Accuracy, Precision, Recall, F1-Score, and a Confusion Matrix.
6. Saves the trained model bundle and confusion matrix visualization to models/.
"""

import os
import sys
import json
from datetime import datetime

try:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# Import feature extractor from local module
from feature_extractor import extract_features, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "malicious_urls_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_SAVE_PATH = os.path.join(MODELS_DIR, "url_classifier.joblib")
CONF_MATRIX_IMAGE_PATH = os.path.join(MODELS_DIR, "confusion_matrix.png")


def verify_and_load_dataset(filepath: str) -> pd.DataFrame:
    """
    Verifies that the dataset file exists, contains the required columns,
    and genuinely supports all three expected classes (Safe, Suspicious, Malicious).
    """
    print(f"[1/6] Verifying dataset at: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"[-] ERROR: Dataset file not found at '{filepath}'.")
        print("    Please compile it using 'python data/build_dataset.py'.")
        sys.exit(1)

    df = pd.read_csv(filepath)
    
    required_cols = {"url", "label"}
    if not required_cols.issubset(set(df.columns)):
        print(f"[-] ERROR: Dataset must contain columns: {required_cols}. Found: {list(df.columns)}")
        sys.exit(1)

    unique_labels = set(df["label"].dropna().unique())
    expected_labels = {"Safe", "Suspicious", "Malicious"}
    
    print(f"      Columns detected: {list(df.columns)}")
    print(f"      Total URL records: {len(df)}")
    print(f"      Unique class labels detected: {unique_labels}")
    
    if not expected_labels.issubset(unique_labels):
        print("[-] ERROR: Dataset does not genuinely support all three classes!")
        print(f"    Expected: {expected_labels}")
        print(f"    Found:    {unique_labels}")
        sys.exit(1)

    print("      Class distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"        - {label:<12}: {count} samples ({count / len(df) * 100:.1f}%)")

    return df


def build_feature_matrix(df: pd.DataFrame):
    """
    Extracts numerical features from raw URLs and maps text labels to integers.
    """
    print(f"[2/6] Extracting lexical and heuristic features ({len(FEATURE_NAMES)} features) for {len(df)} URLs...")
    feature_rows = []
    
    for url in df["url"]:
        feats = extract_features(str(url))
        feature_rows.append([feats[col] for col in FEATURE_NAMES])
        
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    
    label_map = {"Safe": 0, "Suspicious": 1, "Malicious": 2}
    y = df["label"].map(label_map).values
    class_names = ["Safe", "Suspicious", "Malicious"]

    print(f"      Extracted {X.shape[1]} features across {X.shape[0]} samples.")
    return X, y, class_names


def train_and_evaluate(X, y, class_names):
    """
    Performs train/test split, trains Random Forest, and calculates all evaluation metrics.
    """
    print("[3/6] Performing Stratified Train/Test Split (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"      Training samples:   {len(X_train)}")
    print(f"      Testing samples:    {len(X_test)}")

    print("[4/6] Training Random Forest Classifier (100 estimators, max_depth=12, random_state=42)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=1
    )
    clf.fit(X_train, y_train)
    print("      Model training complete.")

    print("[5/6] Evaluating model on unseen test set...")
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    
    prec_weighted = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec_weighted = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    report_dict = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )
    report_text = classification_report(
        y_test, y_pred, target_names=class_names, zero_division=0
    )
    
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 65)
    print("        SENTRIX MODEL EVALUATION REPORT (TEST SET)       ")
    print("=" * 65)
    print(f"  Overall Accuracy:      {acc * 100:.2f}%")
    print(f"  Macro Precision:       {prec_macro * 100:.2f}%")
    print(f"  Macro Recall:          {rec_macro * 100:.2f}%")
    print(f"  Macro F1-Score:        {f1_macro * 100:.2f}%")
    print(f"  Weighted F1-Score:     {f1_weighted * 100:.2f}%")
    print("-" * 65)
    print("  Per-Class Performance:")
    print(report_text)
    print("-" * 65)
    print("  Confusion Matrix (Rows=True, Cols=Predicted):")
    print("                  Pred Safe  Pred Suspicious  Pred Malicious")
    for i, c_name in enumerate(class_names):
        print(f"    True {c_name:<11} {cm[i][0]:^9}    {cm[i][1]:^14}    {cm[i][2]:^14}")
    print("=" * 65 + "\n")

    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_))
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print("Top Feature Importances:")
    for feat_name, imp in sorted_importances[:10]:
        bar = "=" * int(imp * 50)
        print(f"  - {feat_name:<25}: {imp:.4f} [{bar}]")

    metrics_bundle = {
        "accuracy": float(acc),
        "precision_macro": float(prec_macro),
        "recall_macro": float(rec_macro),
        "f1_macro": float(f1_macro),
        "precision_weighted": float(prec_weighted),
        "recall_weighted": float(rec_weighted),
        "f1_weighted": float(f1_weighted),
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist()
    }

    return clf, metrics_bundle, importances, cm


def save_artifacts(clf, metrics_bundle, importances, cm, class_names, train_count, test_count):
    """Saves trained model bundle, metrics, and confusion matrix plot to disk."""
    print(f"[6/6] Saving model bundle and visualization artifacts to '{MODELS_DIR}'...")
    os.makedirs(MODELS_DIR, exist_ok=True)

    try:
        plt.figure(figsize=(6, 5))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            cbar=False
        )
        plt.title("SENTRIX — Confusion Matrix", fontsize=12, fontweight="bold", pad=12)
        plt.xlabel("Predicted Class", fontsize=10, labelpad=8)
        plt.ylabel("True Class", fontsize=10, labelpad=8)
        plt.tight_layout()
        plt.savefig(CONF_MATRIX_IMAGE_PATH, dpi=150)
        plt.close()
        print(f"      Confusion matrix plot saved: {CONF_MATRIX_IMAGE_PATH}")
    except Exception as e:
        print(f"      [!] Note: Could not render plot ({e}). Continuing to save model bundle.")

    bundle = {
        "model": clf,
        "classes": class_names,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics_bundle,
        "feature_importances": importances,
        "dataset_info": {
            "path": DATA_PATH,
            "train_samples": train_count,
            "test_samples": test_count,
            "total_samples": train_count + test_count
        },
        "training_metadata": {
            "trained_at": datetime.now().isoformat(),
            "model_type": "RandomForestClassifier",
            "n_estimators": 100,
            "version": "2.0.0"
        }
    }

    joblib.dump(bundle, MODEL_SAVE_PATH)
    print(f"      Model bundle successfully saved: {MODEL_SAVE_PATH}")
    print("\n>>> SUCCESS: SENTRIX model trained, evaluated, and ready for deployment! <<<\n")


def main():
    print("=================================================================")
    print("      SENTRIX — AI-Powered URL Threat Intelligence Trainer       ")
    print("=================================================================\n")
    
    df = verify_and_load_dataset(DATA_PATH)
    X, y, class_names = build_feature_matrix(df)
    clf, metrics, importances, cm = train_and_evaluate(X, y, class_names)
    save_artifacts(clf, metrics, importances, cm, class_names, int(len(X) * 0.8), int(len(X) * 0.2))


if __name__ == "__main__":
    main()
