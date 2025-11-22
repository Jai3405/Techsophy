#!/usr/bin/env python3
"""
Train ML models for vulnerability risk scoring and false positive filtering.

This script trains the models on the synthetic dataset and saves them
to the models/ directory for use by the scanner.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.utils.logger import get_logger

logger = get_logger(__name__)


def train_risk_scorer(X_train, X_test, y_train, y_test):
    """
    Train the risk scoring model.

    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels (risk scores 0-9)
        y_test: Test labels

    Returns:
        Trained model
    """
    print("\n" + "="*60)
    print("Training Risk Scorer Model")
    print("="*60)

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )

    print(f"\nTraining on {len(X_train)} samples...")
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nModel Performance:")
    print(f"  Training samples: {len(X_train)}")
    print(f"  Test samples:     {len(X_test)}")
    print(f"  Accuracy:         {accuracy:.3f}")

    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
    print(f"  CV Accuracy:      {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    # Feature importance
    feature_names = [
        "severity",
        "confidence",
        "vuln_type_encoded",
        "exploitability",
        "asset_value",
        "exposure",
    ]

    print(f"\nFeature Importance:")
    for name, importance in sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"  {name:20s}: {importance:.3f}")

    # Confusion matrix
    print(f"\nConfusion Matrix (first 5x5):")
    cm = confusion_matrix(y_test, y_pred)
    print(cm[:5, :5])

    return model


def train_false_positive_filter(X_train, X_test, y_train, y_test):
    """
    Train the false positive filter model.

    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels (0=genuine, 1=FP)
        y_test: Test labels

    Returns:
        Trained model
    """
    print("\n" + "="*60)
    print("Training False Positive Filter Model")
    print("="*60)

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight={0: 1, 1: 2},  # Penalize FP misclassification
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )

    print(f"\nTraining on {len(X_train)} samples...")
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nModel Performance:")
    print(f"  Training samples: {len(X_train)}")
    print(f"  Test samples:     {len(X_test)}")
    print(f"  Accuracy:         {accuracy:.3f}")

    # Classification report
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Genuine", "False Positive"]))

    # Feature importance
    feature_names = [
        "confidence",
        "code_context_score",
        "pattern_match_strength",
        "file_type_relevance",
        "historical_accuracy",
    ]

    print(f"\nFeature Importance:")
    for name, importance in sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"  {name:25s}: {importance:.3f}")

    return model


def main():
    """Main training pipeline."""
    print("\n" + "="*60)
    print("ML Model Training Pipeline")
    print("="*60)

    # Load dataset
    data_path = Path(__file__).parent / "data" / "training_data.csv"

    if not data_path.exists():
        print(f"\nError: Dataset not found at {data_path}")
        print("Run: python data/generate_dataset.py")
        sys.exit(1)

    print(f"\nLoading dataset from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"Loaded {len(df)} samples")

    # Prepare Risk Scorer data
    print("\n" + "="*60)
    print("Preparing Risk Scorer Training Data")
    print("="*60)

    X_risk = df[
        ["severity", "confidence", "vuln_type_encoded", "exploitability", "asset_value", "exposure"]
    ].values
    y_risk = df["risk_score"].values

    X_risk_train, X_risk_test, y_risk_train, y_risk_test = train_test_split(
        X_risk, y_risk, test_size=0.2, random_state=42
    )

    # Train Risk Scorer
    risk_model = train_risk_scorer(X_risk_train, X_risk_test, y_risk_train, y_risk_test)

    # Prepare False Positive Filter data
    print("\n" + "="*60)
    print("Preparing False Positive Filter Training Data")
    print("="*60)

    # Create features for FP filter
    # Simulating: confidence, code_context, pattern_match, file_relevance, historical_accuracy
    X_fp = np.column_stack([
        df["confidence"].values,
        10 - df["is_test_file"].values * 5,  # code_context_score (low for test files)
        df["confidence"].values * 2,  # pattern_match_strength
        10 - df["is_test_file"].values * 8,  # file_relevance (low for test files)
        df["confidence"].values * 3,  # historical_accuracy
    ])
    y_fp = df["is_false_positive"].values

    X_fp_train, X_fp_test, y_fp_train, y_fp_test = train_test_split(
        X_fp, y_fp, test_size=0.2, random_state=42
    )

    # Train FP Filter
    fp_model = train_false_positive_filter(X_fp_train, X_fp_test, y_fp_train, y_fp_test)

    # Save models
    print("\n" + "="*60)
    print("Saving Models")
    print("="*60)

    models_dir = Path(__file__).parent / "models"
    models_dir.mkdir(exist_ok=True)

    risk_model_path = models_dir / "risk_scorer.joblib"
    fp_model_path = models_dir / "fp_filter.joblib"

    # Save risk scorer
    joblib.dump(
        {
            "model": risk_model,
            "feature_names": [
                "severity",
                "confidence",
                "vulnerability_type",
                "exploitability",
                "asset_value",
                "exposure",
            ],
        },
        risk_model_path,
    )
    print(f"\n✓ Risk Scorer saved to: {risk_model_path}")

    # Save FP filter
    joblib.dump(
        {
            "model": fp_model,
            "feature_names": [
                "confidence",
                "code_context_score",
                "pattern_match_strength",
                "file_type_relevance",
                "historical_accuracy",
            ],
        },
        fp_model_path,
    )
    print(f"✓ FP Filter saved to: {fp_model_path}")

    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
    print(f"\nModels are ready to use:")
    print(f"  - {risk_model_path}")
    print(f"  - {fp_model_path}")
    print(f"\nYou can now run the scanner:")
    print(f"  python demo.py")
    print(f"  python -m src.main --repo-path test_repo/")


if __name__ == "__main__":
    main()
