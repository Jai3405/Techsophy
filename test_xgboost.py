#!/usr/bin/env python3
"""
Compare XGBoost vs Gradient Boosting for risk scoring.

Tests whether XGBoost can achieve better accuracy than the current 93.25%.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
import joblib

sys.path.insert(0, str(Path(__file__).parent / "src"))
from src.utils.logger import get_logger

logger = get_logger(__name__)


def create_enhanced_features(df):
    """Create enhanced features matching improve_models.py."""
    df = df.copy()

    # Feature interactions
    df['severity_x_exploitability'] = df['severity'] * df['exploitability']
    df['severity_x_confidence'] = df['severity'] * df['confidence']
    df['asset_value_x_exposure'] = df['asset_value'] * df['exposure']

    # Polynomial features
    df['exploitability_squared'] = df['exploitability'] ** 2
    df['severity_squared'] = df['severity'] ** 2

    # Ratios
    df['exploit_to_asset_ratio'] = df['exploitability'] / (df['asset_value'] + 1)
    df['severity_to_confidence_ratio'] = df['severity'] / (df['confidence'] + 1)

    # Boolean flags
    df['is_critical'] = (df['severity'] >= 4).astype(int)
    df['is_high_exploit'] = (df['exploitability'] >= 7).astype(int)
    df['is_high_confidence'] = (df['confidence'] == 3).astype(int)

    return df


def test_xgboost(X_train, X_test, y_train, y_test, label_encoder=None):
    """
    Test XGBoost classifier.

    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels
        y_test: Test labels
        label_encoder: Optional label encoder

    Returns:
        Trained XGBoost model
    """
    print("\n" + "="*60)
    print("Testing XGBoost Classifier")
    print("="*60)

    # Encode labels if needed
    if label_encoder is None:
        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        y_test_encoded = label_encoder.transform(y_test)
    else:
        y_train_encoded = y_train
        y_test_encoded = y_test

    # XGBoost with optimized parameters
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=8,
        min_child_weight=2,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        reg_alpha=0.1,  # L1 regularization
        reg_lambda=1.0,  # L2 regularization
        random_state=42,
        n_jobs=-1,
        eval_metric='mlogloss',
        enable_categorical=False
    )

    print("\nTraining XGBoost...")
    xgb_model.fit(X_train, y_train_encoded)

    # Evaluate
    y_pred_encoded = xgb_model.predict(X_test)
    y_pred = label_encoder.inverse_transform(y_pred_encoded)
    accuracy = accuracy_score(y_test, y_pred)

    # Cross-validation
    cv_scores = cross_val_score(xgb_model, X_train, y_train_encoded, cv=5, scoring='accuracy')

    print(f"\nXGBoost Performance:")
    print(f"  CV Accuracy:   {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    print(f"  Test Accuracy: {accuracy:.4f}")

    # Feature importance
    feature_names = [
        'severity', 'confidence', 'vuln_type_encoded', 'exploitability',
        'asset_value', 'exposure', 'severity_x_exploitability',
        'severity_x_confidence', 'asset_value_x_exposure',
        'exploitability_squared', 'severity_squared',
        'exploit_to_asset_ratio', 'severity_to_confidence_ratio',
        'is_critical', 'is_high_exploit', 'is_high_confidence'
    ]

    print(f"\nTop 10 Feature Importance (XGBoost):")
    importances = xgb_model.feature_importances_
    feature_imp = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    for name, imp in feature_imp[:10]:
        print(f"  {name:30s}: {imp:.4f}")

    return xgb_model, accuracy, label_encoder


def compare_all_models(X_train, X_test, y_train, y_test):
    """Compare all three algorithms."""
    print("\n" + "="*60)
    print("ALGORITHM COMPARISON")
    print("="*60)

    results = {}

    # 1. Current Gradient Boosting (from saved model)
    print("\n1. Loading current Gradient Boosting model...")
    try:
        model_data = joblib.load('models/risk_scorer.joblib')
        gb_current = model_data['model']
        y_pred = gb_current.predict(X_test)
        results['Gradient Boosting (current)'] = accuracy_score(y_test, y_pred)
        print(f"   Accuracy: {results['Gradient Boosting (current)']:.4f}")
    except Exception as e:
        print(f"   Could not load: {e}")
        results['Gradient Boosting (current)'] = 0.0

    # 2. Test XGBoost
    print("\n2. Training XGBoost model...")
    xgb_model, xgb_acc, label_encoder = test_xgboost(X_train, X_test, y_train, y_test)
    results['XGBoost'] = xgb_acc

    # 3. XGBoost with tuned parameters
    print("\n3. Training XGBoost with tuned hyperparameters...")

    # Encode labels
    y_train_encoded = label_encoder.transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)

    xgb_tuned = xgb.XGBClassifier(
        n_estimators=300,  # More trees
        learning_rate=0.05,  # Slower learning
        max_depth=10,
        min_child_weight=1,
        subsample=0.8,
        colsample_bytree=0.9,
        gamma=0.05,
        reg_alpha=0.05,
        reg_lambda=0.5,
        random_state=42,
        n_jobs=-1,
        eval_metric='mlogloss',
        enable_categorical=False
    )

    xgb_tuned.fit(X_train, y_train_encoded)
    y_pred_encoded = xgb_tuned.predict(X_test)
    y_pred = label_encoder.inverse_transform(y_pred_encoded)
    results['XGBoost (tuned)'] = accuracy_score(y_test, y_pred)
    print(f"   Test Accuracy: {results['XGBoost (tuned)']:.4f}")

    # Summary
    print("\n" + "="*60)
    print("FINAL COMPARISON")
    print("="*60)

    baseline = 0.892
    print("\nAccuracy Comparison:")
    for name, acc in sorted(results.items(), key=lambda x: x[1], reverse=True):
        improvement = (acc - baseline) * 100
        print(f"  {name:30s}: {acc:.4f} ({improvement:+.2f}% vs original)")

    # Determine best model
    best_method = max(results.items(), key=lambda x: x[1])
    print(f"\n✓ Best Algorithm: {best_method[0]} ({best_method[1]:.4f})")

    # Should we upgrade?
    current_acc = results.get('Gradient Boosting (current)', 0.932)
    best_acc = best_method[1]

    if best_acc > current_acc + 0.001:  # More than 0.1% improvement
        improvement_pct = (best_acc - current_acc) * 100
        print(f"\n✅ RECOMMENDATION: Upgrade to {best_method[0]}")
        print(f"   Additional improvement: +{improvement_pct:.2f}%")
        print(f"   New accuracy: {best_acc:.4f}")

        # Return best model for saving
        if 'tuned' in best_method[0]:
            return xgb_tuned, best_method[0], best_acc, label_encoder
        else:
            return xgb_model, best_method[0], best_acc, label_encoder
    else:
        print(f"\n⚠️  Current Gradient Boosting is already optimal")
        print(f"   XGBoost improvement: +{(best_acc - current_acc)*100:.2f}% (marginal)")
        return None, None, current_acc, None


def main():
    """Main comparison pipeline."""
    print("\n" + "="*60)
    print("XGBoost vs Gradient Boosting Comparison")
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

    # Create enhanced features
    df_enhanced = create_enhanced_features(df)

    feature_cols = [
        'severity', 'confidence', 'vuln_type_encoded', 'exploitability',
        'asset_value', 'exposure', 'severity_x_exploitability',
        'severity_x_confidence', 'asset_value_x_exposure',
        'exploitability_squared', 'severity_squared',
        'exploit_to_asset_ratio', 'severity_to_confidence_ratio',
        'is_critical', 'is_high_exploit', 'is_high_confidence'
    ]

    X = df_enhanced[feature_cols].values
    y = df_enhanced['risk_score'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Compare all models
    best_model, best_method, best_acc, label_encoder = compare_all_models(X_train, X_test, y_train, y_test)

    # Save if better
    if best_model is not None:
        print("\nSaving improved model...")
        models_dir = Path(__file__).parent / "models"
        model_path = models_dir / "risk_scorer.joblib"

        joblib.dump(
            {
                "model": best_model,
                "feature_names": feature_cols,
                "accuracy": best_acc,
                "method": best_method,
                "label_encoder": label_encoder,
            },
            model_path
        )

        print(f"\n✓ Model saved to: {model_path}")
        print(f"  Method: {best_method}")
        print(f"  Accuracy: {best_acc:.4f}")
        print(f"  Features: {len(feature_cols)}")
    else:
        print("\n✓ Current model is already optimal, no changes made.")


if __name__ == "__main__":
    main()
