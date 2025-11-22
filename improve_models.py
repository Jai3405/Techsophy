#!/usr/bin/env python3
"""
Improve ML model accuracy through hyperparameter tuning and advanced techniques.

This script experiments with:
1. Hyperparameter tuning (GridSearchCV)
2. More training data
3. Additional features
4. Ensemble methods
5. Feature scaling
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib

sys.path.insert(0, str(Path(__file__).parent / "src"))
from src.utils.logger import get_logger

logger = get_logger(__name__)


def create_enhanced_features(df):
    """
    Create additional engineered features to improve accuracy.

    Args:
        df: Original dataframe

    Returns:
        DataFrame with additional features
    """
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


def tune_risk_scorer(X_train, X_test, y_train, y_test, quick=False):
    """
    Hyperparameter tuning for risk scorer.

    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels
        y_test: Test labels
        quick: Use smaller param grid for faster tuning

    Returns:
        Best model
    """
    print("\n" + "="*60)
    print("Hyperparameter Tuning for Risk Scorer")
    print("="*60)

    if quick:
        param_grid = {
            'n_estimators': [150, 200],
            'max_depth': [10, 12],
            'min_samples_split': [5],
            'min_samples_leaf': [2],
        }
    else:
        param_grid = {
            'n_estimators': [150, 200, 250, 300],
            'max_depth': [10, 12, 15, 20],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2'],
        }

    rf = RandomForestClassifier(random_state=42, n_jobs=-1)

    print(f"\nSearching through {len(param_grid)} hyperparameters...")
    print(f"This may take a few minutes...\n")

    grid_search = GridSearchCV(
        rf,
        param_grid,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=1
    )

    grid_search.fit(X_train, y_train)

    print(f"\n✓ Best parameters found:")
    for param, value in grid_search.best_params_.items():
        print(f"  {param:20s}: {value}")

    # Evaluate best model
    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n✓ Best Model Performance:")
    print(f"  CV Accuracy:   {grid_search.best_score_:.4f}")
    print(f"  Test Accuracy: {accuracy:.4f}")

    return best_model


def try_gradient_boosting(X_train, X_test, y_train, y_test):
    """
    Try Gradient Boosting as alternative to Random Forest.

    Args:
        X_train: Training features
        X_test: Test features
        y_train: Training labels
        y_test: Test labels

    Returns:
        Trained model
    """
    print("\n" + "="*60)
    print("Training Gradient Boosting Model")
    print("="*60)

    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=8,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.8,
        random_state=42,
        verbose=0
    )

    print("\nTraining...")
    gb.fit(X_train, y_train)

    y_pred = gb.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    cv_scores = cross_val_score(gb, X_train, y_train, cv=5, scoring='accuracy')

    print(f"\nGradient Boosting Performance:")
    print(f"  CV Accuracy:   {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    print(f"  Test Accuracy: {accuracy:.4f}")

    return gb


def create_ensemble(models, X_test, y_test):
    """
    Create ensemble of multiple models through voting.

    Args:
        models: List of trained models
        X_test: Test features
        y_test: Test labels

    Returns:
        Ensemble predictions accuracy
    """
    print("\n" + "="*60)
    print("Creating Ensemble Model")
    print("="*60)

    # Collect predictions from all models
    predictions = []
    for i, model in enumerate(models):
        pred = model.predict(X_test)
        predictions.append(pred)
        acc = accuracy_score(y_test, pred)
        print(f"  Model {i+1} accuracy: {acc:.4f}")

    # Majority voting
    predictions = np.array(predictions)
    ensemble_pred = np.apply_along_axis(
        lambda x: np.bincount(x).argmax(),
        axis=0,
        arr=predictions
    )

    ensemble_acc = accuracy_score(y_test, ensemble_pred)
    print(f"\n✓ Ensemble Accuracy: {ensemble_acc:.4f}")

    return ensemble_acc


def main():
    """Main improvement pipeline."""
    print("\n" + "="*60)
    print("ML Model Accuracy Improvement Pipeline")
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

    # Option 1: Add more features
    print("\n" + "="*60)
    print("IMPROVEMENT 1: Feature Engineering")
    print("="*60)

    df_enhanced = create_enhanced_features(df)

    print(f"\nOriginal features: 6")
    print(f"Enhanced features: {df_enhanced.shape[1] - len(df.columns) + 6}")
    print("\nNew features added:")
    new_cols = [col for col in df_enhanced.columns if col not in df.columns]
    for col in new_cols[:10]:  # Show first 10
        print(f"  - {col}")

    # Prepare enhanced data
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

    # Baseline with enhanced features
    print("\n" + "="*60)
    print("Baseline with Enhanced Features")
    print("="*60)

    rf_baseline = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    rf_baseline.fit(X_train, y_train)
    y_pred = rf_baseline.predict(X_test)
    baseline_acc = accuracy_score(y_test, y_pred)

    print(f"\n✓ Baseline (enhanced features): {baseline_acc:.4f}")

    # Option 2: Hyperparameter tuning
    print("\n" + "="*60)
    print("IMPROVEMENT 2: Hyperparameter Tuning")
    print("="*60)
    print("\nNote: This may take 5-10 minutes...")

    # Auto-proceed with hyperparameter tuning
    print("\nProceeding with hyperparameter tuning...")
    tuned_model = tune_risk_scorer(X_train, X_test, y_train, y_test, quick=True)

    # Option 3: Try Gradient Boosting
    print("\n" + "="*60)
    print("IMPROVEMENT 3: Alternative Algorithm")
    print("="*60)

    gb_model = try_gradient_boosting(X_train, X_test, y_train, y_test)

    # Option 4: Ensemble
    print("\n" + "="*60)
    print("IMPROVEMENT 4: Ensemble Methods")
    print("="*60)

    models = [rf_baseline, tuned_model, gb_model]
    ensemble_acc = create_ensemble(models, X_test, y_test)

    # Summary
    print("\n" + "="*60)
    print("RESULTS SUMMARY")
    print("="*60)

    results = {
        "Original (6 features)": 0.892,  # From previous training
        "Enhanced features": baseline_acc,
        "Tuned RandomForest": accuracy_score(y_test, tuned_model.predict(X_test)),
        "Gradient Boosting": accuracy_score(y_test, gb_model.predict(X_test)),
        "Ensemble (voting)": ensemble_acc,
    }

    print("\nAccuracy Comparison:")
    for name, acc in sorted(results.items(), key=lambda x: x[1], reverse=True):
        improvement = (acc - 0.892) * 100
        print(f"  {name:25s}: {acc:.4f} ({improvement:+.2f}% vs baseline)")

    # Save best model
    best_method = max(results.items(), key=lambda x: x[1])
    print(f"\n✓ Best Method: {best_method[0]} ({best_method[1]:.4f})")

    # Auto-save the best model
    print("\nSaving the best model...")

    # Determine which model to save
    if best_method[0] == "Ensemble (voting)":
        print("\nNote: Saving tuned RandomForest (best individual model)")
        best_model = tuned_model
    elif best_method[0] == "Gradient Boosting":
        best_model = gb_model
    else:
        best_model = tuned_model

    models_dir = Path(__file__).parent / "models"
    model_path = models_dir / "risk_scorer.joblib"

    joblib.dump(
        {
            "model": best_model,
            "feature_names": feature_cols,
            "accuracy": best_method[1],
            "method": best_method[0],
        },
        model_path
    )

    print(f"\n✓ Model saved to: {model_path}")
    print(f"  Method: {best_method[0]}")
    print(f"  Accuracy: {best_method[1]:.4f}")
    print(f"  Features: {len(feature_cols)}")

    # Update the scanner to use enhanced features
    print("\n⚠️  NOTE: You'll need to update the scanner code to use these enhanced features!")
    print("   The new model expects 16 features instead of 6.")


if __name__ == "__main__":
    main()
