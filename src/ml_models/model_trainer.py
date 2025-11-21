"""Utilities for training and evaluating ML models."""

from typing import Tuple, Dict, Any
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ModelTrainer:
    """Utilities for training and evaluating models."""

    @staticmethod
    def evaluate_model(
        model: Any, X_test: np.ndarray, y_test: np.ndarray
    ) -> Dict[str, Any]:
        """
        Evaluate model performance.

        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels

        Returns:
            Dictionary of evaluation metrics
        """
        y_pred = model.predict(X_test)

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="weighted"),
            "recall": recall_score(y_test, y_pred, average="weighted"),
            "f1": f1_score(y_test, y_pred, average="weighted"),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }

        logger.info(f"Model Evaluation Metrics:")
        logger.info(f"  Accuracy:  {metrics['accuracy']:.3f}")
        logger.info(f"  Precision: {metrics['precision']:.3f}")
        logger.info(f"  Recall:    {metrics['recall']:.3f}")
        logger.info(f"  F1 Score:  {metrics['f1']:.3f}")

        return metrics

    @staticmethod
    def cross_validate(
        model: Any, X: np.ndarray, y: np.ndarray, cv: int = 5
    ) -> Dict[str, float]:
        """
        Perform cross-validation.

        Args:
            model: Model to validate
            X: Features
            y: Labels
            cv: Number of folds

        Returns:
            Cross-validation scores
        """
        scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy")

        results = {
            "mean_score": float(scores.mean()),
            "std_score": float(scores.std()),
            "scores": scores.tolist(),
        }

        logger.info(f"Cross-validation: {results['mean_score']:.3f} (+/- {results['std_score']:.3f})")

        return results

    @staticmethod
    def generate_synthetic_vulnerability_data(
        n_samples: int = 2000,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic vulnerability data for training.

        Args:
            n_samples: Number of samples to generate

        Returns:
            Tuple of (features, labels)
        """
        np.random.seed(42)

        X = []
        y = []

        for _ in range(n_samples):
            # Realistic feature distributions
            severity = np.random.choice([0, 1, 2, 3, 4], p=[0.1, 0.2, 0.3, 0.25, 0.15])
            confidence = np.random.choice([1, 2, 3], p=[0.15, 0.5, 0.35])
            vuln_type = np.random.randint(0, 100)
            exploitability = np.random.beta(2, 5) * 10  # Skewed toward lower values
            asset_value = np.random.beta(3, 3) * 10  # More uniform
            exposure = np.random.beta(2, 5) * 10

            features = [
                severity,
                confidence,
                vuln_type,
                exploitability,
                asset_value,
                exposure,
            ]

            # Calculate risk score
            risk = (
                severity * 2.0
                + confidence * 0.5
                + exploitability * 0.3
                + asset_value * 0.15
                + exposure * 0.15
            )
            risk = min(9, max(0, int(risk)))

            X.append(features)
            y.append(risk)

        return np.array(X), np.array(y)
