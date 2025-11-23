"""ML-based false positive filter to reduce noise."""

from pathlib import Path
from typing import List, Dict, Any
import numpy as np
import joblib
from xgboost import XGBClassifier

from ..utils.logger import get_logger

logger = get_logger(__name__)


class FalsePositiveFilter:
    """ML model to identify and filter false positive vulnerabilities."""

    def __init__(self, model_path: str = "models/fp_filter.joblib"):
        """
        Initialize false positive filter.

        Args:
            model_path: Path to save/load model
        """
        self.model_path = Path(model_path)
        self.model: XGBClassifier = None
        self.feature_names = [
            "confidence",
            "code_context_score",
            "pattern_match_strength",
            "file_type_relevance",
            "historical_accuracy",
        ]

        # Try to load existing model
        if self.model_path.exists():
            self.load_model()
        else:
            self._train_default_model()

    def filter_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]], threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Filter out likely false positives.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            threshold: Confidence threshold for filtering (0-1)

        Returns:
            Filtered vulnerabilities with is_false_positive flag
        """
        if not vulnerabilities:
            return []

        logger.info(f"Filtering false positives from {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            features = self._extract_features(vuln)
            fp_probability = self._predict_false_positive(features)

            vuln["is_false_positive"] = fp_probability > threshold
            vuln["fp_confidence"] = float(fp_probability)

        # Log statistics
        fp_count = sum(1 for v in vulnerabilities if v.get("is_false_positive"))
        logger.info(f"Identified {fp_count} likely false positives")

        return vulnerabilities

    def _extract_features(self, vuln: Dict[str, Any]) -> np.ndarray:
        """Extract features for false positive detection."""
        # Confidence level
        confidence_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
        confidence = confidence_map.get(vuln.get("confidence", "MEDIUM").upper(), 2)

        # Code context score
        code_context_score = self._calculate_code_context_score(vuln)

        # Pattern match strength
        pattern_match = self._calculate_pattern_match_strength(vuln)

        # File type relevance
        file_relevance = self._calculate_file_relevance(vuln)

        # Historical accuracy (based on vulnerability type)
        historical_accuracy = self._get_historical_accuracy(vuln)

        return np.array(
            [
                confidence,
                code_context_score,
                pattern_match,
                file_relevance,
                historical_accuracy,
            ]
        ).reshape(1, -1)

    def _calculate_code_context_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate code context relevance score (0-10)."""
        code_snippet = vuln.get("code_snippet", "")

        if not code_snippet:
            return 5.0  # No context, assume medium

        # Check for common false positive patterns
        fp_patterns = [
            "# TODO",
            "# FIXME",
            "# Example",
            "test_",
            "mock_",
            "dummy_",
            "sample_",
        ]

        code_lower = code_snippet.lower()

        # If in test or example code, likely false positive
        if any(pattern.lower() in code_lower for pattern in fp_patterns):
            return 2.0

        # If in actual implementation
        if any(
            x in code_lower
            for x in ["def ", "class ", "import ", "from ", "return "]
        ):
            return 8.0

        return 5.0

    def _calculate_pattern_match_strength(self, vuln: Dict[str, Any]) -> float:
        """Calculate pattern match strength (0-10)."""
        # High confidence findings are usually strong matches
        confidence = vuln.get("confidence", "MEDIUM").upper()

        if confidence == "HIGH":
            return 8.0
        elif confidence == "MEDIUM":
            return 5.0
        else:
            return 3.0

    def _calculate_file_relevance(self, vuln: Dict[str, Any]) -> float:
        """Calculate file type relevance (0-10)."""
        file_path = vuln.get("file", "").lower()

        # Test files often have intentional vulnerabilities
        if any(x in file_path for x in ["test", "spec", "mock", "fixture"]):
            return 2.0

        # Documentation and examples
        if any(x in file_path for x in ["example", "sample", "demo", "doc"]):
            return 3.0

        # Build and config files
        if any(x in file_path for x in ["setup.py", "build", "dist"]):
            return 4.0

        # Actual source code
        if any(x in file_path for x in ["src/", "lib/", "app/", "main"]):
            return 9.0

        return 6.0

    def _get_historical_accuracy(self, vuln: Dict[str, Any]) -> float:
        """Get historical accuracy for this vulnerability type (0-10)."""
        # Based on known accuracy of different vulnerability types
        type_accuracy = {
            "sql_injection": 8.5,
            "command_injection": 8.0,
            "hardcoded_secret": 7.0,
            "weak_crypto": 9.0,
            "insecure_deserialization": 8.5,
            "xxe": 8.0,
            "missing_healthcheck": 9.5,  # Container findings are usually accurate
            "insecure_port_exposed": 9.0,
            "hardcoded_credential": 6.5,  # Sometimes placeholders
            "vulnerable_dependency": 9.5,  # CVE matches are very accurate
        }

        vuln_type = vuln.get("type", "unknown")
        return type_accuracy.get(vuln_type, 7.0)

    def _predict_false_positive(self, features: np.ndarray) -> float:
        """
        Predict probability of false positive.

        Args:
            features: Feature array

        Returns:
            Probability of false positive (0-1)
        """
        if self.model is None:
            # Fallback to rule-based scoring
            # Lower scores indicate likely false positives
            total_score = np.sum(features[0])
            max_score = len(features[0]) * 10.0

            # Invert: low score = high FP probability
            fp_prob = 1.0 - (total_score / max_score)
            return max(0.0, min(1.0, fp_prob))

        try:
            # Predict false positive probability
            probabilities = self.model.predict_proba(features)[0]

            # Class 1 is "false positive"
            fp_probability = probabilities[1] if len(probabilities) > 1 else 0.0

            return float(fp_probability)

        except Exception as e:
            logger.warning(f"FP prediction failed: {e}, using fallback")
            total_score = np.sum(features[0])
            max_score = len(features[0]) * 10.0
            fp_prob = 1.0 - (total_score / max_score)
            return max(0.0, min(1.0, fp_prob))

    def _train_default_model(self):
        """Train default model with synthetic data using XGBoost."""
        logger.info("Training XGBoost false positive filter")

        np.random.seed(42)
        n_samples = 2000

        X_train = []
        y_train = []

        for _ in range(n_samples):
            # Generate features with realistic distributions
            confidence = np.random.randint(1, 4)
            code_context = np.random.uniform(0, 10)
            pattern_match = np.random.uniform(0, 10)
            file_relevance = np.random.uniform(0, 10)
            historical_accuracy = np.random.uniform(5, 10)

            features = [
                confidence,
                code_context,
                pattern_match,
                file_relevance,
                historical_accuracy,
            ]

            # Calculate if false positive
            # Low values indicate false positive
            score = (
                confidence * 2.0
                + code_context * 1.5
                + pattern_match * 1.5
                + file_relevance * 1.0
                + historical_accuracy * 1.0
            )

            # If score is low, it's likely a false positive
            is_fp = 1 if score < 30 else 0

            X_train.append(features)
            y_train.append(is_fp)

        X_train = np.array(X_train)
        y_train = np.array(y_train)

        # Train XGBoost (optimized for precision - minimize false negatives)
        self.model = XGBClassifier(
            n_estimators=200,           # More trees for better accuracy
            max_depth=5,                # Controlled depth to prevent overfitting
            learning_rate=0.05,         # Conservative learning rate
            subsample=0.8,              # Row sampling for robustness
            colsample_bytree=0.8,       # Column sampling for feature diversity
            gamma=0.1,                  # Minimum loss reduction for split
            min_child_weight=3,         # Minimum instance weight in child
            reg_alpha=0.1,              # L1 regularization
            reg_lambda=1.0,             # L2 regularization
            scale_pos_weight=2.0,       # Handle class imbalance (penalize FP misclassification)
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False,
        )

        self.model.fit(X_train, y_train, verbose=False)

        # Save model
        self.save_model()

        logger.info("XGBoost false positive filter trained successfully")

    def save_model(self):
        """Save model to disk."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {"model": self.model, "feature_names": self.feature_names}

        joblib.dump(model_data, self.model_path)
        logger.info(f"Model saved to {self.model_path}")

    def load_model(self):
        """Load model from disk."""
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data["model"]
            self.feature_names = model_data.get("feature_names", self.feature_names)
            logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}, training new model")
            self._train_default_model()
