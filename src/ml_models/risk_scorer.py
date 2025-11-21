"""ML-based risk scoring for vulnerabilities using RandomForest."""

from pathlib import Path
from typing import List, Dict, Any
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from ..utils.logger import get_logger

logger = get_logger(__name__)


class RiskScorer:
    """ML model to score vulnerability risk on 1-10 scale."""

    def __init__(self, model_path: str = "models/risk_scorer.joblib"):
        """
        Initialize risk scorer.

        Args:
            model_path: Path to save/load model
        """
        self.model_path = Path(model_path)
        self.model: RandomForestClassifier = None
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.feature_names = [
            "severity",
            "confidence",
            "vulnerability_type",
            "exploitability",
            "asset_value",
            "exposure",
        ]

        # Try to load existing model
        if self.model_path.exists():
            self.load_model()
        else:
            self._train_default_model()

    def score_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Score vulnerabilities using ML model.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Vulnerabilities with risk_score added
        """
        if not vulnerabilities:
            return []

        logger.info(f"Scoring {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            features = self._extract_features(vuln)
            risk_score = self._predict_risk(features)
            vuln["risk_score"] = risk_score

        return vulnerabilities

    def _extract_features(self, vuln: Dict[str, Any]) -> np.ndarray:
        """Extract features from vulnerability for ML model."""
        # Severity encoding
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        severity = severity_map.get(vuln.get("severity", "LOW").upper(), 1)

        # Confidence encoding
        confidence_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
        confidence = confidence_map.get(vuln.get("confidence", "MEDIUM").upper(), 2)

        # Vulnerability type encoding (hash to number)
        vuln_type = hash(vuln.get("type", "unknown")) % 100

        # Exploitability (based on vulnerability type and CWE)
        exploitability = self._calculate_exploitability(vuln)

        # Asset value (based on file location and type)
        asset_value = self._calculate_asset_value(vuln)

        # Exposure (based on scanner type and file location)
        exposure = self._calculate_exposure(vuln)

        return np.array(
            [severity, confidence, vuln_type, exploitability, asset_value, exposure]
        ).reshape(1, -1)

    def _calculate_exploitability(self, vuln: Dict[str, Any]) -> float:
        """Calculate exploitability score (0-10)."""
        high_exploitability_types = [
            "sql_injection",
            "command_injection",
            "code_injection",
            "eval",
            "deserialization",
            "xxe",
        ]

        vuln_type = vuln.get("type", "").lower()

        # Check CWE
        critical_cwes = ["CWE-78", "CWE-89", "CWE-95", "CWE-502", "CWE-611"]
        cwe = vuln.get("cwe", "")

        if cwe in critical_cwes:
            return 9.0

        if any(ht in vuln_type for ht in high_exploitability_types):
            return 8.0

        # Dependency vulnerabilities with CVE
        if vuln.get("vulnerability_id"):
            return 7.0

        # Default based on severity
        severity_exp = {"CRITICAL": 8.0, "HIGH": 6.0, "MEDIUM": 4.0, "LOW": 2.0}
        return severity_exp.get(vuln.get("severity", "LOW").upper(), 3.0)

    def _calculate_asset_value(self, vuln: Dict[str, Any]) -> float:
        """Calculate asset value score (0-10)."""
        file_path = vuln.get("file", "").lower()

        # High value assets
        if any(
            x in file_path
            for x in ["auth", "login", "password", "payment", "admin", "api"]
        ):
            return 9.0

        # Medium value assets
        if any(x in file_path for x in ["user", "account", "config", "settings"]):
            return 6.0

        # Container/infrastructure
        if any(x in file_path for x in ["dockerfile", "docker-compose", "kubernetes"]):
            return 7.0

        # Dependency files
        if "requirements" in file_path or "package" in file_path:
            return 5.0

        return 4.0

    def _calculate_exposure(self, vuln: Dict[str, Any]) -> float:
        """Calculate exposure score (0-10)."""
        scanner = vuln.get("scanner", "").lower()

        # Container vulnerabilities are often exposed
        if "container" in scanner:
            return 8.0

        # Infrastructure misconfigurations
        if "infrastructure" in scanner:
            return 7.0

        # Code vulnerabilities in web endpoints
        if "code" in scanner:
            file_path = vuln.get("file", "").lower()
            if any(x in file_path for x in ["api", "route", "view", "controller"]):
                return 8.0
            return 5.0

        # Dependencies
        if "dependency" in scanner:
            return 6.0

        return 5.0

    def _predict_risk(self, features: np.ndarray) -> float:
        """
        Predict risk score using ML model.

        Args:
            features: Feature array

        Returns:
            Risk score (1-10)
        """
        if self.model is None:
            # Fallback to simple weighted scoring
            weights = np.array([3.0, 1.5, 0.5, 2.5, 1.5, 1.0])
            score = np.sum(features[0] * weights) / np.sum(weights)
            return min(10.0, max(1.0, score))

        try:
            # Predict risk class
            risk_class = self.model.predict(features)[0]

            # Get probability for confidence
            probabilities = self.model.predict_proba(features)[0]

            # Convert class to score (1-10)
            # Classes are 0-9, representing scores 1-10
            risk_score = float(risk_class) + 1.0

            # Adjust based on confidence
            confidence = max(probabilities)
            if confidence < 0.5:
                # Less confident, regress to mean
                risk_score = risk_score * 0.7 + 5.0 * 0.3

            return min(10.0, max(1.0, risk_score))

        except Exception as e:
            logger.warning(f"Risk prediction failed: {e}, using fallback")
            weights = np.array([3.0, 1.5, 0.5, 2.5, 1.5, 1.0])
            score = np.sum(features[0] * weights) / np.sum(weights)
            return min(10.0, max(1.0, score))

    def _train_default_model(self):
        """Train default model with synthetic data."""
        logger.info("Training default risk scoring model")

        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 2000

        X_train = []
        y_train = []

        for _ in range(n_samples):
            # Generate features
            severity = np.random.randint(0, 5)
            confidence = np.random.randint(1, 4)
            vuln_type = np.random.randint(0, 100)
            exploitability = np.random.uniform(0, 10)
            asset_value = np.random.uniform(0, 10)
            exposure = np.random.uniform(0, 10)

            features = [
                severity,
                confidence,
                vuln_type,
                exploitability,
                asset_value,
                exposure,
            ]

            # Calculate risk score (0-9 for 10 classes)
            risk = (
                severity * 2.0
                + confidence * 0.5
                + exploitability * 0.3
                + asset_value * 0.15
                + exposure * 0.15
            )
            risk = min(9, max(0, int(risk)))

            X_train.append(features)
            y_train.append(risk)

        X_train = np.array(X_train)
        y_train = np.array(y_train)

        # Train RandomForest
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )

        self.model.fit(X_train, y_train)

        # Save model
        self.save_model()

        logger.info("Risk scoring model trained successfully")

    def save_model(self):
        """Save model to disk."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model": self.model,
            "label_encoders": self.label_encoders,
            "feature_names": self.feature_names,
        }

        joblib.dump(model_data, self.model_path)
        logger.info(f"Model saved to {self.model_path}")

    def load_model(self):
        """Load model from disk."""
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data["model"]
            self.label_encoders = model_data.get("label_encoders", {})
            self.feature_names = model_data.get("feature_names", self.feature_names)
            logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}, training new model")
            self._train_default_model()

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from model."""
        if self.model is None:
            return {}

        importance = self.model.feature_importances_
        return {
            name: float(imp)
            for name, imp in zip(self.feature_names, importance)
        }
