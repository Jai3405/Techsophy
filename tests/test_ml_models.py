"""Tests for ML models."""

import pytest
import numpy as np
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.ml_models import RiskScorer, FalsePositiveFilter, ModelTrainer


class TestRiskScorer:
    """Test risk scoring model."""

    def test_risk_scorer_initialization(self):
        """Test model initializes."""
        scorer = RiskScorer()
        assert scorer.model is not None

    def test_score_vulnerabilities(self):
        """Test vulnerability scoring."""
        scorer = RiskScorer()

        vulns = [
            {
                "type": "sql_injection",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "file": "app.py",
                "scanner": "CodeScanner",
            }
        ]

        scored = scorer.score_vulnerabilities(vulns)
        assert len(scored) == 1
        assert "risk_score" in scored[0]
        assert 1.0 <= scored[0]["risk_score"] <= 10.0

    def test_extract_features(self):
        """Test feature extraction."""
        scorer = RiskScorer()
        vuln = {
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "type": "sql_injection",
        }

        features = scorer._extract_features(vuln)
        assert features.shape == (1, 6)

    def test_feature_importance(self):
        """Test feature importance retrieval."""
        scorer = RiskScorer()
        importance = scorer.get_feature_importance()
        assert isinstance(importance, dict)
        assert len(importance) > 0


class TestFalsePositiveFilter:
    """Test false positive filter."""

    def test_fp_filter_initialization(self):
        """Test model initializes."""
        filter = FalsePositiveFilter()
        assert filter.model is not None

    def test_filter_vulnerabilities(self):
        """Test FP filtering."""
        filter = FalsePositiveFilter()

        vulns = [
            {
                "type": "test_vulnerability",
                "confidence": "LOW",
                "file": "test_file.py",
                "code_snippet": "# Test code",
            }
        ]

        filtered = filter.filter_vulnerabilities(vulns, threshold=0.5)
        assert len(filtered) == 1
        assert "is_false_positive" in filtered[0]
        assert "fp_confidence" in filtered[0]


class TestModelTrainer:
    """Test model training utilities."""

    def test_generate_synthetic_data(self):
        """Test synthetic data generation."""
        X, y = ModelTrainer.generate_synthetic_vulnerability_data(n_samples=100)
        assert X.shape == (100, 6)
        assert y.shape == (100,)
        assert np.all(y >= 0) and np.all(y <= 9)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
