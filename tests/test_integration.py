"""Integration tests for complete workflow."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.main import SecurityScanner


class TestIntegration:
    """Integration tests for complete scan workflow."""

    def test_full_scan_workflow(self):
        """Test complete scan on test repository."""
        test_repo = Path(__file__).parent.parent / "test_repo"

        if not test_repo.exists():
            pytest.skip("Test repository not found")

        scanner = SecurityScanner(
            repo_path=str(test_repo),
            scan_types=["code", "dependency", "container", "infrastructure"],
        )

        results = scanner.scan()

        assert "vulnerabilities" in results
        assert "summary" in results
        assert "metadata" in results
        assert results["summary"]["total"] > 0

    def test_scanner_with_threshold(self):
        """Test scanning with severity threshold."""
        test_repo = Path(__file__).parent.parent / "test_repo"

        if not test_repo.exists():
            pytest.skip("Test repository not found")

        scanner = SecurityScanner(
            repo_path=str(test_repo),
            severity_threshold="HIGH",
        )

        results = scanner.scan()

        # All results should be HIGH or CRITICAL
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "").upper()
            assert severity in ["HIGH", "CRITICAL"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
