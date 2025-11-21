"""Tests for scanner modules."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.scanners import (
    CodeScanner,
    DependencyScanner,
    ContainerScanner,
    InfrastructureScanner,
    Vulnerability,
)


class TestCodeScanner:
    """Test code scanner functionality."""

    def test_code_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = CodeScanner()
        assert scanner.name == "CodeScanner"

    def test_vulnerability_creation(self):
        """Test vulnerability object creation."""
        vuln = Vulnerability(
            type="sql_injection",
            severity="HIGH",
            scanner="CodeScanner",
            issue="SQL injection detected",
            description="Test vulnerability",
        )
        assert vuln.type == "sql_injection"
        assert vuln.severity == "HIGH"

    def test_vulnerability_to_dict(self):
        """Test vulnerability serialization."""
        vuln = Vulnerability(
            type="test",
            severity="MEDIUM",
            scanner="Test",
            issue="Test issue",
            description="Test description",
        )
        d = vuln.to_dict()
        assert isinstance(d, dict)
        assert d["type"] == "test"


class TestDependencyScanner:
    """Test dependency scanner functionality."""

    def test_dependency_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = DependencyScanner()
        assert scanner.name == "DependencyScanner"

    def test_manual_cve_check(self):
        """Test manual CVE detection."""
        scanner = DependencyScanner()

        # Create test requirements file
        test_file = Path("/tmp/test_requirements.txt")
        test_file.write_text("django==2.0.0\nflask==0.12.0\n")

        try:
            vulns = scanner._manual_cve_check(test_file)
            assert len(vulns) > 0
            assert any(v.package == "django" for v in vulns)
        finally:
            test_file.unlink()


class TestContainerScanner:
    """Test container scanner functionality."""

    def test_container_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = ContainerScanner()
        assert scanner.name == "ContainerScanner"

    def test_extract_ports(self):
        """Test port extraction from EXPOSE."""
        scanner = ContainerScanner()
        ports = scanner._extract_ports("EXPOSE 8080 9090")
        assert 8080 in ports
        assert 9090 in ports

    def test_contains_secret(self):
        """Test secret detection."""
        scanner = ContainerScanner()
        assert scanner._contains_secret("ENV API_KEY=secret123")
        assert not scanner._contains_secret("ENV PORT=8080")


class TestInfrastructureScanner:
    """Test infrastructure scanner functionality."""

    def test_infrastructure_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = InfrastructureScanner()
        assert scanner.name == "InfrastructureScanner"

    def test_is_placeholder(self):
        """Test placeholder detection."""
        scanner = InfrastructureScanner()
        assert scanner._is_placeholder("change_me")
        assert scanner._is_placeholder("YOUR_API_KEY")
        assert not scanner._is_placeholder("actual_secret_123")

    def test_flatten_dict(self):
        """Test dictionary flattening."""
        scanner = InfrastructureScanner()
        nested = {"a": {"b": {"c": 1}}}
        flat = scanner._flatten_dict(nested)
        assert "a.b.c" in flat
        assert flat["a.b.c"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
