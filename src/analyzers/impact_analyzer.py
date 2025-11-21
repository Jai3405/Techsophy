"""Business impact analyzer for vulnerabilities."""

from typing import List, Dict, Any

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ImpactAnalyzer:
    """Analyze business impact of security vulnerabilities."""

    def __init__(self):
        """Initialize impact analyzer."""
        self.logger = get_logger(__name__)

    def analyze_impact(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze business impact for all vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Vulnerabilities with impact analysis added
        """
        logger.info(f"Analyzing business impact for {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            impact = self._calculate_impact(vuln)
            vuln["impact"] = impact

        return vulnerabilities

    def _calculate_impact(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate business impact for a vulnerability.

        Returns:
            Impact analysis dictionary
        """
        # Calculate individual impact dimensions
        data_exposure_risk = self._assess_data_exposure_risk(vuln)
        availability_impact = self._assess_availability_impact(vuln)
        compliance_impact = self._assess_compliance_impact(vuln)
        reputation_impact = self._assess_reputation_impact(vuln)

        # Calculate composite impact score (0-10)
        impact_score = (
            data_exposure_risk * 0.35
            + availability_impact * 0.25
            + compliance_impact * 0.25
            + reputation_impact * 0.15
        )

        return {
            "impact_score": round(impact_score, 2),
            "data_exposure_risk": round(data_exposure_risk, 2),
            "availability_impact": round(availability_impact, 2),
            "compliance_impact": round(compliance_impact, 2),
            "reputation_impact": round(reputation_impact, 2),
            "reasoning": self._generate_impact_reasoning(
                vuln,
                data_exposure_risk,
                availability_impact,
                compliance_impact,
                reputation_impact,
            ),
        }

    def _assess_data_exposure_risk(self, vuln: Dict[str, Any]) -> float:
        """Assess risk of data exposure (0-10)."""
        high_risk_types = [
            "sql_injection",
            "command_injection",
            "hardcoded_secret",
            "hardcoded_credential",
            "insecure_deserialization",
            "xxe",
        ]

        vuln_type = vuln.get("type", "").lower()

        # Critical data exposure vulnerabilities
        if any(hrt in vuln_type for hrt in high_risk_types):
            return 9.5

        # Check file context
        file_path = vuln.get("file", "").lower()

        if any(
            x in file_path
            for x in ["auth", "login", "password", "payment", "user", "customer"]
        ):
            return 8.5

        # Database-related
        if any(x in file_path for x in ["database", "db", "model", "schema"]):
            return 8.0

        # API endpoints
        if any(x in file_path for x in ["api", "endpoint", "route"]):
            return 7.5

        # Configuration exposure
        if "Infrastructure" in vuln.get("scanner", ""):
            return 7.0

        # Severity-based fallback
        severity_map = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 3.0}
        return severity_map.get(vuln.get("severity", "MEDIUM").upper(), 5.0)

    def _assess_availability_impact(self, vuln: Dict[str, Any]) -> float:
        """Assess impact on system availability (0-10)."""
        dos_types = [
            "denial_of_service",
            "resource_exhaustion",
            "missing_healthcheck",
        ]

        vuln_type = vuln.get("type", "").lower()

        # Direct DoS vulnerabilities
        if any(dos in vuln_type for dos in dos_types):
            return 8.5

        # Container/infrastructure issues can affect availability
        scanner = vuln.get("scanner", "")

        if scanner == "ContainerScanner":
            if "healthcheck" in vuln_type:
                return 7.0
            return 5.5

        if scanner == "InfrastructureScanner":
            return 6.0

        # Code vulnerabilities that could cause crashes
        if scanner == "CodeScanner":
            if vuln.get("severity") == "CRITICAL":
                return 6.5
            return 4.0

        # Dependencies
        if scanner == "DependencyScanner":
            return 5.0

        return 4.0

    def _assess_compliance_impact(self, vuln: Dict[str, Any]) -> float:
        """Assess compliance violation risk (0-10)."""
        compliance_violations = {
            "hardcoded_secret": {
                "score": 9.5,
                "regulations": ["GDPR", "PCI-DSS", "HIPAA"],
            },
            "hardcoded_credential": {
                "score": 9.5,
                "regulations": ["GDPR", "PCI-DSS", "SOC 2"],
            },
            "weak_crypto": {
                "score": 8.5,
                "regulations": ["PCI-DSS", "HIPAA", "FIPS 140-2"],
            },
            "missing_encryption": {
                "score": 8.5,
                "regulations": ["GDPR", "HIPAA"],
            },
            "sql_injection": {
                "score": 9.0,
                "regulations": ["PCI-DSS", "GDPR"],
            },
            "insecure_configuration": {
                "score": 7.0,
                "regulations": ["SOC 2", "ISO 27001"],
            },
        }

        vuln_type = vuln.get("type", "").lower()

        # Check for direct compliance violations
        for violation_type, info in compliance_violations.items():
            if violation_type in vuln_type:
                return info["score"]

        # CWE-based assessment
        high_compliance_cwes = {
            "CWE-798": 9.5,  # Hardcoded credentials
            "CWE-327": 8.5,  # Weak crypto
            "CWE-89": 9.0,  # SQL injection
            "CWE-311": 8.5,  # Missing encryption
        }

        cwe = vuln.get("cwe")
        if cwe in high_compliance_cwes:
            return high_compliance_cwes[cwe]

        # Severity-based fallback
        if vuln.get("severity") == "CRITICAL":
            return 7.0

        return 5.0

    def _assess_reputation_impact(self, vuln: Dict[str, Any]) -> float:
        """Assess potential reputation damage (0-10)."""
        # Public-facing vulnerabilities have higher reputation impact
        file_path = vuln.get("file", "").lower()

        if any(x in file_path for x in ["api", "public", "web", "frontend"]):
            base_score = 7.5
        else:
            base_score = 5.0

        # Data breach potential increases reputation risk
        high_exposure_types = [
            "sql_injection",
            "hardcoded_credential",
            "data_leak",
        ]

        vuln_type = vuln.get("type", "").lower()

        if any(het in vuln_type for het in high_exposure_types):
            base_score += 2.0

        # Critical severity increases reputation risk
        if vuln.get("severity") == "CRITICAL":
            base_score += 1.5

        return min(10.0, base_score)

    def _generate_impact_reasoning(
        self,
        vuln: Dict[str, Any],
        data_exposure: float,
        availability: float,
        compliance: float,
        reputation: float,
    ) -> str:
        """Generate human-readable impact reasoning."""
        reasons = []

        # Data exposure
        if data_exposure >= 8.0:
            reasons.append(
                "High risk of sensitive data exposure that could lead to data breach"
            )
        elif data_exposure >= 6.0:
            reasons.append("Moderate risk of unauthorized data access")

        # Availability
        if availability >= 8.0:
            reasons.append("Could severely impact system availability and uptime")
        elif availability >= 6.0:
            reasons.append("May affect service reliability")

        # Compliance
        if compliance >= 8.0:
            reasons.append(
                "Likely violation of compliance requirements (GDPR, PCI-DSS, HIPAA)"
            )
        elif compliance >= 6.0:
            reasons.append("Potential compliance concerns")

        # Reputation
        if reputation >= 7.0:
            reasons.append("Significant reputation damage risk if exploited")

        if not reasons:
            reasons.append("Standard security risk requiring remediation")

        return "; ".join(reasons)
