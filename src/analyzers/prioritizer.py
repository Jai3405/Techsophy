"""Multi-factor vulnerability prioritization engine."""

from typing import List, Dict, Any
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger(__name__)


class Prioritizer:
    """Prioritize vulnerabilities based on multiple risk factors."""

    def __init__(self):
        """Initialize prioritizer."""
        self.logger = get_logger(__name__)

        # Trending CVEs (would be fetched from threat intelligence in production)
        self.trending_cves = {
            "CVE-2018-7536",
            "CVE-2018-1000656",
            "CVE-2017-18342",
            "CVE-2019-16865",
        }

    def prioritize(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities using multi-factor analysis.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Vulnerabilities with priority_score and priority_level added
        """
        if not vulnerabilities:
            return []

        logger.info(f"Prioritizing {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            # Calculate composite priority score
            priority_score = self._calculate_priority_score(vuln)
            vuln["priority_score"] = priority_score

            # Assign priority level
            vuln["priority_level"] = self._assign_priority_level(priority_score)

        # Sort by priority score (descending)
        vulnerabilities.sort(key=lambda x: x.get("priority_score", 0), reverse=True)

        # Log statistics
        self._log_priority_stats(vulnerabilities)

        return vulnerabilities

    def _calculate_priority_score(self, vuln: Dict[str, Any]) -> float:
        """
        Calculate composite priority score.

        Factors:
        - Risk score from ML model (40%)
        - Business impact (25%)
        - Exploitability (20%)
        - Ease of remediation (10%, inverted)
        - Threat landscape relevance (5%)

        Returns:
            Priority score (0-100)
        """
        # Risk score (0-10 -> 0-40)
        risk_score = vuln.get("risk_score", 5.0)
        risk_component = (risk_score / 10.0) * 40.0

        # Business impact (0-10 -> 0-25)
        business_impact = vuln.get("impact", {}).get("impact_score", 5.0)
        impact_component = (business_impact / 10.0) * 25.0

        # Exploitability (0-10 -> 0-20)
        exploitability = self._calculate_exploitability(vuln)
        exploit_component = (exploitability / 10.0) * 20.0

        # Ease of remediation (inverted: easier = higher priority)
        # 0-10 -> 0-10, where 10 = easy, 0 = hard
        ease = self._calculate_ease_of_remediation(vuln)
        ease_component = (ease / 10.0) * 10.0

        # Threat landscape (0-10 -> 0-5)
        threat_relevance = self._calculate_threat_relevance(vuln)
        threat_component = (threat_relevance / 10.0) * 5.0

        total_score = (
            risk_component
            + impact_component
            + exploit_component
            + ease_component
            + threat_component
        )

        return min(100.0, max(0.0, total_score))

    def _calculate_exploitability(self, vuln: Dict[str, Any]) -> float:
        """Calculate exploitability score (0-10)."""
        # Critical exploit types
        high_exploit_types = [
            "sql_injection",
            "command_injection",
            "code_injection",
            "deserialization",
            "xxe",
        ]

        vuln_type = vuln.get("type", "").lower()

        # Critical CWEs
        critical_cwes = {
            "CWE-78": 10.0,  # Command injection
            "CWE-89": 10.0,  # SQL injection
            "CWE-95": 10.0,  # Code injection
            "CWE-502": 9.5,  # Deserialization
            "CWE-611": 9.0,  # XXE
            "CWE-798": 8.5,  # Hardcoded credentials
            "CWE-327": 7.0,  # Weak crypto
            "CWE-250": 8.0,  # Privilege escalation
        }

        cwe = vuln.get("cwe")
        if cwe in critical_cwes:
            return critical_cwes[cwe]

        # Check vulnerability type
        if any(het in vuln_type for het in high_exploit_types):
            return 9.0

        # Has public exploit (CVE with known exploits)
        if vuln.get("vulnerability_id") and "CVE" in vuln.get("vulnerability_id", ""):
            return 8.0

        # Severity-based fallback
        severity_map = {"CRITICAL": 8.5, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 3.0}
        return severity_map.get(vuln.get("severity", "LOW").upper(), 4.0)

    def _calculate_ease_of_remediation(self, vuln: Dict[str, Any]) -> float:
        """
        Calculate ease of remediation (0-10, higher = easier).

        Args:
            vuln: Vulnerability dictionary

        Returns:
            Ease score
        """
        remediation = vuln.get("remediation", {})
        complexity = remediation.get("fix_complexity", "medium").lower()

        # Complexity mapping
        complexity_map = {"easy": 9.0, "medium": 5.0, "hard": 2.0}

        base_score = complexity_map.get(complexity, 5.0)

        # Dependency updates are usually easy
        if vuln.get("type") == "vulnerable_dependency":
            if vuln.get("fixed_version"):
                return 9.0  # Just update the version
            return 6.0  # Need to find alternative

        # Container fixes are usually straightforward
        if vuln.get("scanner") == "ContainerScanner":
            return 7.0

        # Config changes are easy
        if vuln.get("scanner") == "InfrastructureScanner":
            return 8.0

        # Code changes vary
        if vuln.get("scanner") == "CodeScanner":
            # Hardcoded secrets are easy to fix
            if "secret" in vuln.get("type", "").lower():
                return 7.0
            # Logic changes are harder
            return 4.0

        return base_score

    def _calculate_threat_relevance(self, vuln: Dict[str, Any]) -> float:
        """Calculate current threat landscape relevance (0-10)."""
        # Check if CVE is trending
        vuln_id = vuln.get("vulnerability_id", "")

        if vuln_id in self.trending_cves:
            return 10.0

        # Recent CVEs are more relevant
        if "CVE" in vuln_id:
            try:
                # Extract year from CVE-YYYY-NNNNN
                year = int(vuln_id.split("-")[1])
                current_year = datetime.now().year

                age = current_year - year

                if age == 0:
                    return 9.0
                elif age == 1:
                    return 7.0
                elif age <= 3:
                    return 5.0
                else:
                    return 3.0
            except (IndexError, ValueError):
                pass

        # Container/infrastructure issues are currently high priority
        scanner = vuln.get("scanner", "")
        if "Container" in scanner or "Infrastructure" in scanner:
            return 7.0

        return 5.0

    def _assign_priority_level(self, priority_score: float) -> str:
        """
        Assign priority level based on score.

        Args:
            priority_score: Priority score (0-100)

        Returns:
            Priority level: CRITICAL, HIGH, MEDIUM, or LOW
        """
        if priority_score >= 75:
            return "CRITICAL"
        elif priority_score >= 50:
            return "HIGH"
        elif priority_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def _log_priority_stats(self, vulnerabilities: List[Dict[str, Any]]):
        """Log priority statistics."""
        priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for vuln in vulnerabilities:
            level = vuln.get("priority_level", "LOW")
            priority_counts[level] += 1

        logger.info("Priority Distribution:")
        logger.info(f"  CRITICAL: {priority_counts['CRITICAL']}")
        logger.info(f"  HIGH:     {priority_counts['HIGH']}")
        logger.info(f"  MEDIUM:   {priority_counts['MEDIUM']}")
        logger.info(f"  LOW:      {priority_counts['LOW']}")

    def get_critical_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get only critical priority vulnerabilities."""
        return [v for v in vulnerabilities if v.get("priority_level") == "CRITICAL"]

    def group_by_priority(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by priority level."""
        groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for vuln in vulnerabilities:
            level = vuln.get("priority_level", "LOW")
            groups[level].append(vuln)

        return groups
