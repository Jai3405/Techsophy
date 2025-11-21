"""Dependency scanner using Safety to check for vulnerable packages."""

import json
import subprocess
from pathlib import Path
from typing import List

from .base_scanner import BaseScanner, Vulnerability


class DependencyScanner(BaseScanner):
    """Scanner for vulnerable dependencies using Safety."""

    def __init__(self):
        """Initialize dependency scanner."""
        super().__init__("DependencyScanner")

    def scan(self, target_path: Path) -> List[Vulnerability]:
        """
        Scan dependencies for known vulnerabilities.

        Args:
            target_path: Path to scan

        Returns:
            List of dependency vulnerabilities
        """
        self.logger.info(f"Scanning dependencies at {target_path}")

        vulnerabilities = []

        # Find dependency files
        dep_files = self._find_dependency_files(target_path)

        for dep_file in dep_files:
            self.logger.info(f"Scanning {dep_file}")
            vulns = self._scan_requirements_file(dep_file)
            vulnerabilities.extend(vulns)

        self.logger.info(f"Found {len(vulnerabilities)} dependency vulnerabilities")
        return vulnerabilities

    def _find_dependency_files(self, target_path: Path) -> List[Path]:
        """Find dependency specification files."""
        files = []

        if target_path.is_file():
            if target_path.name in [
                "requirements.txt",
                "Pipfile",
                "pyproject.toml",
            ]:
                files.append(target_path)
        else:
            # Search for requirements files
            files.extend(target_path.rglob("requirements*.txt"))
            files.extend(target_path.rglob("Pipfile"))
            files.extend(target_path.rglob("pyproject.toml"))

        return list(set(files))

    def _scan_requirements_file(self, req_file: Path) -> List[Vulnerability]:
        """
        Scan a requirements file using Safety.

        Args:
            req_file: Requirements file path

        Returns:
            List of vulnerabilities
        """
        try:
            # Run safety check
            cmd = ["safety", "check", "--file", str(req_file), "--json"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Parse Safety output
            return self._parse_safety_output(result.stdout, req_file)

        except subprocess.TimeoutExpired:
            self.logger.error(f"Safety scan timeout for {req_file}")
            return []
        except FileNotFoundError:
            self.logger.error("Safety not found. Install with: pip install safety")
            # Fallback to manual CVE check
            return self._manual_cve_check(req_file)
        except Exception as e:
            self.logger.error(f"Error scanning {req_file}: {e}")
            return self._manual_cve_check(req_file)

    def _parse_safety_output(
        self, safety_output: str, req_file: Path
    ) -> List[Vulnerability]:
        """
        Parse Safety JSON output.

        Args:
            safety_output: Safety JSON output
            req_file: Source requirements file

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        try:
            if not safety_output.strip():
                return []

            data = json.loads(safety_output)

            for vuln_data in data:
                # Safety output format varies, handle both formats
                if isinstance(vuln_data, list):
                    vuln_data = {
                        "package": vuln_data[0] if len(vuln_data) > 0 else "unknown",
                        "affected": vuln_data[1] if len(vuln_data) > 1 else "unknown",
                        "installed": vuln_data[2] if len(vuln_data) > 2 else "unknown",
                        "description": vuln_data[3] if len(vuln_data) > 3 else "",
                        "id": vuln_data[4] if len(vuln_data) > 4 else "",
                    }

                severity = self._determine_severity(vuln_data)

                vuln = Vulnerability(
                    type="vulnerable_dependency",
                    severity=severity,
                    scanner=self.name,
                    issue=f"Vulnerable package: {vuln_data.get('package', 'unknown')}",
                    description=vuln_data.get("description", ""),
                    file=str(req_file),
                    package=vuln_data.get("package"),
                    version=vuln_data.get("installed", vuln_data.get("affected")),
                    vulnerability_id=vuln_data.get("id", vuln_data.get("vulnerability_id")),
                    fixed_version=self._extract_fixed_version(vuln_data),
                    metadata={
                        "cve": vuln_data.get("CVE"),
                        "affected_versions": vuln_data.get("affected"),
                    },
                )

                vulnerabilities.append(vuln)

        except json.JSONDecodeError:
            self.logger.warning("Could not parse Safety output as JSON")
        except Exception as e:
            self.logger.error(f"Error parsing Safety output: {e}")

        return vulnerabilities

    def _manual_cve_check(self, req_file: Path) -> List[Vulnerability]:
        """
        Manual CVE check for known vulnerable packages (fallback).

        Args:
            req_file: Requirements file

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        # Known vulnerable packages database
        known_vulns = {
            "django": {
                "2.0.0": ("CVE-2018-7536", "HIGH", "2.0.13"),
                "2.0.1": ("CVE-2018-7536", "HIGH", "2.0.13"),
                "2.1.0": ("CVE-2019-3498", "MEDIUM", "2.1.15"),
            },
            "flask": {
                "0.12.0": ("CVE-2018-1000656", "HIGH", "0.12.3"),
                "0.12.1": ("CVE-2018-1000656", "HIGH", "0.12.3"),
                "0.12.2": ("CVE-2018-1000656", "HIGH", "0.12.3"),
            },
            "requests": {
                "2.6.0": ("CVE-2018-18074", "MEDIUM", "2.20.0"),
                "2.19.0": ("CVE-2018-18074", "MEDIUM", "2.20.0"),
            },
            "pyyaml": {
                "3.12": ("CVE-2017-18342", "CRITICAL", "5.4"),
                "3.13": ("CVE-2017-18342", "CRITICAL", "5.4"),
                "5.3": ("CVE-2020-1747", "HIGH", "5.4"),
            },
            "pillow": {
                "5.0.0": ("CVE-2019-16865", "HIGH", "6.2.2"),
                "6.0.0": ("CVE-2019-16865", "HIGH", "6.2.2"),
            },
            "urllib3": {
                "1.24.0": ("CVE-2019-11324", "MEDIUM", "1.24.2"),
            },
            "jinja2": {
                "2.10.0": ("CVE-2019-10906", "HIGH", "2.10.1"),
            },
        }

        try:
            content = self._read_file_safely(req_file)
            if not content:
                return []

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse requirement
                parts = line.replace("==", " ").replace(">=", " ").replace("<=", " ").split()
                if len(parts) < 2:
                    continue

                package = parts[0].lower()
                version = parts[1]

                if package in known_vulns and version in known_vulns[package]:
                    cve, severity, fixed = known_vulns[package][version]

                    vuln = Vulnerability(
                        type="vulnerable_dependency",
                        severity=severity,
                        scanner=self.name,
                        issue=f"Vulnerable package: {package}",
                        description=f"Package {package} version {version} has known security vulnerability",
                        file=str(req_file),
                        package=package,
                        version=version,
                        vulnerability_id=cve,
                        fixed_version=fixed,
                    )

                    vulnerabilities.append(vuln)

        except Exception as e:
            self.logger.error(f"Error in manual CVE check: {e}")

        return vulnerabilities

    def _determine_severity(self, vuln_data: dict) -> str:
        """Determine severity from vulnerability data."""
        description = vuln_data.get("description", "").lower()

        if any(
            word in description
            for word in ["critical", "remote code execution", "arbitrary code"]
        ):
            return "CRITICAL"
        elif any(word in description for word in ["high", "privilege escalation"]):
            return "HIGH"
        elif any(word in description for word in ["medium", "denial of service"]):
            return "MEDIUM"
        else:
            return "LOW"

    def _extract_fixed_version(self, vuln_data: dict) -> str:
        """Extract fixed version from vulnerability data."""
        description = vuln_data.get("description", "")

        # Try to find version in description
        import re

        match = re.search(r"upgrade to (\d+\.\d+\.?\d*)", description, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r"fixed in (\d+\.\d+\.?\d*)", description, re.IGNORECASE)
        if match:
            return match.group(1)

        return "latest"
