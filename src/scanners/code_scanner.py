"""Code scanner using Bandit for Python security analysis."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from .base_scanner import BaseScanner, Vulnerability


class CodeScanner(BaseScanner):
    """Scanner for Python source code vulnerabilities using Bandit."""

    SEVERITY_MAP = {
        "HIGH": "CRITICAL",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }

    def __init__(self):
        """Initialize code scanner."""
        super().__init__("CodeScanner")

    def scan(self, target_path: Path) -> List[Vulnerability]:
        """
        Scan Python code for security vulnerabilities.

        Args:
            target_path: Path to scan

        Returns:
            List of code vulnerabilities
        """
        self.logger.info(f"Scanning code at {target_path}")

        # Find all Python files
        python_files = self._find_python_files(target_path)

        if not python_files:
            self.logger.info("No Python files found")
            return []

        vulnerabilities = []

        # Run Bandit
        try:
            bandit_results = self._run_bandit(target_path)
            vulnerabilities.extend(self._parse_bandit_results(bandit_results))
        except Exception as e:
            self.logger.error(f"Bandit scan failed: {e}")

        self.logger.info(f"Found {len(vulnerabilities)} code vulnerabilities")
        return vulnerabilities

    def _find_python_files(self, target_path: Path) -> List[Path]:
        """Find all Python files in target path."""
        if target_path.is_file() and target_path.suffix == ".py":
            return [target_path]

        if target_path.is_dir():
            return list(target_path.rglob("*.py"))

        return []

    def _run_bandit(self, target_path: Path) -> dict:
        """
        Run Bandit security scanner.

        Args:
            target_path: Path to scan

        Returns:
            Bandit results as dictionary
        """
        cmd = [
            "bandit",
            "-r",
            str(target_path),
            "-f",
            "json",
            "--skip",
            "B404,B603",  # Skip common false positives
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Bandit returns non-zero exit code when vulnerabilities found
            if result.stdout:
                return json.loads(result.stdout)
            else:
                return {"results": []}

        except subprocess.TimeoutExpired:
            self.logger.error("Bandit scan timeout")
            return {"results": []}
        except json.JSONDecodeError:
            self.logger.error("Failed to parse Bandit output")
            return {"results": []}
        except FileNotFoundError:
            self.logger.error(
                "Bandit not found. Install with: pip install bandit"
            )
            return {"results": []}

    def _parse_bandit_results(self, bandit_output: dict) -> List[Vulnerability]:
        """
        Parse Bandit JSON output into Vulnerability objects.

        Args:
            bandit_output: Bandit JSON results

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        for result in bandit_output.get("results", []):
            severity = self.SEVERITY_MAP.get(
                result.get("issue_severity", "LOW"), "LOW"
            )

            vuln = Vulnerability(
                type=result.get("test_id", "unknown"),
                severity=severity,
                scanner=self.name,
                issue=result.get("issue_text", "Unknown issue"),
                description=self._get_issue_description(result.get("test_id", "")),
                file=result.get("filename"),
                line=result.get("line_number"),
                confidence=result.get("issue_confidence", "UNKNOWN"),
                cwe=self._get_cwe_for_test(result.get("test_id", "")),
                code_snippet=result.get("code", ""),
                metadata={
                    "test_name": result.get("test_name", ""),
                    "line_range": result.get("line_range", []),
                    "more_info": result.get("more_info", ""),
                },
            )

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_issue_description(self, test_id: str) -> str:
        """Get detailed description for Bandit test ID."""
        descriptions = {
            "B201": "Flask app run with debug=True detected",
            "B301": "Pickle usage detected - potential code execution risk",
            "B302": "marshal usage detected - potential code execution risk",
            "B303": "MD5 hash detected - weak cryptographic algorithm",
            "B304": "insecure cipher mode detected",
            "B305": "cipher usage without authentication detected",
            "B306": "mktemp usage detected - insecure temporary file",
            "B307": "eval() usage detected - arbitrary code execution risk",
            "B308": "mark_safe usage detected - XSS vulnerability risk",
            "B309": "HTTPSConnection without certificate validation",
            "B310": "URL open without timeout",
            "B311": "random usage for security/cryptography",
            "B312": "telnetlib usage - insecure protocol",
            "B313": "XML parsing vulnerable to XXE attacks",
            "B314": "XML parsing vulnerable to entity expansion",
            "B315": "XML parsing vulnerable to entity expansion",
            "B316": "XML parsing vulnerable to entity expansion",
            "B317": "XML parsing with lxml - potential XXE",
            "B318": "XML parsing with lxml - potential XXE",
            "B319": "XML parsing with lxml - potential XXE",
            "B320": "XML parsing with lxml - potential XXE",
            "B321": "FTP usage detected - insecure protocol",
            "B322": "Input validation bypass detected",
            "B323": "Unverified SSL/TLS context usage",
            "B324": "hashlib usage with insecure hash function",
            "B501": "Certificate validation disabled",
            "B502": "SSL/TLS version too old",
            "B503": "SSL/TLS insecure cipher detected",
            "B504": "SSL/TLS insecure protocol version",
            "B505": "Weak cryptographic key detected",
            "B506": "YAML load usage - code execution risk",
            "B507": "SSH with disabled host key verification",
            "B601": "Paramiko call with shell=True",
            "B602": "Shell injection via Popen with shell=True",
            "B605": "Shell injection via os.system",
            "B606": "Shell injection without shell=True",
            "B607": "Partial path in shell command",
            "B608": "SQL injection via string formatting",
            "B609": "Wildcard injection in shell command",
            "B610": "SQL injection via string concatenation",
            "B611": "SQL injection via Django extra/raw SQL",
            "B701": "jinja2 autoescape disabled - XSS risk",
            "B702": "Test fixture file usage",
        }

        return descriptions.get(test_id, "Security vulnerability detected")

    def _get_cwe_for_test(self, test_id: str) -> Optional[str]:
        """Map Bandit test ID to CWE."""
        cwe_map = {
            "B201": "CWE-489",
            "B301": "CWE-502",
            "B302": "CWE-502",
            "B303": "CWE-327",
            "B304": "CWE-327",
            "B305": "CWE-327",
            "B307": "CWE-95",
            "B308": "CWE-79",
            "B309": "CWE-295",
            "B311": "CWE-330",
            "B312": "CWE-319",
            "B313": "CWE-611",
            "B314": "CWE-776",
            "B501": "CWE-295",
            "B502": "CWE-327",
            "B506": "CWE-502",
            "B602": "CWE-78",
            "B608": "CWE-89",
            "B610": "CWE-89",
        }

        return cwe_map.get(test_id)
