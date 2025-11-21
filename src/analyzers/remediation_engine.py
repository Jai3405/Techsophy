"""Remediation engine with fix suggestions and patterns."""

from typing import List, Dict, Any, Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


class RemediationEngine:
    """Engine to provide remediation guidance for vulnerabilities."""

    def __init__(self):
        """Initialize remediation engine with fix database."""
        self.logger = get_logger(__name__)
        self.remediation_db = self._build_remediation_database()

    def add_remediation(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Add remediation guidance to vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Vulnerabilities with remediation added
        """
        logger.info(f"Adding remediation guidance to {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            remediation = self._get_remediation(vuln)
            vuln["remediation"] = remediation

        return vulnerabilities

    def _get_remediation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation for a specific vulnerability."""
        vuln_type = vuln.get("type", "").lower()
        scanner = vuln.get("scanner", "")

        # Try exact match first
        if vuln_type in self.remediation_db:
            return self.remediation_db[vuln_type].copy()

        # Try partial match
        for key in self.remediation_db:
            if key in vuln_type or vuln_type in key:
                return self.remediation_db[key].copy()

        # Scanner-specific defaults
        if scanner == "DependencyScanner":
            return self._get_dependency_remediation(vuln)
        elif scanner == "ContainerScanner":
            return self._get_container_remediation(vuln)
        elif scanner == "InfrastructureScanner":
            return self._get_infrastructure_remediation(vuln)
        elif scanner == "CodeScanner":
            return self._get_code_remediation(vuln)

        # Generic remediation
        return {
            "description": "Review and fix the security issue",
            "fix_complexity": "medium",
            "steps": ["Investigate the vulnerability", "Apply appropriate fix"],
            "references": ["https://owasp.org/"],
        }

    def _build_remediation_database(self) -> Dict[str, Dict[str, Any]]:
        """Build database of remediation patterns."""
        return {
            # SQL Injection
            "b608": {
                "description": "Use parameterized queries instead of string formatting",
                "fix_complexity": "medium",
                "steps": [
                    "Replace string concatenation/formatting with parameterized queries",
                    "Use ORM methods or prepared statements",
                    "Validate and sanitize all user inputs",
                ],
                "code_example_before": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "code_example_after": "query = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_id,))",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            },
            "b610": {
                "description": "Use parameterized queries instead of string concatenation",
                "fix_complexity": "medium",
                "steps": [
                    "Replace string concatenation with parameterized queries",
                    "Use prepared statements",
                    "Implement input validation",
                ],
                "code_example_before": 'query = "SELECT * FROM users WHERE name = \'" + username + "\'"',
                "code_example_after": "query = \"SELECT * FROM users WHERE name = %s\"\ncursor.execute(query, (username,))",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
            },
            # Command Injection
            "b602": {
                "description": "Avoid shell=True and use subprocess with list arguments",
                "fix_complexity": "easy",
                "steps": [
                    "Remove shell=True from subprocess calls",
                    "Pass command as list of arguments",
                    "Validate and sanitize inputs",
                    "Use absolute paths for commands",
                ],
                "code_example_before": "subprocess.run(f'ls {user_input}', shell=True)",
                "code_example_after": "subprocess.run(['ls', user_input], shell=False)",
                "references": [
                    "https://owasp.org/www-community/attacks/Command_Injection",
                ],
            },
            # Hardcoded Secrets
            "hardcoded_secret": {
                "description": "Move secrets to environment variables or secrets manager",
                "fix_complexity": "easy",
                "steps": [
                    "Remove hardcoded credentials from code",
                    "Store secrets in environment variables",
                    "Use secrets management service (AWS Secrets Manager, HashiCorp Vault)",
                    "Add secrets to .gitignore",
                    "Rotate compromised credentials",
                ],
                "code_example_before": "API_KEY = 'sk-1234567890abcdef'",
                "code_example_after": "import os\nAPI_KEY = os.environ.get('API_KEY')",
                "references": [
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                ],
            },
            "hardcoded_credential": {
                "description": "Use secrets management instead of hardcoding credentials",
                "fix_complexity": "easy",
                "steps": [
                    "Remove credentials from configuration files",
                    "Use environment-specific secret stores",
                    "Implement proper secrets rotation",
                    "Use Kubernetes secrets or cloud secret managers",
                ],
                "references": [
                    "https://kubernetes.io/docs/concepts/configuration/secret/",
                ],
            },
            # Weak Crypto
            "b303": {
                "description": "Replace MD5 with SHA-256 or better",
                "fix_complexity": "easy",
                "steps": [
                    "Replace MD5 with SHA-256, SHA-3, or bcrypt for passwords",
                    "Use appropriate algorithm for use case",
                    "Add salt for password hashing",
                ],
                "code_example_before": "import hashlib\nhash = hashlib.md5(password.encode()).hexdigest()",
                "code_example_after": "import hashlib\nimport os\nsalt = os.urandom(32)\nhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)",
                "references": [
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                ],
            },
            # Deserialization
            "b301": {
                "description": "Avoid pickle for untrusted data, use JSON instead",
                "fix_complexity": "medium",
                "steps": [
                    "Replace pickle with JSON for data serialization",
                    "If pickle is necessary, validate source and use HMAC",
                    "Implement allowlist for deserializable classes",
                ],
                "code_example_before": "import pickle\ndata = pickle.loads(user_input)",
                "code_example_after": "import json\ndata = json.loads(user_input)",
                "references": [
                    "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                ],
            },
            # eval() usage
            "b307": {
                "description": "Remove eval() and use safe alternatives",
                "fix_complexity": "medium",
                "steps": [
                    "Remove eval() usage",
                    "Use ast.literal_eval() for simple literals",
                    "Use json.loads() for JSON data",
                    "Implement proper parsing for expressions",
                ],
                "code_example_before": "result = eval(user_expression)",
                "code_example_after": "import ast\nresult = ast.literal_eval(user_expression)  # Only for literals",
                "references": [
                    "https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html",
                ],
            },
            # XXE
            "b313": {
                "description": "Disable XML external entity processing",
                "fix_complexity": "easy",
                "steps": [
                    "Use defusedxml library instead of standard XML libraries",
                    "Disable DTD processing",
                    "Disable external entity resolution",
                ],
                "code_example_before": "import xml.etree.ElementTree as ET\ntree = ET.parse(xml_file)",
                "code_example_after": "import defusedxml.ElementTree as ET\ntree = ET.parse(xml_file)",
                "references": [
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                ],
            },
            # Vulnerable Dependencies
            "vulnerable_dependency": {
                "description": "Update package to fixed version",
                "fix_complexity": "easy",
                "steps": [
                    "Update package to secure version",
                    "Review breaking changes in changelog",
                    "Test application after update",
                    "Run security scan again",
                ],
                "references": [
                    "https://owasp.org/www-project-dependency-check/",
                ],
            },
            # Container Security
            "insecure_base_image": {
                "description": "Pin base image to specific version",
                "fix_complexity": "easy",
                "steps": [
                    "Replace 'latest' tag with specific version",
                    "Use official images from trusted registries",
                    "Regularly update to patched versions",
                ],
                "code_example_before": "FROM python:latest",
                "code_example_after": "FROM python:3.11-slim",
                "references": [
                    "https://docs.docker.com/develop/dev-best-practices/",
                ],
            },
            "running_as_root": {
                "description": "Run container as non-root user",
                "fix_complexity": "easy",
                "steps": [
                    "Create non-root user in Dockerfile",
                    "Switch to that user with USER directive",
                    "Adjust file permissions as needed",
                ],
                "code_example_before": "# No USER directive",
                "code_example_after": "RUN adduser -D appuser\nUSER appuser",
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                ],
            },
            "missing_user_directive": {
                "description": "Add USER directive with non-root user",
                "fix_complexity": "easy",
                "steps": [
                    "Create dedicated user in Dockerfile",
                    "Add USER directive before CMD/ENTRYPOINT",
                    "Verify application works with non-root user",
                ],
                "code_example_after": "RUN useradd -m -s /bin/bash appuser\nUSER appuser",
                "references": [
                    "https://docs.docker.com/engine/reference/builder/#user",
                ],
            },
            "missing_healthcheck": {
                "description": "Add HEALTHCHECK to Dockerfile",
                "fix_complexity": "easy",
                "steps": [
                    "Add HEALTHCHECK directive",
                    "Implement health endpoint in application",
                    "Test healthcheck works correctly",
                ],
                "code_example_after": "HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n  CMD curl -f http://localhost:8000/health || exit 1",
                "references": [
                    "https://docs.docker.com/engine/reference/builder/#healthcheck",
                ],
            },
            "insecure_port_exposed": {
                "description": "Remove exposure of insecure ports",
                "fix_complexity": "easy",
                "steps": [
                    "Remove EXPOSE directive for sensitive ports",
                    "Use VPN or SSH tunneling if access needed",
                    "Implement proper authentication",
                ],
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                ],
            },
            # Infrastructure
            "insecure_configuration": {
                "description": "Fix insecure configuration setting",
                "fix_complexity": "easy",
                "steps": [
                    "Review and update configuration",
                    "Use environment-specific configs",
                    "Enable security features",
                ],
                "references": [
                    "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                ],
            },
            "privileged_container": {
                "description": "Remove privileged mode unless absolutely necessary",
                "fix_complexity": "medium",
                "steps": [
                    "Remove privileged: true",
                    "Use specific capabilities instead",
                    "Review security context requirements",
                ],
                "references": [
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                ],
            },
        }

    def _get_dependency_remediation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation for dependency vulnerabilities."""
        fixed_version = vuln.get("fixed_version", "latest")
        package = vuln.get("package", "unknown")

        return {
            "description": f"Update {package} to version {fixed_version} or later",
            "fix_complexity": "easy",
            "steps": [
                f"Update {package} in requirements.txt",
                f"Change version to: {package}>={fixed_version}",
                "Run pip install -r requirements.txt",
                "Test application functionality",
            ],
            "references": [
                "https://pypi.org/",
                f"https://pypi.org/project/{package}/",
            ],
        }

    def _get_container_remediation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation for container vulnerabilities."""
        return {
            "description": "Fix Dockerfile security issue",
            "fix_complexity": "easy",
            "steps": [
                "Update Dockerfile with security best practices",
                "Rebuild container image",
                "Test container functionality",
            ],
            "references": [
                "https://docs.docker.com/develop/security-best-practices/",
            ],
        }

    def _get_infrastructure_remediation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation for infrastructure vulnerabilities."""
        return {
            "description": "Fix configuration security issue",
            "fix_complexity": "easy",
            "steps": [
                "Update configuration file",
                "Use secrets management for sensitive values",
                "Apply changes to environment",
            ],
            "references": [
                "https://kubernetes.io/docs/concepts/configuration/",
            ],
        }

    def _get_code_remediation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation for code vulnerabilities."""
        return {
            "description": "Fix code security vulnerability",
            "fix_complexity": "medium",
            "steps": [
                "Review vulnerable code",
                "Apply secure coding practices",
                "Test fix thoroughly",
                "Consider adding security tests",
            ],
            "references": [
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/",
            ],
        }
