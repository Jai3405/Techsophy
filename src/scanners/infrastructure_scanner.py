"""Infrastructure scanner for YAML/JSON configuration files."""

import re
import json
from pathlib import Path
from typing import List, Any, Dict

import yaml

from .base_scanner import BaseScanner, Vulnerability


class InfrastructureScanner(BaseScanner):
    """Scanner for infrastructure configuration security issues."""

    def __init__(self):
        """Initialize infrastructure scanner."""
        super().__init__("InfrastructureScanner")

    def scan(self, target_path: Path) -> List[Vulnerability]:
        """
        Scan infrastructure configs for security issues.

        Args:
            target_path: Path to scan

        Returns:
            List of infrastructure vulnerabilities
        """
        self.logger.info(f"Scanning infrastructure at {target_path}")

        vulnerabilities = []

        # Find config files
        config_files = self._find_config_files(target_path)

        for config_file in config_files:
            self.logger.info(f"Scanning {config_file}")
            vulns = self._scan_config_file(config_file)
            vulnerabilities.extend(vulns)

        self.logger.info(
            f"Found {len(vulnerabilities)} infrastructure vulnerabilities"
        )
        return vulnerabilities

    def _find_config_files(self, target_path: Path) -> List[Path]:
        """Find configuration files."""
        files = []

        if target_path.is_file():
            if target_path.suffix in [".yaml", ".yml", ".json"]:
                files.append(target_path)
        else:
            files.extend(target_path.rglob("*.yaml"))
            files.extend(target_path.rglob("*.yml"))
            files.extend(target_path.rglob("*.json"))

            # Exclude common non-config files
            files = [
                f
                for f in files
                if "node_modules" not in str(f)
                and ".git" not in str(f)
                and "package-lock.json" not in str(f)
            ]

        return files

    def _scan_config_file(self, config_file: Path) -> List[Vulnerability]:
        """
        Scan a configuration file.

        Args:
            config_file: Config file path

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        try:
            # Parse config
            config_data = self._parse_config(config_file)

            if config_data is None:
                return []

            # Scan for issues
            vulnerabilities.extend(self._check_hardcoded_credentials(config_file, config_data))
            vulnerabilities.extend(self._check_insecure_settings(config_file, config_data))
            vulnerabilities.extend(self._check_kubernetes_security(config_file, config_data))
            vulnerabilities.extend(self._check_docker_compose_security(config_file, config_data))

        except Exception as e:
            self.logger.error(f"Error scanning {config_file}: {e}")

        return vulnerabilities

    def _parse_config(self, config_file: Path) -> Any:
        """Parse YAML or JSON config file."""
        content = self._read_file_safely(config_file)
        if not content:
            return None

        try:
            if config_file.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(content)
            elif config_file.suffix == ".json":
                return json.loads(content)
        except Exception as e:
            self.logger.warning(f"Could not parse {config_file}: {e}")
            return None

    def _check_hardcoded_credentials(
        self, config_file: Path, config_data: Any
    ) -> List[Vulnerability]:
        """Check for hardcoded credentials."""
        vulnerabilities = []

        # Flatten config to check all key-value pairs
        credentials = self._find_credentials_in_data(config_data, str(config_file))

        for cred in credentials:
            vulnerabilities.append(
                Vulnerability(
                    type="hardcoded_credential",
                    severity="CRITICAL",
                    scanner=self.name,
                    issue=f"Hardcoded credential found: {cred['key']}",
                    description="Hardcoded credentials in config files are a security risk. Use secrets management.",
                    file=str(config_file),
                    cwe="CWE-798",
                    metadata={"key": cred["key"], "value_preview": cred["preview"]},
                )
            )

        return vulnerabilities

    def _find_credentials_in_data(
        self, data: Any, path: str = "", results: List[Dict] = None
    ) -> List[Dict]:
        """Recursively find credentials in nested data structures."""
        if results is None:
            results = []

        credential_keywords = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "client_secret",
            "auth",
            "credential",
        ]

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check if key indicates credential
                if any(keyword in key.lower() for keyword in credential_keywords):
                    if isinstance(value, str) and len(value) > 0:
                        # Check if value looks like a real credential (not placeholder)
                        if not self._is_placeholder(value):
                            results.append(
                                {
                                    "key": current_path,
                                    "preview": value[:20] + "..." if len(value) > 20 else value,
                                }
                            )

                # Recurse into nested structures
                self._find_credentials_in_data(value, current_path, results)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                self._find_credentials_in_data(item, current_path, results)

        return results

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder rather than real credential."""
        placeholders = [
            "change_me",
            "changeme",
            "your_",
            "<",
            ">",
            "xxx",
            "todo",
            "placeholder",
            "example",
            "sample",
            "${",
            "{{",
        ]

        value_lower = value.lower()
        return any(ph in value_lower for ph in placeholders)

    def _check_insecure_settings(
        self, config_file: Path, config_data: Any
    ) -> List[Vulnerability]:
        """Check for insecure configuration settings."""
        vulnerabilities = []

        insecure_patterns = {
            "debug": {
                "values": [True, "true", "1", "yes"],
                "severity": "MEDIUM",
                "description": "Debug mode enabled in production exposes sensitive information",
            },
            "ssl_verify": {
                "values": [False, "false", "0", "no"],
                "severity": "HIGH",
                "description": "SSL verification disabled allows man-in-the-middle attacks",
            },
            "allow_all_origins": {
                "values": [True, "true", "*"],
                "severity": "HIGH",
                "description": "Allowing all origins enables CORS attacks",
            },
            "cors_allowed_origins": {
                "values": ["*"],
                "severity": "HIGH",
                "description": "Wildcard CORS origin allows any domain to make requests",
            },
        }

        # Flatten and check
        flat_config = self._flatten_dict(config_data)

        for key, value in flat_config.items():
            key_lower = key.lower()

            for pattern, config in insecure_patterns.items():
                if pattern in key_lower:
                    if value in config["values"]:
                        vulnerabilities.append(
                            Vulnerability(
                                type="insecure_configuration",
                                severity=config["severity"],
                                scanner=self.name,
                                issue=f"Insecure setting: {key}",
                                description=config["description"],
                                file=str(config_file),
                                cwe="CWE-16",
                                metadata={"setting": key, "value": str(value)},
                            )
                        )

        return vulnerabilities

    def _flatten_dict(
        self, data: Any, parent_key: str = "", sep: str = "."
    ) -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []

        if isinstance(data, dict):
            for k, v in data.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(self._flatten_dict(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
        else:
            items.append((parent_key, data))

        return dict(items)

    def _check_kubernetes_security(
        self, config_file: Path, config_data: Any
    ) -> List[Vulnerability]:
        """Check Kubernetes-specific security issues."""
        vulnerabilities = []

        if not isinstance(config_data, dict):
            return []

        # Check if it's a Kubernetes manifest
        if config_data.get("apiVersion") and config_data.get("kind"):
            kind = config_data.get("kind", "")

            # Check for privileged containers
            if kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]:
                spec = config_data.get("spec", {})

                # Handle different resource types
                if kind == "Pod":
                    containers = spec.get("containers", [])
                else:
                    containers = spec.get("template", {}).get("spec", {}).get("containers", [])

                for container in containers:
                    security_context = container.get("securityContext", {})

                    if security_context.get("privileged"):
                        vulnerabilities.append(
                            Vulnerability(
                                type="privileged_container",
                                severity="CRITICAL",
                                scanner=self.name,
                                issue="Privileged container detected",
                                description="Privileged containers have root access to host. Avoid unless absolutely necessary.",
                                file=str(config_file),
                                cwe="CWE-250",
                                metadata={"container": container.get("name")},
                            )
                        )

                    if security_context.get("runAsUser") == 0:
                        vulnerabilities.append(
                            Vulnerability(
                                type="container_runs_as_root",
                                severity="HIGH",
                                scanner=self.name,
                                issue="Container runs as root (UID 0)",
                                description="Running as root increases security risk. Use non-root user.",
                                file=str(config_file),
                                cwe="CWE-250",
                                metadata={"container": container.get("name")},
                            )
                        )

        return vulnerabilities

    def _check_docker_compose_security(
        self, config_file: Path, config_data: Any
    ) -> List[Vulnerability]:
        """Check Docker Compose security issues."""
        vulnerabilities = []

        if not isinstance(config_data, dict):
            return []

        # Check if it's a Docker Compose file
        if "version" in config_data and "services" in config_data:
            services = config_data.get("services", {})

            for service_name, service_config in services.items():
                # Check for privileged mode
                if service_config.get("privileged"):
                    vulnerabilities.append(
                        Vulnerability(
                            type="privileged_service",
                            severity="CRITICAL",
                            scanner=self.name,
                            issue=f"Privileged mode enabled for service: {service_name}",
                            description="Privileged mode grants extensive permissions. Avoid unless necessary.",
                            file=str(config_file),
                            cwe="CWE-250",
                            metadata={"service": service_name},
                        )
                    )

                # Check for host network mode
                if service_config.get("network_mode") == "host":
                    vulnerabilities.append(
                        Vulnerability(
                            type="host_network_mode",
                            severity="MEDIUM",
                            scanner=self.name,
                            issue=f"Host network mode for service: {service_name}",
                            description="Host network mode reduces container isolation.",
                            file=str(config_file),
                            cwe="CWE-668",
                            metadata={"service": service_name},
                        )
                    )

        return vulnerabilities
