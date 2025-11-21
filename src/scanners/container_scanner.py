"""Container scanner for Dockerfile security analysis."""

import re
from pathlib import Path
from typing import List, Set

from .base_scanner import BaseScanner, Vulnerability


class ContainerScanner(BaseScanner):
    """Scanner for Dockerfile security issues."""

    INSECURE_PORTS = {22, 23, 3389, 3306, 5432, 6379, 27017, 5000, 8080}

    def __init__(self):
        """Initialize container scanner."""
        super().__init__("ContainerScanner")

    def scan(self, target_path: Path) -> List[Vulnerability]:
        """
        Scan Dockerfiles for security issues.

        Args:
            target_path: Path to scan

        Returns:
            List of container vulnerabilities
        """
        self.logger.info(f"Scanning containers at {target_path}")

        vulnerabilities = []

        # Find Dockerfiles
        dockerfiles = self._find_dockerfiles(target_path)

        for dockerfile in dockerfiles:
            self.logger.info(f"Scanning {dockerfile}")
            vulns = self._scan_dockerfile(dockerfile)
            vulnerabilities.extend(vulns)

        self.logger.info(f"Found {len(vulnerabilities)} container vulnerabilities")
        return vulnerabilities

    def _find_dockerfiles(self, target_path: Path) -> List[Path]:
        """Find Dockerfile files."""
        files = []

        if target_path.is_file() and "dockerfile" in target_path.name.lower():
            files.append(target_path)
        elif target_path.is_dir():
            files.extend(target_path.rglob("Dockerfile*"))
            files.extend(target_path.rglob("*.dockerfile"))

        return files

    def _scan_dockerfile(self, dockerfile: Path) -> List[Vulnerability]:
        """
        Scan a Dockerfile for security issues.

        Args:
            dockerfile: Dockerfile path

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        content = self._read_file_safely(dockerfile)
        if not content:
            return []

        lines = content.splitlines()

        # Track findings
        has_user = False
        has_healthcheck = False
        base_images: List[str] = []

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            # Check for 'latest' tag
            if line.upper().startswith("FROM"):
                base_images.append(line)
                if ":latest" in line.lower() or ":" not in line.split()[1]:
                    vulnerabilities.append(
                        Vulnerability(
                            type="insecure_base_image",
                            severity="MEDIUM",
                            scanner=self.name,
                            issue="Using 'latest' tag in base image",
                            description="Using 'latest' tag can lead to unpredictable builds and security issues. Pin to specific version.",
                            file=str(dockerfile),
                            line=line_num,
                            code_snippet=line,
                            cwe="CWE-710",
                        )
                    )

            # Check for USER directive
            if line.upper().startswith("USER"):
                has_user = True
                user = line.split()[1] if len(line.split()) > 1 else ""
                if user in ["root", "0"]:
                    vulnerabilities.append(
                        Vulnerability(
                            type="running_as_root",
                            severity="HIGH",
                            scanner=self.name,
                            issue="Container explicitly runs as root",
                            description="Running containers as root increases security risk. Use non-root user.",
                            file=str(dockerfile),
                            line=line_num,
                            code_snippet=line,
                            cwe="CWE-250",
                        )
                    )

            # Check for HEALTHCHECK
            if line.upper().startswith("HEALTHCHECK"):
                has_healthcheck = True

            # Check for exposed ports
            if line.upper().startswith("EXPOSE"):
                ports = self._extract_ports(line)
                for port in ports:
                    if port in self.INSECURE_PORTS:
                        vulnerabilities.append(
                            Vulnerability(
                                type="insecure_port_exposed",
                                severity="HIGH",
                                scanner=self.name,
                                issue=f"Insecure port {port} exposed",
                                description=f"Port {port} is commonly targeted by attackers. Avoid exposing if not necessary.",
                                file=str(dockerfile),
                                line=line_num,
                                code_snippet=line,
                                cwe="CWE-200",
                                metadata={"port": port},
                            )
                        )

            # Check for secrets in ENV
            if line.upper().startswith("ENV"):
                if self._contains_secret(line):
                    vulnerabilities.append(
                        Vulnerability(
                            type="hardcoded_secret",
                            severity="CRITICAL",
                            scanner=self.name,
                            issue="Potential secret in ENV variable",
                            description="Hardcoded secrets in ENV variables are insecure. Use secrets management.",
                            file=str(dockerfile),
                            line=line_num,
                            code_snippet=line,
                            cwe="CWE-798",
                        )
                    )

            # Check for package manager without cleanup
            if re.search(r"(apt-get|yum|apk)\s+install", line.lower()):
                if not re.search(
                    r"(rm -rf|clean|autoremove)", line.lower()
                ) and not re.search(r"&&.*rm", content[content.find(line) :].split("\n")[0]):
                    vulnerabilities.append(
                        Vulnerability(
                            type="inefficient_layer",
                            severity="LOW",
                            scanner=self.name,
                            issue="Package installation without cleanup",
                            description="Not cleaning package manager cache increases image size and attack surface.",
                            file=str(dockerfile),
                            line=line_num,
                            code_snippet=line,
                            cwe="CWE-710",
                        )
                    )

            # Check for ADD instead of COPY
            if line.upper().startswith("ADD") and not any(
                x in line for x in [".tar", ".gz", ".zip", "http://", "https://"]
            ):
                vulnerabilities.append(
                    Vulnerability(
                        type="insecure_add_usage",
                        severity="LOW",
                        scanner=self.name,
                        issue="Using ADD instead of COPY",
                        description="ADD has implicit behavior. Use COPY for simple file copies.",
                        file=str(dockerfile),
                        line=line_num,
                        code_snippet=line,
                        cwe="CWE-710",
                    )
                )

            # Check for curl/wget without verification
            if re.search(r"(curl|wget)", line.lower()):
                if not re.search(r"(-k|--insecure)", line):
                    # Good - not using insecure flags
                    pass
                else:
                    vulnerabilities.append(
                        Vulnerability(
                            type="insecure_download",
                            severity="MEDIUM",
                            scanner=self.name,
                            issue="Insecure download detected",
                            description="Using --insecure flag bypasses SSL verification.",
                            file=str(dockerfile),
                            line=line_num,
                            code_snippet=line,
                            cwe="CWE-295",
                        )
                    )

        # Check if USER was never set
        if not has_user:
            vulnerabilities.append(
                Vulnerability(
                    type="missing_user_directive",
                    severity="HIGH",
                    scanner=self.name,
                    issue="No USER directive found",
                    description="Container will run as root by default. Add USER directive with non-root user.",
                    file=str(dockerfile),
                    cwe="CWE-250",
                )
            )

        # Check if HEALTHCHECK is missing
        if not has_healthcheck:
            vulnerabilities.append(
                Vulnerability(
                    type="missing_healthcheck",
                    severity="MEDIUM",
                    scanner=self.name,
                    issue="No HEALTHCHECK directive found",
                    description="HEALTHCHECK allows Docker to detect unhealthy containers. Add health check.",
                    file=str(dockerfile),
                    cwe="CWE-710",
                )
            )

        return vulnerabilities

    def _extract_ports(self, expose_line: str) -> Set[int]:
        """Extract port numbers from EXPOSE directive."""
        ports = set()

        # Remove EXPOSE keyword
        line = re.sub(r"EXPOSE\s+", "", expose_line, flags=re.IGNORECASE)

        # Extract numbers
        for match in re.finditer(r"\d+", line):
            try:
                ports.add(int(match.group()))
            except ValueError:
                pass

        return ports

    def _contains_secret(self, line: str) -> bool:
        """Check if line contains potential secrets."""
        secret_patterns = [
            r"(password|passwd|pwd|secret|token|api_key|apikey|access_key)",
            r"(aws_access_key_id|aws_secret_access_key)",
            r"(private_key|client_secret)",
        ]

        line_lower = line.lower()

        for pattern in secret_patterns:
            if re.search(pattern, line_lower):
                # Check if there's a value that looks like a secret
                if re.search(r"=\s*['\"]?[a-zA-Z0-9_\-]{8,}", line):
                    return True

        return False
