"""Base scanner abstract class for all security scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Vulnerability:
    """Data class representing a security vulnerability."""

    type: str
    severity: str
    scanner: str
    issue: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    confidence: Optional[str] = None
    cwe: Optional[str] = None
    code_snippet: Optional[str] = None
    vulnerability_id: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    fixed_version: Optional[str] = None
    risk_score: float = 0.0
    priority_score: float = 0.0
    is_false_positive: bool = False
    remediation: Dict[str, Any] = field(default_factory=dict)
    impact: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, name: str):
        """
        Initialize scanner.

        Args:
            name: Scanner name
        """
        self.name = name
        self.logger = get_logger(f"{__name__}.{name}")

    @abstractmethod
    def scan(self, target_path: Path) -> List[Vulnerability]:
        """
        Scan target for security vulnerabilities.

        Args:
            target_path: Path to scan (file or directory)

        Returns:
            List of discovered vulnerabilities
        """
        pass

    def is_applicable(self, target_path: Path) -> bool:
        """
        Check if scanner is applicable to target.

        Args:
            target_path: Path to check

        Returns:
            True if scanner can analyze this target
        """
        return True

    def _read_file_safely(
        self, file_path: Path, encoding: str = "utf-8"
    ) -> Optional[str]:
        """
        Safely read file with fallback encodings.

        Args:
            file_path: File to read
            encoding: Primary encoding to try

        Returns:
            File contents or None if unreadable
        """
        encodings = [encoding, "utf-8", "latin-1", "cp1252"]

        for enc in encodings:
            try:
                with open(file_path, "r", encoding=enc) as f:
                    return f.read()
            except (UnicodeDecodeError, LookupError):
                continue
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
                return None

        self.logger.warning(f"Could not decode {file_path} with any encoding")
        return None

    def _get_code_snippet(
        self, file_path: Path, line_number: int, context: int = 2
    ) -> str:
        """
        Extract code snippet around a line number.

        Args:
            file_path: Source file
            line_number: Line number of interest
            context: Number of lines before/after to include

        Returns:
            Code snippet string
        """
        content = self._read_file_safely(file_path)
        if not content:
            return ""

        lines = content.splitlines()
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")

        return "\n".join(snippet_lines)
