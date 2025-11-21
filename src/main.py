"""Main orchestrator with CLI for security vulnerability scanner."""

import argparse
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from tqdm import tqdm

from .scanners import (
    CodeScanner,
    DependencyScanner,
    ContainerScanner,
    InfrastructureScanner,
)
from .ml_models import RiskScorer, FalsePositiveFilter
from .analyzers import Prioritizer, RemediationEngine, ImpactAnalyzer
from .utils import get_logger, ReportGenerator

logger = get_logger(__name__)
console = Console()


class SecurityScanner:
    """Main security vulnerability scanner orchestrator."""

    def __init__(
        self,
        repo_path: str,
        scan_types: List[str] = None,
        severity_threshold: str = None,
        verbose: bool = False,
    ):
        """
        Initialize security scanner.

        Args:
            repo_path: Path to repository to scan
            scan_types: List of scanner types to run (None = all)
            severity_threshold: Minimum severity to report
            verbose: Enable verbose logging
        """
        self.repo_path = Path(repo_path)
        self.scan_types = scan_types or ["code", "dependency", "container", "infrastructure"]
        self.severity_threshold = severity_threshold
        self.verbose = verbose

        # Initialize components
        self.scanners = self._initialize_scanners()
        self.risk_scorer = RiskScorer()
        self.fp_filter = FalsePositiveFilter()
        self.prioritizer = Prioritizer()
        self.remediation_engine = RemediationEngine()
        self.impact_analyzer = ImpactAnalyzer()

    def _initialize_scanners(self) -> Dict[str, Any]:
        """Initialize scanners based on requested types."""
        all_scanners = {
            "code": CodeScanner(),
            "dependency": DependencyScanner(),
            "container": ContainerScanner(),
            "infrastructure": InfrastructureScanner(),
        }

        return {k: v for k, v in all_scanners.items() if k in self.scan_types}

    def scan(self) -> Dict[str, Any]:
        """
        Run complete security scan workflow.

        Returns:
            Scan results dictionary
        """
        console.print("\n[bold cyan]🔒 Security Vulnerability Scanner[/bold cyan]\n")
        console.print(f"📂 Scanning: [yellow]{self.repo_path}[/yellow]\n")

        # Step 1: Run scanners in parallel
        console.print("[bold]Step 1:[/bold] Running security scanners...")
        vulnerabilities = self._run_scanners()

        if not vulnerabilities:
            console.print("\n[bold green]✓ No vulnerabilities found![/bold green]\n")
            return {
                "vulnerabilities": [],
                "summary": {"total": 0},
                "metadata": {"repo_path": str(self.repo_path)},
            }

        console.print(f"Found [red]{len(vulnerabilities)}[/red] potential issues\n")

        # Step 2: Score with ML
        console.print("[bold]Step 2:[/bold] Scoring vulnerabilities with ML model...")
        vulnerabilities = self.risk_scorer.score_vulnerabilities(vulnerabilities)

        # Step 3: Filter false positives
        console.print("[bold]Step 3:[/bold] Filtering false positives...")
        vulnerabilities = self.fp_filter.filter_vulnerabilities(vulnerabilities)

        # Remove false positives
        original_count = len(vulnerabilities)
        vulnerabilities = [v for v in vulnerabilities if not v.get("is_false_positive")]
        fp_count = original_count - len(vulnerabilities)
        console.print(f"Filtered out [yellow]{fp_count}[/yellow] likely false positives\n")

        # Step 4: Analyze impact
        console.print("[bold]Step 4:[/bold] Analyzing business impact...")
        vulnerabilities = self.impact_analyzer.analyze_impact(vulnerabilities)

        # Step 5: Prioritize
        console.print("[bold]Step 5:[/bold] Prioritizing by risk...")
        vulnerabilities = self.prioritizer.prioritize(vulnerabilities)

        # Step 6: Add remediation
        console.print("[bold]Step 6:[/bold] Generating remediation guidance...\n")
        vulnerabilities = self.remediation_engine.add_remediation(vulnerabilities)

        # Apply severity threshold
        if self.severity_threshold:
            vulnerabilities = self._filter_by_severity(vulnerabilities)

        # Prepare results
        results = {
            "vulnerabilities": [self._serialize_vulnerability(v) for v in vulnerabilities],
            "summary": self._generate_summary(vulnerabilities),
            "metadata": {
                "repo_path": str(self.repo_path),
                "scan_types": self.scan_types,
                "total_scanned": original_count,
                "false_positives_filtered": fp_count,
            },
        }

        return results

    def _run_scanners(self) -> List[Dict[str, Any]]:
        """Run all scanners in parallel."""
        all_vulnerabilities = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Run scanners in parallel
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}

                for name, scanner in self.scanners.items():
                    task = progress.add_task(f"Running {name} scanner...", total=None)
                    future = executor.submit(scanner.scan, self.repo_path)
                    futures[future] = (name, task)

                for future in as_completed(futures):
                    name, task = futures[future]
                    try:
                        vulnerabilities = future.result()
                        # Convert Vulnerability objects to dicts
                        vuln_dicts = [
                            v.to_dict() if hasattr(v, "to_dict") else v
                            for v in vulnerabilities
                        ]
                        all_vulnerabilities.extend(vuln_dicts)
                        progress.update(
                            task,
                            description=f"✓ {name} scanner: {len(vulnerabilities)} issues",
                            completed=True,
                        )
                    except Exception as e:
                        logger.error(f"Scanner {name} failed: {e}")
                        progress.update(task, description=f"✗ {name} scanner: error", completed=True)

        return all_vulnerabilities

    def _filter_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter vulnerabilities by severity threshold."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold_level = severity_order.get(self.severity_threshold.upper(), 0)

        return [
            v
            for v in vulnerabilities
            if severity_order.get(v.get("severity", "INFO").upper(), 0) >= threshold_level
        ]

    def _serialize_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize vulnerability for JSON output."""
        # Ensure all values are JSON serializable
        return {k: v for k, v in vuln.items() if v is not None}

    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics."""
        summary = {
            "total": len(vulnerabilities),
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_priority": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_scanner": {},
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1

            priority = vuln.get("priority_level", "LOW")
            if priority in summary["by_priority"]:
                summary["by_priority"][priority] += 1

            scanner = vuln.get("scanner", "unknown")
            summary["by_scanner"][scanner] = summary["by_scanner"].get(scanner, 0) + 1

        return summary

    def print_summary(self, results: Dict[str, Any]):
        """Print results summary to console."""
        summary = results["summary"]

        # Summary table
        table = Table(title="Vulnerability Summary", show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="magenta")

        table.add_row("Total Vulnerabilities", str(summary["total"]))
        table.add_row("", "")  # Separator

        # By severity
        table.add_row("[bold]By Severity[/bold]", "")
        for severity, count in summary["by_severity"].items():
            if count > 0:
                color = {
                    "CRITICAL": "red",
                    "HIGH": "orange1",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                }.get(severity, "white")
                table.add_row(f"  {severity}", f"[{color}]{count}[/{color}]")

        table.add_row("", "")  # Separator

        # By priority
        table.add_row("[bold]By Priority[/bold]", "")
        for priority, count in summary["by_priority"].items():
            if count > 0:
                table.add_row(f"  {priority}", str(count))

        console.print("\n")
        console.print(table)
        console.print("\n")

    def print_top_vulnerabilities(self, results: Dict[str, Any], limit: int = 10):
        """Print top vulnerabilities."""
        vulnerabilities = results["vulnerabilities"][:limit]

        console.print(f"[bold]Top {min(limit, len(vulnerabilities))} Critical Vulnerabilities:[/bold]\n")

        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get("severity", "UNKNOWN")
            color = {
                "CRITICAL": "red",
                "HIGH": "orange1",
                "MEDIUM": "yellow",
                "LOW": "blue",
            }.get(severity, "white")

            console.print(f"[bold]{i}. [{color}]{severity}[/{color}][/bold] {vuln.get('issue', 'Unknown')}")
            console.print(f"   Type: {vuln.get('type', 'N/A')}")
            console.print(f"   File: {vuln.get('file', 'N/A')}")
            console.print(f"   Risk Score: {vuln.get('risk_score', 0):.1f}/10")
            console.print(f"   Priority: {vuln.get('priority_level', 'N/A')}")

            remediation = vuln.get("remediation", {})
            if remediation:
                console.print(f"   Fix: {remediation.get('description', 'N/A')}\n")
            else:
                console.print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="DevOps Security Vulnerability Scanner and Prioritizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--repo-path",
        required=True,
        help="Path to repository or directory to scan",
    )

    parser.add_argument(
        "--output-format",
        choices=["json", "html", "both"],
        default="both",
        help="Output report format (default: both)",
    )

    parser.add_argument(
        "--severity-threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by minimum severity",
    )

    parser.add_argument(
        "--scan-types",
        nargs="+",
        choices=["code", "dependency", "container", "infrastructure"],
        default=["code", "dependency", "container", "infrastructure"],
        help="Specific scanners to run (default: all)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for reports (default: reports)",
    )

    args = parser.parse_args()

    # Validate repo path
    if not Path(args.repo_path).exists():
        console.print(f"[red]Error: Path does not exist: {args.repo_path}[/red]")
        sys.exit(1)

    try:
        # Initialize scanner
        scanner = SecurityScanner(
            repo_path=args.repo_path,
            scan_types=args.scan_types,
            severity_threshold=args.severity_threshold,
            verbose=args.verbose,
        )

        # Run scan
        results = scanner.scan()

        # Print summary
        scanner.print_summary(results)
        scanner.print_top_vulnerabilities(results)

        # Generate reports
        report_gen = ReportGenerator(output_dir=args.output_dir)

        if args.output_format in ["json", "both"]:
            json_file = report_gen.generate_json_report(
                results["vulnerabilities"], results["metadata"]
            )
            console.print(f"📄 JSON report: [cyan]{json_file}[/cyan]")

        if args.output_format in ["html", "both"]:
            html_file = report_gen.generate_html_report(
                results["vulnerabilities"], results["metadata"]
            )
            console.print(f"📄 HTML report: [cyan]{html_file}[/cyan]")

        console.print("\n[bold green]✓ Scan complete![/bold green]\n")

        # Exit with error code if critical vulnerabilities found
        if results["summary"]["by_severity"]["CRITICAL"] > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Scan failed")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
