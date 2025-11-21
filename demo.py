#!/usr/bin/env python3
"""
Demo script for DevOps Security Vulnerability Scanner.
Runs a complete scan on the test repository and displays results.
"""

import sys
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.main import SecurityScanner
from src.utils import ReportGenerator

console = Console()


def print_banner():
    """Print demo banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║  DevOps Security Vulnerability Scanner & Prioritizer    ║
    ║  Techsophy Interview Submission Demo                    ║
    ╚══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold cyan"))


def print_features():
    """Print feature highlights."""
    console.print("\n[bold]🎯 Key Features Demonstrated:[/bold]\n")

    features = [
        ("✓", "Multi-Scanner Architecture", "Code, Dependencies, Containers, Infrastructure"),
        ("✓", "ML-Based Risk Scoring", "RandomForest with 150 estimators"),
        ("✓", "False Positive Filtering", "ML-powered noise reduction"),
        ("✓", "Multi-Factor Prioritization", "Risk, Impact, Exploitability, Remediation Ease"),
        ("✓", "Business Impact Analysis", "Data, Availability, Compliance, Reputation"),
        ("✓", "Remediation Engine", "30+ fix patterns with code examples"),
        ("✓", "Interactive Reports", "JSON & HTML with charts"),
        ("✓", "Production-Ready", "Clean architecture, type hints, comprehensive error handling"),
    ]

    table = Table(show_header=False, box=None)
    table.add_column("", style="green")
    table.add_column("Feature", style="cyan bold")
    table.add_column("Details", style="white")

    for check, feature, details in features:
        table.add_row(check, feature, details)

    console.print(table)
    console.print()


def main():
    """Run demo scan."""
    print_banner()
    print_features()

    # Demo configuration
    test_repo = Path(__file__).parent / "test_repo"

    if not test_repo.exists():
        console.print("[red]Error: test_repo not found![/red]")
        sys.exit(1)

    console.print(f"[bold]📂 Target:[/bold] {test_repo}\n")

    # Initialize scanner
    console.print("[bold cyan]Initializing Security Scanner...[/bold cyan]\n")
    time.sleep(1)

    scanner = SecurityScanner(
        repo_path=str(test_repo),
        scan_types=["code", "dependency", "container", "infrastructure"],
        verbose=False,
    )

    # Run scan
    start_time = time.time()

    try:
        results = scanner.scan()
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    elapsed_time = time.time() - start_time

    # Print detailed summary
    scanner.print_summary(results)

    # Print top 10 critical vulnerabilities
    console.print("\n")
    scanner.print_top_vulnerabilities(results, limit=10)

    # Generate reports
    console.print("\n[bold cyan]📊 Generating Reports...[/bold cyan]\n")

    report_gen = ReportGenerator(output_dir="reports")

    json_file = report_gen.generate_json_report(
        results["vulnerabilities"], results["metadata"]
    )
    html_file = report_gen.generate_html_report(
        results["vulnerabilities"], results["metadata"]
    )

    # Performance metrics
    console.print("\n[bold cyan]⚡ Performance Metrics:[/bold cyan]\n")

    metrics_table = Table(show_header=False, box=None)
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Value", style="green bold")

    metrics_table.add_row("Scan Time", f"{elapsed_time:.2f} seconds")
    metrics_table.add_row("Vulnerabilities Found", str(results["metadata"]["total_scanned"]))
    metrics_table.add_row("False Positives Filtered", str(results["metadata"]["false_positives_filtered"]))
    metrics_table.add_row("Final Count", str(results["summary"]["total"]))
    metrics_table.add_row("Critical Issues", str(results["summary"]["by_severity"]["CRITICAL"]))
    metrics_table.add_row("High Priority", str(results["summary"]["by_priority"]["HIGH"]))

    console.print(metrics_table)

    # Report locations
    console.print("\n[bold cyan]📄 Reports Generated:[/bold cyan]\n")
    console.print(f"  JSON: [green]{json_file}[/green]")
    console.print(f"  HTML: [green]{html_file}[/green]")

    # Remediation example
    if results["vulnerabilities"]:
        console.print("\n[bold cyan]🔧 Example Remediation:[/bold cyan]\n")

        top_vuln = results["vulnerabilities"][0]
        remediation = top_vuln.get("remediation", {})

        console.print(f"[bold]Issue:[/bold] {top_vuln.get('issue', 'N/A')}")
        console.print(f"[bold]Severity:[/bold] {top_vuln.get('severity', 'N/A')}")
        console.print(f"[bold]Risk Score:[/bold] {top_vuln.get('risk_score', 0):.1f}/10")
        console.print(f"\n[bold]Remediation:[/bold]")
        console.print(f"  {remediation.get('description', 'N/A')}")

        if remediation.get("code_example_after"):
            console.print(f"\n[bold]Fix Example:[/bold]")
            console.print(f"[green]{remediation.get('code_example_after')}[/green]")

    # Final summary
    console.print("\n" + "=" * 70)
    console.print("\n[bold green]✓ Demo Complete![/bold green]")
    console.print(f"\nThis demo showcased:")
    console.print("  • Comprehensive vulnerability scanning across 4 dimensions")
    console.print("  • ML-powered risk assessment and prioritization")
    console.print("  • Actionable remediation guidance with code examples")
    console.print("  • Professional reporting in multiple formats")
    console.print(f"\n[bold cyan]View the HTML report for interactive visualizations:[/bold cyan]")
    console.print(f"[green]open {html_file}[/green]\n")


if __name__ == "__main__":
    main()
