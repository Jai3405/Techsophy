"""Report generation utilities for vulnerability scan results."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from jinja2 import Template

from .logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generate comprehensive security reports in multiple formats."""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_json_report(
        self, vulnerabilities: List[Dict[str, Any]], metadata: Dict[str, Any]
    ) -> str:
        """
        Generate JSON report with full vulnerability details.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            metadata: Scan metadata (repo_path, scan_time, etc.)

        Returns:
            Path to generated JSON file
        """
        report = {
            "metadata": {
                **metadata,
                "report_generated": datetime.now().isoformat(),
                "total_vulnerabilities": len(vulnerabilities),
            },
            "summary": self._generate_summary(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

        output_file = self.output_dir / f"security_report_{self.timestamp}.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"JSON report generated: {output_file}")
        return str(output_file)

    def generate_html_report(
        self, vulnerabilities: List[Dict[str, Any]], metadata: Dict[str, Any]
    ) -> str:
        """
        Generate interactive HTML report with charts.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            metadata: Scan metadata

        Returns:
            Path to generated HTML file
        """
        summary = self._generate_summary(vulnerabilities)

        # Generate charts
        charts_html = self._generate_charts(vulnerabilities)

        # Generate HTML from template
        html_template = self._get_html_template()
        template = Template(html_template)

        html_content = template.render(
            metadata=metadata,
            summary=summary,
            vulnerabilities=sorted(
                vulnerabilities, key=lambda x: x.get("priority_score", 0), reverse=True
            ),
            charts=charts_html,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        output_file = self.output_dir / f"security_report_{self.timestamp}.html"
        with open(output_file, "w") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {output_file}")
        return str(output_file)

    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from vulnerabilities."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        type_counts: Dict[str, int] = {}
        scanner_counts: Dict[str, int] = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

            vuln_type = vuln.get("type", "unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

            scanner = vuln.get("scanner", "unknown")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        return {
            "total": len(vulnerabilities),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "by_scanner": scanner_counts,
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
        }

    def _generate_charts(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate plotly charts for vulnerabilities."""
        if not vulnerabilities:
            return "<p>No vulnerabilities found to visualize.</p>"

        # Create subplots
        fig = make_subplots(
            rows=2,
            cols=2,
            subplot_titles=(
                "Vulnerabilities by Severity",
                "Vulnerabilities by Type",
                "Risk Score Distribution",
                "Vulnerabilities by Scanner",
            ),
            specs=[
                [{"type": "pie"}, {"type": "bar"}],
                [{"type": "histogram"}, {"type": "bar"}],
            ],
        )

        # Severity pie chart
        summary = self._generate_summary(vulnerabilities)
        severity_data = summary["by_severity"]
        fig.add_trace(
            go.Pie(
                labels=list(severity_data.keys()),
                values=list(severity_data.values()),
                marker=dict(
                    colors=["#dc3545", "#fd7e14", "#ffc107", "#17a2b8", "#6c757d"]
                ),
            ),
            row=1,
            col=1,
        )

        # Type bar chart
        type_data = summary["by_type"]
        sorted_types = sorted(type_data.items(), key=lambda x: x[1], reverse=True)[:10]
        fig.add_trace(
            go.Bar(
                x=[t[0] for t in sorted_types],
                y=[t[1] for t in sorted_types],
                marker_color="#0d6efd",
            ),
            row=1,
            col=2,
        )

        # Risk score histogram
        risk_scores = [v.get("risk_score", 0) for v in vulnerabilities]
        fig.add_trace(
            go.Histogram(x=risk_scores, nbinsx=10, marker_color="#198754"), row=2, col=1
        )

        # Scanner bar chart
        scanner_data = summary["by_scanner"]
        fig.add_trace(
            go.Bar(
                x=list(scanner_data.keys()),
                y=list(scanner_data.values()),
                marker_color="#6f42c1",
            ),
            row=2,
            col=2,
        )

        # Update layout
        fig.update_layout(
            height=800,
            showlegend=False,
            title_text="Security Vulnerability Analysis Dashboard",
        )

        return fig.to_html(include_plotlyjs="cdn", div_id="charts")

    def _get_html_template(self) -> str:
        """Get HTML template for report."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Vulnerability Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .metadata {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .summary-card h3 { color: #667eea; margin-bottom: 10px; }
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        .severity-critical { border-left-color: #dc3545; color: #dc3545; }
        .severity-high { border-left-color: #fd7e14; color: #fd7e14; }
        .severity-medium { border-left-color: #ffc107; color: #ffc107; }
        .severity-low { border-left-color: #17a2b8; color: #17a2b8; }
        .charts {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .vulnerabilities {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .vuln-item {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: transform 0.2s;
        }
        .vuln-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .vuln-title {
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #17a2b8; color: white; }
        .badge-info { background: #6c757d; color: white; }
        .vuln-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .vuln-details p {
            margin: 8px 0;
        }
        .code-snippet {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        .remediation {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-top: 10px;
            border-radius: 5px;
        }
        .remediation h4 {
            color: #155724;
            margin-bottom: 10px;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Vulnerability Report</h1>
            <p>Comprehensive security analysis and risk assessment</p>
            <div class="metadata">
                <p><strong>Repository:</strong> {{ metadata.get('repo_path', 'N/A') }}</p>
                <p><strong>Scan Date:</strong> {{ timestamp }}</p>
                <p><strong>Total Vulnerabilities:</strong> {{ summary.total }}</p>
            </div>
        </header>

        <div class="summary">
            <div class="summary-card severity-critical">
                <h3>Critical</h3>
                <div class="number">{{ summary.by_severity.CRITICAL }}</div>
                <p>Immediate action required</p>
            </div>
            <div class="summary-card severity-high">
                <h3>High</h3>
                <div class="number">{{ summary.by_severity.HIGH }}</div>
                <p>High priority fixes</p>
            </div>
            <div class="summary-card severity-medium">
                <h3>Medium</h3>
                <div class="number">{{ summary.by_severity.MEDIUM }}</div>
                <p>Should be addressed</p>
            </div>
            <div class="summary-card severity-low">
                <h3>Low</h3>
                <div class="number">{{ summary.by_severity.LOW }}</div>
                <p>Low risk items</p>
            </div>
        </div>

        <div class="charts">
            {{ charts|safe }}
        </div>

        <div class="vulnerabilities">
            <h2 style="margin-bottom: 20px;">📋 Detailed Findings</h2>
            {% for vuln in vulnerabilities[:50] %}
            <div class="vuln-item">
                <div class="vuln-header">
                    <div>
                        <span class="vuln-title">{{ vuln.get('issue', vuln.get('type', 'Unknown Issue')) }}</span>
                        <span class="badge badge-{{ vuln.get('severity', 'info').lower() }}">
                            {{ vuln.get('severity', 'INFO') }}
                        </span>
                        {% if vuln.get('risk_score') %}
                        <span class="badge" style="background: #6f42c1; color: white;">
                            Risk Score: {{ "%.1f"|format(vuln.risk_score) }}
                        </span>
                        {% endif %}
                    </div>
                </div>

                <div class="vuln-details">
                    <p><strong>Scanner:</strong> {{ vuln.get('scanner', 'N/A') }}</p>
                    <p><strong>Type:</strong> {{ vuln.get('type', 'N/A') }}</p>
                    {% if vuln.get('file') %}
                    <p><strong>Location:</strong> {{ vuln.file }}{% if vuln.get('line') %}:{{ vuln.line }}{% endif %}</p>
                    {% endif %}
                    {% if vuln.get('description') %}
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% endif %}
                    {% if vuln.get('cwe') %}
                    <p><strong>CWE:</strong> {{ vuln.cwe }}</p>
                    {% endif %}
                    {% if vuln.get('vulnerability_id') %}
                    <p><strong>CVE/Advisory:</strong> {{ vuln.vulnerability_id }}</p>
                    {% endif %}
                </div>

                {% if vuln.get('code_snippet') %}
                <div class="code-snippet">{{ vuln.code_snippet }}</div>
                {% endif %}

                {% if vuln.get('remediation') %}
                <div class="remediation">
                    <h4>🔧 Remediation</h4>
                    <p>{{ vuln.remediation.get('description', 'N/A') }}</p>
                    {% if vuln.remediation.get('fix_complexity') %}
                    <p><strong>Complexity:</strong> {{ vuln.remediation.fix_complexity }}</p>
                    {% endif %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
            {% if vulnerabilities|length > 50 %}
            <p style="text-align: center; margin-top: 20px; color: #6c757d;">
                Showing top 50 vulnerabilities. See JSON report for complete details.
            </p>
            {% endif %}
        </div>

        <footer>
            <p>Generated by DevOps Security Vulnerability Scanner v1.0.0</p>
            <p>Techsophy Interview Submission</p>
        </footer>
    </div>
</body>
</html>
"""
