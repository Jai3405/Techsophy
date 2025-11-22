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

        # Severity pie chart with better color sorting
        summary = self._generate_summary(vulnerabilities)
        severity_data = summary["by_severity"]

        # Color mapping: CRITICAL (red) -> HIGH (orange) -> MEDIUM (yellow) -> LOW (blue) -> INFO (gray)
        severity_colors = {
            "CRITICAL": "#f7768e",  # Muted red - most dangerous
            "HIGH": "#ff9e64",      # Muted orange - high priority
            "MEDIUM": "#e0af68",    # Muted amber - medium priority
            "LOW": "#7aa2f7",       # Muted blue - low risk
            "INFO": "#565f89"       # Muted gray - informational
        }

        fig.add_trace(
            go.Pie(
                labels=list(severity_data.keys()),
                values=list(severity_data.values()),
                marker=dict(
                    colors=[severity_colors.get(k, "#565f89") for k in severity_data.keys()]
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
                marker_color="#7aa2f7",
            ),
            row=1,
            col=2,
        )

        # Risk score histogram
        risk_scores = [v.get("risk_score", 0) for v in vulnerabilities]
        fig.add_trace(
            go.Histogram(x=risk_scores, nbinsx=10, marker_color="#9ece6a"), row=2, col=1
        )

        # Scanner bar chart
        scanner_data = summary["by_scanner"]
        fig.add_trace(
            go.Bar(
                x=list(scanner_data.keys()),
                y=list(scanner_data.values()),
                marker_color="#bb9af7",
            ),
            row=2,
            col=2,
        )

        # Update layout for dark theme
        fig.update_layout(
            height=800,
            showlegend=False,
            title_text="Security Vulnerability Analysis Dashboard",
            title_font=dict(size=20, color="#c0caf5"),
            paper_bgcolor="#24283b",
            plot_bgcolor="#2f334d",
            font=dict(color="#c0caf5", family="-apple-system, BlinkMacSystemFont, 'Inter', 'SF Pro', 'Segoe UI', system-ui, sans-serif"),
        )

        # Update axes for dark theme
        fig.update_xaxes(gridcolor="#414868", zerolinecolor="#414868")
        fig.update_yaxes(gridcolor="#414868", zerolinecolor="#414868")

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
        /* Dark Theme with Muted Pastels */
        :root {
            --bg-primary: #1a1b26;
            --bg-secondary: #24283b;
            --bg-hover: #2f334d;
            --color-primary: #7aa2f7;
            --color-success: #9ece6a;
            --color-warning: #e0af68;
            --color-danger: #f7768e;
            --color-critical: #f7768e;
            --color-high: #ff9e64;
            --color-medium: #e0af68;
            --color-low: #7aa2f7;
            --color-info: #565f89;
            --text-primary: #c0caf5;
            --text-secondary: #9aa5ce;
            --border-color: #414868;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'SF Pro', 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 32px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.4);
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        header p {
            color: var(--text-secondary);
            font-size: 16px;
        }

        .metadata {
            background: rgba(122, 162, 247, 0.1);
            border: 1px solid rgba(122, 162, 247, 0.2);
            padding: 20px;
            border-radius: 8px;
            margin-top: 24px;
        }

        .metadata p {
            margin: 8px 0;
            color: var(--text-primary);
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }

        .summary-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 28px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            border-left: 4px solid var(--color-primary);
            transition: all 0.2s;
        }

        .summary-card:hover {
            border-color: var(--color-primary);
            transform: translateY(-2px);
        }

        .summary-card h3 {
            color: var(--text-secondary);
            margin-bottom: 12px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .summary-card .number {
            font-size: 2.5em;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .summary-card p {
            color: var(--text-secondary);
            font-size: 14px;
        }

        .severity-critical { border-left-color: var(--color-critical); }
        .severity-critical h3 { color: var(--color-critical); }

        .severity-high { border-left-color: var(--color-high); }
        .severity-high h3 { color: var(--color-high); }

        .severity-medium { border-left-color: var(--color-medium); }
        .severity-medium h3 { color: var(--color-medium); }

        .severity-low { border-left-color: var(--color-low); }
        .severity-low h3 { color: var(--color-low); }

        .charts {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 32px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .vulnerabilities {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 32px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .vulnerabilities h2 {
            color: var(--text-primary);
            margin-bottom: 24px;
            font-size: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .vuln-item {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            transition: all 0.2s;
        }

        .vuln-item:hover {
            border-color: var(--color-primary);
            box-shadow: 0 0 0 1px var(--color-primary);
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .vuln-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 100px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 8px;
        }

        .badge-critical {
            background: rgba(247, 118, 142, 0.15);
            color: var(--color-critical);
            border: 1px solid rgba(247, 118, 142, 0.3);
        }

        .badge-high {
            background: rgba(255, 158, 100, 0.15);
            color: var(--color-high);
            border: 1px solid rgba(255, 158, 100, 0.3);
        }

        .badge-medium {
            background: rgba(224, 175, 104, 0.15);
            color: var(--color-medium);
            border: 1px solid rgba(224, 175, 104, 0.3);
        }

        .badge-low {
            background: rgba(122, 162, 247, 0.15);
            color: var(--color-low);
            border: 1px solid rgba(122, 162, 247, 0.3);
        }

        .badge-info {
            background: rgba(86, 95, 137, 0.15);
            color: var(--color-info);
            border: 1px solid rgba(86, 95, 137, 0.3);
        }

        .vuln-details {
            background: var(--bg-hover);
            padding: 20px;
            border-radius: 8px;
            margin-top: 12px;
            border: 1px solid var(--border-color);
        }

        .vuln-details p {
            margin: 10px 0;
            color: var(--text-primary);
            font-size: 14px;
        }

        .vuln-details strong {
            color: var(--text-secondary);
            font-weight: 600;
        }

        .code-snippet {
            background: #16161e;
            color: #c0caf5;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            margin: 16px 0;
            border: 1px solid var(--border-color);
        }

        .remediation {
            background: rgba(158, 206, 106, 0.1);
            border: 1px solid rgba(158, 206, 106, 0.3);
            border-left: 4px solid var(--color-success);
            padding: 20px;
            margin-top: 16px;
            border-radius: 8px;
        }

        .remediation h4 {
            color: var(--color-success);
            margin-bottom: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .remediation p {
            color: var(--text-primary);
            margin: 8px 0;
        }

        footer {
            text-align: center;
            padding: 32px 24px;
            color: var(--text-secondary);
            margin-top: 48px;
            border-top: 1px solid var(--border-color);
        }

        footer p {
            margin: 4px 0;
            font-size: 14px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }

            header {
                padding: 24px;
            }

            header h1 {
                font-size: 1.8em;
            }

            .summary {
                grid-template-columns: 1fr;
            }

            .vuln-item {
                padding: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Security Vulnerability Report
            </h1>
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
            <h2>
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                </svg>
                Detailed Findings
            </h2>
            {% for vuln in vulnerabilities[:50] %}
            <div class="vuln-item">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">{{ vuln.get('issue', vuln.get('type', 'Unknown Issue')) }}</div>
                        <span class="badge badge-{{ vuln.get('severity', 'info').lower() }}">
                            {{ vuln.get('severity', 'INFO') }}
                        </span>
                        {% if vuln.get('risk_score') %}
                        <span class="badge" style="background: rgba(187, 154, 247, 0.15); color: #bb9af7;">
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
                    <h4>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                            <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                        Remediation
                    </h4>
                    <p>{{ vuln.remediation.get('description', 'N/A') }}</p>
                    {% if vuln.remediation.get('fix_complexity') %}
                    <p><strong>Complexity:</strong> {{ vuln.remediation.fix_complexity }}</p>
                    {% endif %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
            {% if vulnerabilities|length > 50 %}
            <p style="text-align: center; margin-top: 24px; color: var(--text-secondary); font-size: 14px;">
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
