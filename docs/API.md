# API Documentation

## Programmatic Usage

The security scanner can be used programmatically in Python applications.

## SecurityScanner Class

### Initialization

```python
from src.main import SecurityScanner

scanner = SecurityScanner(
    repo_path="/path/to/repository",
    scan_types=["code", "dependency", "container", "infrastructure"],
    severity_threshold="HIGH",  # Optional
    verbose=False  # Optional
)
```

**Parameters:**
- `repo_path` (str): Path to repository or directory to scan
- `scan_types` (list): List of scanner types to run (default: all)
- `severity_threshold` (str): Minimum severity to report (optional)
- `verbose` (bool): Enable verbose logging (default: False)

### Methods

#### scan()

Run complete security scan workflow.

```python
results = scanner.scan()
```

**Returns:** Dictionary with structure:
```python
{
    "vulnerabilities": [
        {
            "type": str,
            "severity": str,
            "scanner": str,
            "issue": str,
            "description": str,
            "file": str,
            "line": int,
            "risk_score": float,
            "priority_score": float,
            "priority_level": str,
            "remediation": dict,
            "impact": dict,
            ...
        }
    ],
    "summary": {
        "total": int,
        "by_severity": dict,
        "by_priority": dict,
        "by_scanner": dict
    },
    "metadata": {
        "repo_path": str,
        "scan_types": list,
        "total_scanned": int,
        "false_positives_filtered": int
    }
}
```

## Individual Scanners

### CodeScanner

```python
from src.scanners import CodeScanner

scanner = CodeScanner()
vulnerabilities = scanner.scan(Path("/path/to/code"))
```

### DependencyScanner

```python
from src.scanners import DependencyScanner

scanner = DependencyScanner()
vulnerabilities = scanner.scan(Path("/path/to/repo"))
```

### ContainerScanner

```python
from src.scanners import ContainerScanner

scanner = ContainerScanner()
vulnerabilities = scanner.scan(Path("/path/to/dockerfile"))
```

### InfrastructureScanner

```python
from src.scanners import InfrastructureScanner

scanner = InfrastructureScanner()
vulnerabilities = scanner.scan(Path("/path/to/configs"))
```

## ML Models

### RiskScorer

```python
from src.ml_models import RiskScorer

scorer = RiskScorer()
vulnerabilities = scorer.score_vulnerabilities(vulnerabilities)

# Get feature importance
importance = scorer.get_feature_importance()
```

### FalsePositiveFilter

```python
from src.ml_models import FalsePositiveFilter

fp_filter = FalsePositiveFilter()
filtered_vulns = fp_filter.filter_vulnerabilities(
    vulnerabilities,
    threshold=0.7
)
```

## Analyzers

### Prioritizer

```python
from src.analyzers import Prioritizer

prioritizer = Prioritizer()
prioritized = prioritizer.prioritize(vulnerabilities)

# Get only critical vulnerabilities
critical = prioritizer.get_critical_vulnerabilities(vulnerabilities)

# Group by priority
groups = prioritizer.group_by_priority(vulnerabilities)
```

### ImpactAnalyzer

```python
from src.analyzers import ImpactAnalyzer

analyzer = ImpactAnalyzer()
analyzed = analyzer.analyze_impact(vulnerabilities)
```

### RemediationEngine

```python
from src.analyzers import RemediationEngine

engine = RemediationEngine()
with_remediation = engine.add_remediation(vulnerabilities)
```

## Report Generation

```python
from src.utils import ReportGenerator

generator = ReportGenerator(output_dir="reports")

# Generate JSON report
json_file = generator.generate_json_report(
    vulnerabilities,
    metadata
)

# Generate HTML report
html_file = generator.generate_html_report(
    vulnerabilities,
    metadata
)
```

## Complete Example

```python
from pathlib import Path
from src.main import SecurityScanner
from src.utils import ReportGenerator

# Initialize scanner
scanner = SecurityScanner(
    repo_path="/path/to/my-app",
    scan_types=["code", "dependency"],
    severity_threshold="HIGH"
)

# Run scan
results = scanner.scan()

# Process results
critical_vulns = [
    v for v in results["vulnerabilities"]
    if v["severity"] == "CRITICAL"
]

print(f"Found {len(critical_vulns)} critical vulnerabilities")

# Generate reports
report_gen = ReportGenerator()
report_gen.generate_json_report(
    results["vulnerabilities"],
    results["metadata"]
)
report_gen.generate_html_report(
    results["vulnerabilities"],
    results["metadata"]
)
```

## Vulnerability Object Schema

```python
from src.scanners import Vulnerability

vuln = Vulnerability(
    type="sql_injection",              # Required
    severity="CRITICAL",                # Required
    scanner="CodeScanner",              # Required
    issue="SQL injection detected",     # Required
    description="Detailed description", # Required
    file="/path/to/file.py",           # Optional
    line=42,                           # Optional
    confidence="HIGH",                 # Optional
    cwe="CWE-89",                      # Optional
    code_snippet="vulnerable code",    # Optional
    vulnerability_id="CVE-2024-1234",  # Optional
    package="package-name",            # Optional
    version="1.0.0",                   # Optional
    fixed_version="1.0.1",             # Optional
)

# Convert to dictionary
vuln_dict = vuln.to_dict()
```

## CLI Integration

Run scanner from command line:

```bash
# Basic scan
python -m src.main --repo-path /path/to/repo

# With options
python -m src.main \
  --repo-path /path/to/repo \
  --scan-types code dependency \
  --severity-threshold HIGH \
  --output-format both \
  --output-dir ./reports \
  --verbose
```

Exit codes:
- 0: Success, no critical vulnerabilities
- 1: Critical vulnerabilities found
- 130: Interrupted by user
- Other: Error occurred
