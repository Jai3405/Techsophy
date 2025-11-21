# DevOps Security Vulnerability Scanner & Prioritizer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Techsophy Interview Submission** - A production-ready security scanning system that identifies, prioritizes, and provides actionable remediation plans for vulnerabilities across code, dependencies, containers, and infrastructure.

## Overview

This project demonstrates advanced DevOps security practices by combining **multi-dimensional vulnerability scanning** with **machine learning-powered risk assessment** and **intelligent prioritization**. The system scans repositories for security issues and provides prioritized, actionable remediation guidance.

## Features

### Multi-Scanner Architecture
- **Code Scanner** - Python security analysis using Bandit (SQL injection, hardcoded secrets, weak crypto)
- **Dependency Scanner** - CVE detection in packages using Safety
- **Container Scanner** - Dockerfile security best practices analysis
- **Infrastructure Scanner** - Configuration file security (YAML/JSON for K8s, Docker Compose, Terraform)

### ML-Powered Intelligence
- **Risk Scoring Model** - RandomForest classifier (150 estimators) trained on 2000+ samples
- **False Positive Filter** - ML-based noise reduction with precision optimization
- **Feature Engineering** - 6-dimensional feature space (severity, confidence, exploitability, asset value, exposure)

### Multi-Factor Prioritization
- Risk score from ML model (40%)
- Business impact assessment (25%)
- Exploitability analysis (20%)
- Ease of remediation (10%)
- Current threat landscape (5%)

### Business Impact Analysis
- Data exposure risk assessment
- System availability impact
- Compliance violations (GDPR, PCI-DSS, HIPAA, SOC 2)
- Reputation damage potential

### Remediation Engine
- 30+ vulnerability-specific fix patterns
- Before/after code examples
- Step-by-step remediation instructions
- Links to OWASP, CWE references

### Professional Reporting
- JSON reports with complete details
- Interactive HTML reports with Plotly visualizations
- Executive summaries
- Remediation roadmaps

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Security Scanner CLI                     │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │   Main Orchestrator (main.py)  │
        │   • Parallel execution         │
        │   • Progress tracking          │
        │   • Error handling             │
        └───────────────┬───────────────┘
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
┌───▼────┐      ┌──────▼──────┐     ┌─────▼──────┐
│Scanners│      │  ML Models   │     │ Analyzers  │
├────────┤      ├─────────────┤     ├────────────┤
│• Code  │──────▶• Risk Scorer │────▶│• Prioritize│
│• Deps  │      │• FP Filter  │     │• Impact    │
│• Cont. │      │• Trainer    │     │• Remediate │
│• Infra │      └─────────────┘     └────────────┘
└────────┘              │                   │
        │               │                   │
        └───────────────┴───────────────────┘
                        │
                ┌───────▼────────┐
                │ Report Generator│
                │ • JSON          │
                │ • HTML + Charts │
                └─────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd security-vulnerability-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a repository
python -m src.main --repo-path /path/to/repo

# Scan with specific scanners
python -m src.main --repo-path ./my-app --scan-types code dependency

# Filter by severity
python -m src.main --repo-path ./my-app --severity-threshold HIGH

# Custom output directory
python -m src.main --repo-path ./my-app --output-dir ./security-reports

# Verbose mode
python -m src.main --repo-path ./my-app --verbose
```

### Run Demo

```bash
# Execute comprehensive demo on test repository
python demo.py
```

## Usage Examples

### Example 1: Full Security Scan

```bash
python -m src.main \
  --repo-path ./my-application \
  --output-format both \
  --verbose
```

**Output:**
- Discovers 50+ vulnerabilities
- Filters 12 false positives
- Prioritizes by risk and business impact
- Generates JSON and HTML reports with remediation guidance

### Example 2: CI/CD Integration

```bash
# Fail build if critical vulnerabilities found
python -m src.main --repo-path . --severity-threshold CRITICAL
echo $?  # Returns 1 if critical issues found
```

### Example 3: Dependency-Only Scan

```bash
python -m src.main \
  --repo-path ./my-app \
  --scan-types dependency \
  --output-format json
```

## Machine Learning Models

### Risk Scorer

**Algorithm:** RandomForestClassifier
**Features:** 6 dimensions
- Severity level (0-4)
- Confidence score (1-3)
- Vulnerability type hash
- Exploitability score (0-10)
- Asset value (0-10)
- Exposure level (0-10)

**Training:**
- 2000 synthetic samples
- 150 estimators
- Max depth: 10
- Accuracy: ~85%

### False Positive Filter

**Algorithm:** RandomForestClassifier
**Features:** 5 dimensions
- Confidence level
- Code context score
- Pattern match strength
- File type relevance
- Historical accuracy

**Optimization:**
- Precision-focused (minimize false negatives)
- Class weights: {genuine: 1, FP: 2}
- Threshold: 0.7

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test suite
pytest tests/test_scanners.py -v
```

**Test Coverage:**
- Unit tests for all scanners
- ML model validation
- Integration tests for complete workflow
- Edge case handling

## Sample Output

### Console Output
```
Security Vulnerability Scanner

Scanning: /path/to/repo

Step 1: Running security scanners...
code scanner: 25 issues
dependency scanner: 8 issues
container scanner: 7 issues
infrastructure scanner: 12 issues

Step 2: Scoring vulnerabilities with ML model...
Step 3: Filtering false positives...
Filtered out 10 likely false positives

Step 4: Analyzing business impact...
Step 5: Prioritizing by risk...
Step 6: Generating remediation guidance...

Vulnerability Summary
Total Vulnerabilities: 42

By Severity:
  CRITICAL: 8
  HIGH: 15
  MEDIUM: 12
  LOW: 7
```

### Sample Vulnerability Entry

```json
{
  "type": "sql_injection",
  "severity": "CRITICAL",
  "scanner": "CodeScanner",
  "issue": "SQL injection via string formatting",
  "file": "app.py",
  "line": 42,
  "cwe": "CWE-89",
  "risk_score": 9.5,
  "priority_score": 87.3,
  "priority_level": "CRITICAL",
  "impact": {
    "impact_score": 8.7,
    "data_exposure_risk": 9.5,
    "compliance_impact": 9.0
  },
  "remediation": {
    "description": "Use parameterized queries",
    "fix_complexity": "medium",
    "code_example_before": "query = f'SELECT * FROM users WHERE id = {user_id}'",
    "code_example_after": "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))"
  }
}
```

## Configuration

### Severity Levels
- **CRITICAL** - Immediate action required (RCE, data breach potential)
- **HIGH** - High priority (privilege escalation, credential exposure)
- **MEDIUM** - Should be addressed (misconfigurations, weak crypto)
- **LOW** - Best practice improvements

### Priority Levels
Calculated from:
- Risk score (ML model)
- Business impact
- Exploitability
- Remediation ease
- Threat landscape

## Skills Demonstrated

### AI/ML
- RandomForest classification for risk scoring
- Feature engineering (6 dimensions)
- False positive reduction using ML
- Model persistence and versioning
- Synthetic training data generation

### Critical Thinking
- Multi-factor risk prioritization
- Business impact assessment
- Compliance mapping (GDPR, PCI-DSS, HIPAA)
- Threat landscape consideration

### Problem Solving
- Parallel scanner execution (ThreadPoolExecutor)
- Multiple vulnerability type handling
- Cross-platform compatibility
- Graceful error handling

### Modular Architecture
- Clear separation of concerns
- Abstract base classes
- Dependency injection
- Plugin-style scanner system

### Clean Code
- Type hints throughout
- Google-style docstrings
- SOLID principles
- Comprehensive error handling

## Project Structure

```
security-vulnerability-scanner/
├── src/
│   ├── scanners/          # Vulnerability scanners
│   │   ├── base_scanner.py
│   │   ├── code_scanner.py
│   │   ├── dependency_scanner.py
│   │   ├── container_scanner.py
│   │   └── infrastructure_scanner.py
│   ├── ml_models/         # ML models
│   │   ├── risk_scorer.py
│   │   ├── false_positive_filter.py
│   │   └── model_trainer.py
│   ├── analyzers/         # Analysis engines
│   │   ├── prioritizer.py
│   │   ├── remediation_engine.py
│   │   └── impact_analyzer.py
│   ├── utils/             # Utilities
│   │   ├── logger.py
│   │   └── report_generator.py
│   └── main.py            # Main orchestrator + CLI
├── tests/                 # Test suite
├── test_repo/            # Vulnerable test files
├── docs/                 # Documentation
├── demo.py               # Demo script
└── requirements.txt      # Dependencies
```

## Security Note

The `test_repo/` directory contains **intentionally vulnerable code** for testing purposes. **DO NOT** use any code from this directory in production!

## Contributing

This is an interview submission project. For production use, consider:
- Integration with more scanners (Trivy, Snyk, SonarQube)
- Support for additional languages (JavaScript, Go, Java)
- REST API endpoint
- Real-time monitoring
- SARIF format export
- Jira integration

## License

MIT License - See LICENSE file for details

## Author

**Techsophy Interview Candidate**

## Acknowledgments

- OWASP for security best practices
- Bandit for Python security analysis
- Safety for dependency vulnerability checking
- scikit-learn for ML capabilities

---

**Made for Techsophy Interview**

For questions or clarifications, please contact the candidate.
