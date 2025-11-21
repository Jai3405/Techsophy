# Quick Start Guide

## Installation (5 minutes)

### Step 1: Set Up Environment

```bash
# Navigate to project directory
cd security-vulnerability-scanner

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Verify Python version
python --version  # Should be 3.9 or higher
```

### Step 2: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
python -c "import bandit; import sklearn; print('Installation successful!')"
```

## Running the Demo (2 minutes)

### Option 1: Run Demo Script

```bash
# Execute the demo
python demo.py
```

**What it does:**
- Scans the vulnerable test repository
- Demonstrates all features
- Shows top 10 critical vulnerabilities
- Generates HTML and JSON reports
- Displays performance metrics

**Expected Output:**
```
Security Vulnerability Scanner
Scanning: test_repo/

Step 1: Running security scanners...
Step 2: Scoring vulnerabilities with ML model...
Step 3: Filtering false positives...
Step 4: Analyzing business impact...
Step 5: Prioritizing by risk...
Step 6: Generating remediation guidance...

Found 42 vulnerabilities
CRITICAL: 8
HIGH: 15

Reports generated in reports/
```

### Option 2: Manual Scan

```bash
# Scan the test repository
python -m src.main --repo-path test_repo/

# View the generated HTML report
open reports/security_report_*.html  # On Mac
# OR
xdg-open reports/security_report_*.html  # On Linux
# OR
start reports/security_report_*.html  # On Windows
```

## Running Tests (2 minutes)

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_scanners.py -v
```

**Expected Results:**
- All tests should pass
- Coverage should be 70%+

## Scan Your Own Repository (1 minute)

```bash
# Basic scan
python -m src.main --repo-path /path/to/your/project

# Scan with filtering
python -m src.main \
  --repo-path /path/to/your/project \
  --severity-threshold HIGH \
  --output-format both

# Scan specific types only
python -m src.main \
  --repo-path /path/to/your/project \
  --scan-types code dependency
```

## Understanding the Output

### Console Output

The scanner displays:
1. Progress for each scanner
2. Number of vulnerabilities found
3. False positives filtered
4. Summary by severity and priority
5. Top critical vulnerabilities with remediation

### JSON Report

Location: `reports/security_report_TIMESTAMP.json`

Contains:
- Complete vulnerability details
- Metadata (scan time, configuration)
- Summary statistics
- ML model scores
- Remediation guidance

### HTML Report

Location: `reports/security_report_TIMESTAMP.html`

Features:
- Interactive Plotly charts
- Severity breakdown
- Top vulnerabilities
- Remediation steps
- Code examples

## Common Use Cases

### Use Case 1: Pre-commit Hook

```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
python -m src.main --repo-path . --severity-threshold CRITICAL
```

### Use Case 2: CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python -m src.main --repo-path . --output-format json
    if [ $? -eq 1 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### Use Case 3: Periodic Scanning

```bash
# Cron job (daily at 2 AM)
0 2 * * * cd /path/to/project && /path/to/venv/bin/python -m src.main --repo-path . --output-dir /var/reports
```

## Troubleshooting

### Issue: Bandit not found

```bash
pip install bandit>=1.7.5
```

### Issue: Safety not found

```bash
pip install safety>=3.0.0
```

### Issue: No vulnerabilities found

Check that:
- Repository contains Python files
- requirements.txt exists for dependency scanning
- Dockerfile exists for container scanning
- YAML/JSON configs exist for infrastructure scanning

### Issue: ModuleNotFoundError

```bash
# Ensure you're in the project root
cd security-vulnerability-scanner

# Reinstall dependencies
pip install -r requirements.txt
```

## Next Steps

1. **Read the full README.md** - Comprehensive documentation
2. **Review ARCHITECTURE.md** - System design details
3. **Check SUBMISSION.md** - Project deliverables
4. **Explore the code** - Well-documented and modular
5. **Customize** - Add your own scanners or remediation patterns

## Key Files

- `src/main.py` - Main entry point and CLI
- `src/scanners/` - All vulnerability scanners
- `src/ml_models/` - ML models for risk scoring
- `src/analyzers/` - Prioritization and remediation
- `demo.py` - Demonstration script
- `tests/` - Test suite
- `test_repo/` - Vulnerable code for testing

## Getting Help

For questions or issues:
1. Check the README.md
2. Review the API documentation (docs/API.md)
3. Look at the test cases for examples
4. Contact the candidate

## Performance Tips

1. **Faster scans** - Use `--scan-types` to run specific scanners only
2. **Less noise** - Use `--severity-threshold HIGH` to focus on critical issues
3. **CI optimization** - Use JSON output and parse programmatically

## What's Next?

After running the scanner, you should:
1. Review the HTML report for visualization
2. Prioritize CRITICAL and HIGH severity issues
3. Follow the remediation guidance
4. Re-scan after fixes
5. Integrate into your development workflow

---

**Total time to get started: ~10 minutes**

Happy scanning!
