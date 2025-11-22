# Training Dataset

This directory contains the synthetic vulnerability dataset used to train the ML models.

## Files

- **`training_data.csv`** - 2000 synthetic vulnerability samples
- **`generate_dataset.py`** - Script to regenerate the dataset

## Dataset Description

The dataset contains realistic vulnerability data based on:
- OWASP Top 10 security risks
- CWE (Common Weakness Enumeration) classifications
- CVSS scoring methodology
- Real-world vulnerability distributions from security research

### Features

| Column | Description | Type | Range |
|--------|-------------|------|-------|
| `severity` | Vulnerability severity level | int | 0-4 (INFO, LOW, MEDIUM, HIGH, CRITICAL) |
| `confidence` | Scanner confidence level | int | 1-3 (LOW, MEDIUM, HIGH) |
| `vuln_type` | Type of vulnerability | string | sql_injection, xss, etc. |
| `vuln_type_encoded` | Encoded vulnerability type | int | 0-100 |
| `scanner` | Scanner that detected it | string | CodeScanner, DependencyScanner, etc. |
| `exploitability` | How exploitable (0-10) | float | 0.0-10.0 |
| `asset_value` | Value of affected asset | float | 0.0-10.0 |
| `exposure` | Exposure to attackers | float | 0.0-10.0 |
| `risk_score` | Overall risk score (label) | int | 0-9 |
| `is_false_positive` | Is it a false positive | int | 0 or 1 |
| `is_test_file` | Found in test file | int | 0 or 1 |

### Statistics

- **Total Samples**: 2,000
- **Severity Distribution**:
  - CRITICAL: ~14%
  - HIGH: ~26%
  - MEDIUM: ~37%
  - LOW: ~23%

- **Scanner Distribution**:
  - CodeScanner: ~87%
  - DependencyScanner: ~7%
  - InfrastructureScanner: ~6%

- **False Positives**: ~16% (realistic rate)

## Regenerating the Dataset

To regenerate the dataset with different parameters:

```bash
cd data/
python generate_dataset.py
```

This will create a new `training_data.csv` file with 2000 samples.

To generate a different number of samples, edit the script:

```python
df = generate_vulnerability_dataset(n_samples=5000)  # Generate 5000 samples
```

## Training Models

After regenerating the dataset, retrain the models:

```bash
cd ..
python train_models.py
```

This will train both the Risk Scorer and False Positive Filter models and save them to the `models/` directory.

## Data Quality

The synthetic data is designed to be realistic:

1. **Severity-Exploitability Correlation**: High severity vulnerabilities have higher exploitability
2. **Scanner-Specific Distributions**: Different scanners find different vulnerability types
3. **Realistic Noise**: 16% false positive rate mimics real security tools
4. **Beta Distributions**: Used for exploitability to create realistic skews
5. **CVSS-Based Scoring**: Risk calculation follows CVSS methodology

## Why Synthetic Data?

Real vulnerability datasets contain:
- Proprietary code that can't be shared
- Sensitive security information
- Privacy concerns

Synthetic data allows us to:
- Share the complete training pipeline
- Reproduce results exactly (seed=42)
- Train models without data licensing issues
- Demonstrate ML engineering skills

## Citation

If using this dataset generation approach, please cite:

```
Techsophy Security Vulnerability Scanner
Synthetic Vulnerability Dataset Generator
Based on OWASP Top 10 and CWE classifications
```
