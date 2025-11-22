#!/usr/bin/env python3
"""
Generate synthetic vulnerability dataset for training ML models.

This script creates realistic vulnerability training data based on:
- OWASP Top 10 patterns
- CWE (Common Weakness Enumeration) classifications
- CVSS scoring methodology
- Real-world vulnerability distributions
"""

import pandas as pd
import numpy as np
from pathlib import Path


def generate_vulnerability_dataset(n_samples: int = 2000, output_file: str = "training_data.csv"):
    """
    Generate synthetic vulnerability training dataset.

    Args:
        n_samples: Number of samples to generate
        output_file: Output CSV filename
    """
    np.random.seed(42)  # Reproducible results

    print(f"Generating {n_samples} synthetic vulnerability samples...")

    # Vulnerability type distribution (based on OWASP Top 10)
    vuln_types = [
        "sql_injection",
        "command_injection",
        "xss",
        "hardcoded_secret",
        "weak_crypto",
        "insecure_deserialization",
        "xxe",
        "missing_authentication",
        "broken_access_control",
        "security_misconfiguration",
        "vulnerable_dependency",
        "insecure_api",
        "path_traversal",
        "csrf",
        "ssrf",
    ]

    # Scanner types
    scanners = ["CodeScanner", "DependencyScanner", "ContainerScanner", "InfrastructureScanner"]

    # Severity distribution (realistic - more medium/low than critical)
    severity_weights = [0.15, 0.25, 0.35, 0.25]  # CRITICAL, HIGH, MEDIUM, LOW

    data = []

    for i in range(n_samples):
        # Select vulnerability type
        vuln_type = np.random.choice(vuln_types)

        # Select scanner (some vuln types more common in certain scanners)
        if vuln_type in ["vulnerable_dependency"]:
            scanner = "DependencyScanner"
        elif vuln_type in ["missing_healthcheck", "running_as_root"]:
            scanner = "ContainerScanner"
        elif vuln_type in ["hardcoded_credential", "security_misconfiguration"]:
            scanner = "InfrastructureScanner"
        else:
            scanner = "CodeScanner"

        # Severity (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
        severity = np.random.choice([4, 3, 2, 1], p=severity_weights)

        # Confidence (1=LOW, 2=MEDIUM, 3=HIGH)
        # Higher severity tends to have higher confidence
        if severity >= 3:
            confidence = np.random.choice([2, 3], p=[0.3, 0.7])
        else:
            confidence = np.random.choice([1, 2, 3], p=[0.2, 0.5, 0.3])

        # Vulnerability type encoding
        vuln_type_encoded = hash(vuln_type) % 100

        # Exploitability (0-10)
        # High severity vulnerabilities tend to be more exploitable
        if severity == 4:  # CRITICAL
            exploitability = np.random.beta(5, 2) * 10  # Skewed high
        elif severity == 3:  # HIGH
            exploitability = np.random.beta(4, 3) * 10
        elif severity == 2:  # MEDIUM
            exploitability = np.random.beta(3, 4) * 10
        else:  # LOW
            exploitability = np.random.beta(2, 5) * 10  # Skewed low

        # Asset value (0-10)
        # Depends on file type
        if scanner == "CodeScanner":
            # Higher for auth, payment, api files
            if np.random.random() < 0.3:  # 30% high-value files
                asset_value = np.random.uniform(7, 10)
            else:
                asset_value = np.random.uniform(4, 7)
        elif scanner == "DependencyScanner":
            asset_value = np.random.uniform(5, 8)
        elif scanner == "ContainerScanner":
            asset_value = np.random.uniform(6, 9)
        else:  # InfrastructureScanner
            asset_value = np.random.uniform(6, 9)

        # Exposure (0-10)
        # How exposed is this vulnerability to attackers
        if scanner in ["ContainerScanner", "InfrastructureScanner"]:
            exposure = np.random.uniform(6, 9)
        elif scanner == "DependencyScanner":
            exposure = np.random.uniform(5, 8)
        else:
            exposure = np.random.uniform(4, 8)

        # Calculate risk score (ground truth label)
        # Based on weighted formula (matches CVSS methodology)
        risk = (
            severity * 2.0
            + confidence * 0.5
            + exploitability * 0.3
            + asset_value * 0.15
            + exposure * 0.15
        )

        # Normalize to 0-9 range (10 classes for classification)
        risk_class = min(9, max(0, int(risk)))

        # False positive probability (for FP filter training)
        # Test files, low confidence findings are more likely FPs
        is_test_file = np.random.random() < 0.15  # 15% test files

        if is_test_file and confidence == 1:
            fp_probability = 0.7
        elif confidence == 1:
            fp_probability = 0.4
        elif confidence == 2:
            fp_probability = 0.2
        else:
            fp_probability = 0.05

        is_false_positive = np.random.random() < fp_probability

        data.append({
            "severity": severity,
            "confidence": confidence,
            "vuln_type": vuln_type,
            "vuln_type_encoded": vuln_type_encoded,
            "scanner": scanner,
            "exploitability": round(exploitability, 2),
            "asset_value": round(asset_value, 2),
            "exposure": round(exposure, 2),
            "risk_score": risk_class,
            "is_false_positive": int(is_false_positive),
            "is_test_file": int(is_test_file),
        })

    # Create DataFrame
    df = pd.DataFrame(data)

    # Save to CSV
    output_path = Path(__file__).parent / output_file
    df.to_csv(output_path, index=False)

    print(f"\n✓ Dataset saved to: {output_path}")
    print(f"\nDataset Statistics:")
    print(f"  Total samples: {len(df)}")
    print(f"\nSeverity Distribution:")
    severity_names = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    for sev, count in df["severity"].value_counts().sort_index().items():
        print(f"  {severity_names[sev]:8s}: {count:4d} ({count/len(df)*100:.1f}%)")

    print(f"\nScanner Distribution:")
    for scanner, count in df["scanner"].value_counts().items():
        print(f"  {scanner:20s}: {count:4d} ({count/len(df)*100:.1f}%)")

    print(f"\nRisk Score Distribution:")
    for risk, count in df["risk_score"].value_counts().sort_index().items():
        print(f"  Risk {risk}: {count:4d} ({count/len(df)*100:.1f}%)")

    print(f"\nFalse Positives: {df['is_false_positive'].sum()} ({df['is_false_positive'].sum()/len(df)*100:.1f}%)")

    return df


if __name__ == "__main__":
    # Generate dataset
    df = generate_vulnerability_dataset(n_samples=2000)

    print("\n" + "="*60)
    print("Dataset generation complete!")
    print("="*60)
    print("\nSample rows:")
    print(df.head(10).to_string())
