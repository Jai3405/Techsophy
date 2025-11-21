"""Setup configuration for DevOps Security Vulnerability Scanner."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="security-vulnerability-scanner",
    version="1.0.0",
    author="Techsophy Candidate",
    author_email="candidate@example.com",
    description="DevOps Security Vulnerability Scanner with ML-powered prioritization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/security-vulnerability-scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        "bandit>=1.7.5",
        "safety>=3.0.0",
        "docker>=7.0.0",
        "scikit-learn>=1.3.0",
        "pandas>=2.1.0",
        "numpy>=1.24.0",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "joblib>=1.3.0",
        "plotly>=5.17.0",
        "rich>=13.6.0",
        "tqdm>=4.66.0",
        "jinja2>=3.1.2",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.10.0",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-scanner=src.main:main",
        ],
    },
)
