<div align="center">

# 🛡️ DevOps Security Vulnerability Scanner

### **AI-Powered Security Intelligence Platform**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![ML Powered](https://img.shields.io/badge/ML-RandomForest-success.svg)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Enterprise-Grade Security Scanning | ML-Driven Risk Assessment | Intelligent Prioritization**

[Features](#-key-features) • [Demo](#-live-demo) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Documentation](#-documentation)

---

### 📹 **Live Demo**

https://github.com/user-attachments/assets/YOUR_VIDEO_ID

*Full walkthrough of the security scanner in action - from scan initiation to remediation insights*

---

</div>

## 🎯 **Overview**

A **production-ready security vulnerability scanner** that combines multi-dimensional scanning with cutting-edge machine learning to deliver actionable security insights. Built for **Techsophy** as a demonstration of advanced DevOps security practices, AI/ML integration, and full-stack development capabilities.

### **What Makes This Different?**

```
Traditional Scanners          →    This Platform
────────────────────────────────────────────────────────────
❌ Noisy alerts               ✅ ML-filtered results (93% accuracy)
❌ Binary severity            ✅ Multi-factor risk scoring
❌ No context                 ✅ Business impact analysis
❌ Generic fixes              ✅ Code-level remediation examples
❌ CLI only                   ✅ Beautiful web interface + REST API
```

---

## ✨ **Key Features**

<table>
<tr>
<td width="50%">

### 🔍 **Multi-Dimensional Scanning**
- **Code Analysis** - Bandit for Python security issues
- **Dependency Audit** - CVE detection in packages
- **Container Security** - Dockerfile best practices
- **Infrastructure Config** - K8s, Docker Compose, Terraform

### 🧠 **ML-Powered Intelligence**
- **Risk Scorer** - RandomForest (150 estimators)
- **False Positive Filter** - 93%+ accuracy
- **6D Feature Engineering** - Severity, confidence, exploitability
- **Trained on 2000+ samples** - Continuous improvement

</td>
<td width="50%">

### 🎯 **Smart Prioritization**
- **Multi-Factor Scoring** - Risk + Impact + Exploitability
- **Business Impact** - Data exposure, compliance, reputation
- **Remediation Complexity** - Ease of fix consideration
- **Threat Landscape** - Current exploit trends

### 🔧 **Actionable Remediation**
- **30+ Fix Patterns** - Vulnerability-specific guidance
- **Before/After Code** - Real code examples
- **Step-by-Step** - Clear remediation instructions
- **Reference Links** - OWASP, CWE documentation

</td>
</tr>
</table>

---

## 🖥️ **Beautiful Web Interface**

### Home - Scan Launcher
![Home Page](Interfaces/Screenshot%202025-11-23%20at%204.31.06%20AM.png)
*Professional dark theme with intuitive scan configuration*

### Scan Results - Success Card
![Scan Results](Interfaces/Screenshot%202025-11-23%20at%204.31.49%20AM.png)
*Animated success card with direct links to reports*

### Dashboard - Real-Time Monitoring
![Dashboard](Interfaces/Screenshot%202025-11-23%20at%204.32.27%20AM.png)
*Live scan status tracking with auto-refresh capability*

### Vulnerability Report - Interactive Analysis
![Vulnerability Report](Interfaces/Screenshot%202025-11-23%20at%204.32.46%20AM.png)
*Dark-themed HTML reports with Plotly visualizations*

### Detailed Findings - Severity Breakdown
![Report Details](Interfaces/Screenshot%202025-11-23%20at%204.33.17%20AM.png)
*Color-coded severity levels with distinct visual hierarchy*

### Remediation Guidance - Code Examples
![Remediation Guide](Interfaces/Screenshot%202025-11-23%20at%204.33.53%20AM.png)
*Actionable fix recommendations with code snippets*

---

## 🏗️ **System Architecture**

```mermaid
graph TB
    subgraph "User Interface Layer"
        A[Web Interface<br/>FastAPI + Jinja2]
        B[REST API<br/>OpenAPI/Swagger]
        C[CLI Interface<br/>Rich Console]
    end

    subgraph "Orchestration Layer"
        D[Main Scanner<br/>ThreadPoolExecutor]
    end

    subgraph "Scanner Layer"
        E1[Code Scanner<br/>Bandit]
        E2[Dependency Scanner<br/>Safety]
        E3[Container Scanner<br/>Dockerfile Analysis]
        E4[Infrastructure Scanner<br/>Config Validation]
    end

    subgraph "ML Intelligence Layer"
        F1[Risk Scorer<br/>RandomForest 150]
        F2[FP Filter<br/>93% Accuracy]
    end

    subgraph "Analysis Layer"
        G1[Impact Analyzer<br/>Business Context]
        G2[Prioritizer<br/>Multi-Factor Scoring]
        G3[Remediation Engine<br/>30+ Patterns]
    end

    subgraph "Output Layer"
        H1[Report Generator<br/>JSON + HTML]
        H2[Dashboard<br/>Real-Time Updates]
    end

    A --> D
    B --> D
    C --> D

    D --> E1
    D --> E2
    D --> E3
    D --> E4

    E1 --> F1
    E2 --> F1
    E3 --> F1
    E4 --> F1

    F1 --> F2
    F2 --> G1
    G1 --> G2
    G2 --> G3

    G3 --> H1
    G3 --> H2

    style A fill:#7aa2f7
    style B fill:#7aa2f7
    style C fill:#7aa2f7
    style F1 fill:#9ece6a
    style F2 fill:#9ece6a
    style H1 fill:#bb9af7
    style H2 fill:#bb9af7
```

---

## 🚀 **Quick Start**

### Prerequisites
```bash
Python 3.9+
pip (package manager)
Git
```

### Installation

```bash
# Clone the repository
git clone https://github.com/Jai3405/Techsophy.git
cd Techsophy/security-vulnerability-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Usage Options

<table>
<tr>
<td width="50%">

#### **🌐 Web Interface** (Recommended)
```bash
# Start the web server
python app.py

# Open browser
http://localhost:8000
```

**Features:**
- Visual scan configuration
- Real-time progress tracking
- Interactive reports
- REST API access

</td>
<td width="50%">

#### **⌨️ Command Line**
```bash
# Quick scan
python demo.py

# Custom scan
python -m src.main \
  --repo-path ./my-app \
  --scan-types code dependency \
  --severity-threshold HIGH
```

**Use Cases:**
- CI/CD integration
- Automated testing
- Batch processing
- Scripting

</td>
</tr>
</table>

---

## 📊 **ML Models Performance**

### Risk Scorer Model
```
Algorithm:     RandomForestClassifier
Estimators:    150 trees
Max Depth:     10 levels
Features:      6 dimensions
Training Size: 2000+ samples
Accuracy:      ~85%
Precision:     0.87
Recall:        0.83
F1-Score:      0.85
```

### False Positive Filter
```
Algorithm:     RandomForestClassifier
Optimization:  Precision-focused
Class Weights: {genuine: 1, FP: 2}
Threshold:     0.7
Accuracy:      93%+
False Negatives: <5% (critical for security)
```

### Feature Engineering
| Feature | Range | Weight | Impact |
|---------|-------|--------|--------|
| Severity Level | 0-4 | High | ⭐⭐⭐⭐⭐ |
| Confidence Score | 1-3 | High | ⭐⭐⭐⭐ |
| Exploitability | 0-10 | High | ⭐⭐⭐⭐⭐ |
| Asset Value | 0-10 | Medium | ⭐⭐⭐ |
| Exposure Level | 0-10 | Medium | ⭐⭐⭐ |
| Type Hash | 0-N | Low | ⭐⭐ |

---

## 🎯 **Prioritization Algorithm**

The platform uses a **multi-factor weighted scoring system**:

```python
Priority Score = (
    Risk Score × 0.40 +           # ML-predicted risk
    Business Impact × 0.25 +      # Data, compliance, reputation
    Exploitability × 0.20 +       # Ease of exploitation
    Remediation Ease × 0.10 +     # Fix complexity (inverted)
    Threat Landscape × 0.05       # Current exploit trends
)
```

### Business Impact Factors
- **Data Exposure Risk** - Potential for data breach (GDPR, PCI-DSS)
- **Availability Impact** - Service disruption potential
- **Compliance Violations** - Regulatory requirements (HIPAA, SOC 2)
- **Reputation Damage** - Brand and customer trust impact

---

## 📁 **Project Structure**

```
security-vulnerability-scanner/
│
├── 🌐 Web Application
│   ├── app.py                      # FastAPI server
│   ├── templates/                  # Jinja2 templates
│   │   ├── index.html             # Home page
│   │   └── dashboard.html         # Monitoring dashboard
│   └── Interfaces/                # UI screenshots & demo video
│
├── 🧠 Core Scanner
│   ├── src/
│   │   ├── main.py                # Main orchestrator
│   │   ├── scanners/              # Vulnerability scanners
│   │   │   ├── code_scanner.py
│   │   │   ├── dependency_scanner.py
│   │   │   ├── container_scanner.py
│   │   │   └── infrastructure_scanner.py
│   │   │
│   │   ├── ml_models/             # Machine learning
│   │   │   ├── risk_scorer.py
│   │   │   ├── false_positive_filter.py
│   │   │   └── model_trainer.py
│   │   │
│   │   ├── analyzers/             # Intelligence layer
│   │   │   ├── prioritizer.py
│   │   │   ├── impact_analyzer.py
│   │   │   └── remediation_engine.py
│   │   │
│   │   └── utils/                 # Utilities
│   │       ├── logger.py
│   │       └── report_generator.py
│   │
├── 🧪 ML Training & Testing
│   ├── data/                      # Training data
│   │   ├── generate_dataset.py
│   │   └── training_data.csv
│   ├── models/                    # Trained models
│   │   ├── risk_scorer.joblib
│   │   └── fp_filter.joblib
│   ├── train_models.py           # Initial training
│   ├── improve_models.py         # Hyperparameter tuning
│   └── test_xgboost.py          # XGBoost experiments
│
├── 📝 Documentation
│   ├── docs/
│   │   ├── ARCHITECTURE.md
│   │   ├── API.md
│   │   ├── MODEL_IMPROVEMENTS.md
│   │   ├── SEVERITY_COLORS.md
│   │   └── WEB_INTERFACE_GUIDE.md
│   └── README.md                 # This file
│
├── ✅ Tests
│   ├── tests/
│   │   ├── test_scanners.py
│   │   ├── test_ml_models.py
│   │   └── test_integration.py
│   └── test_repo/                # Vulnerable test files
│
└── 🚀 Entry Points
    ├── demo.py                   # CLI demo script
    └── requirements.txt          # Dependencies
```

---

## 🔌 **REST API**

The platform exposes a full REST API with interactive documentation:

```bash
# Start API server
python app.py

# Access Swagger UI
http://localhost:8000/docs
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start new security scan |
| `GET` | `/api/scan/{job_id}` | Get scan status & results |
| `GET` | `/api/scans` | List all scans |
| `DELETE` | `/api/scan/{job_id}` | Delete scan |
| `GET` | `/api/reports` | List generated reports |
| `GET` | `/api/reports/{filename}` | Download report |
| `GET` | `/api/health` | Health check |

### Example Usage

```bash
# Start scan
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "repo_path=test_repo&scan_types=code,dependency&output_format=both"

# Check status
curl "http://localhost:8000/api/scan/{job_id}"

# Download report
curl "http://localhost:8000/api/reports/security_report_20251123.json" -o report.json
```

---

## 🧪 **Testing**

Comprehensive test suite with unit, integration, and ML validation tests:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test suite
pytest tests/test_scanners.py -v
pytest tests/test_ml_models.py -v
```

**Test Coverage:**
- ✅ Scanner functionality and edge cases
- ✅ ML model accuracy validation
- ✅ Integration workflow testing
- ✅ API endpoint testing
- ✅ Error handling and recovery

---

## 🎨 **Design Philosophy**

### Dark Theme with Muted Pastels
Inspired by modern developer tools (GitHub Dark, Vercel, Linear), the interface uses:

```css
Color Palette:
--bg-primary:    #1a1b26  (Deep Navy)
--bg-secondary:  #24283b  (Dark Slate)
--color-primary: #7aa2f7  (Muted Blue)
--color-success: #9ece6a  (Muted Green)
--color-warning: #e0af68  (Muted Amber)
--color-danger:  #f7768e  (Muted Red)
```

### Severity Color Hierarchy
```
🔴 CRITICAL  #f7768e  (Muted Red)    - Immediate action required
🟠 HIGH      #ff9e64  (Muted Orange) - High priority
🟡 MEDIUM    #e0af68  (Muted Amber)  - Should be addressed
🔵 LOW       #7aa2f7  (Muted Blue)   - Low risk
⚪ INFO      #565f89  (Muted Gray)   - Informational
```

---

## 💡 **Skills Demonstrated**

<table>
<tr>
<td width="50%">

### **🤖 AI/ML Engineering**
- RandomForest classification
- Feature engineering & selection
- Hyperparameter tuning
- False positive reduction
- Model persistence & versioning
- Synthetic data generation

### **💻 Full-Stack Development**
- FastAPI (async Python)
- Jinja2 templating
- REST API design
- OpenAPI documentation
- Responsive web design
- Real-time updates

### **🔒 Security Expertise**
- OWASP Top 10 knowledge
- CVE analysis
- Container security
- Infrastructure as Code security
- Compliance frameworks

</td>
<td width="50%">

### **🏗️ Software Architecture**
- Clean architecture
- SOLID principles
- Abstract base classes
- Dependency injection
- Plugin-style system
- Modular design

### **🧪 Quality Assurance**
- Unit testing (pytest)
- Integration testing
- Code coverage analysis
- Type hints (mypy)
- Code formatting (black)
- Linting (flake8)

### **⚡ Performance Optimization**
- Parallel execution (ThreadPoolExecutor)
- Async operations
- Efficient algorithms
- Resource management
- Progress tracking

</td>
</tr>
</table>

---

## 📈 **Roadmap & Future Enhancements**

- [ ] **Additional Language Support** - JavaScript, Go, Java, Rust
- [ ] **Cloud Integration** - AWS Security Hub, Azure Security Center
- [ ] **CI/CD Plugins** - Jenkins, GitLab CI, GitHub Actions
- [ ] **SARIF Export** - Standard format for security tools
- [ ] **Jira Integration** - Automatic ticket creation
- [ ] **Real-Time Monitoring** - Continuous security scanning
- [ ] **Multi-Tenancy** - Organization and team support
- [ ] **WebSocket Updates** - Real-time scan progress
- [ ] **Custom Rules Engine** - User-defined security patterns
- [ ] **Scheduled Scans** - Automated recurring scans

---

## 📚 **Documentation**

Comprehensive documentation available in the [`docs/`](docs/) directory:

- [Architecture Overview](docs/ARCHITECTURE.md) - System design and components
- [API Reference](docs/API.md) - REST API documentation
- [ML Model Details](docs/MODEL_IMPROVEMENTS.md) - Training and optimization
- [Web Interface Guide](docs/WEB_INTERFACE_GUIDE.md) - Using the web platform
- [Severity Colors](docs/SEVERITY_COLORS.md) - Visual hierarchy explanation

---

## 🤝 **Contributing & Feedback**

This project was built as an interview submission for **Techsophy**. For questions, feedback, or suggestions:

**Author:** Jayaditya Reddy
**Purpose:** Techsophy Interview Submission
**Date:** November 2025

---

## 📄 **License**

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **OWASP** - Security best practices and vulnerability knowledge
- **Bandit** - Python code security analysis
- **Safety** - Dependency vulnerability checking
- **scikit-learn** - Machine learning capabilities
- **FastAPI** - Modern web framework
- **Plotly** - Interactive visualizations
- **Rich** - Beautiful terminal output

---

<div align="center">

### **Built with ❤️ for Techsophy**

**Demonstrating:** Production-Ready Code • ML Engineering • Full-Stack Development • Security Expertise

[⬆ Back to Top](#️-devops-security-vulnerability-scanner)

</div>
