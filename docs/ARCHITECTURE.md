# Architecture Documentation

## System Design

The DevOps Security Vulnerability Scanner follows a modular, layered architecture designed for scalability, maintainability, and extensibility.

## Component Architecture

### Layer 1: Scanner Layer

**Responsibility:** Detect vulnerabilities from different sources

**Components:**
- `BaseScanner` - Abstract base class defining scanner interface
- `CodeScanner` - Analyzes Python source code using Bandit
- `DependencyScanner` - Checks package vulnerabilities using Safety
- `ContainerScanner` - Scans Dockerfiles for security issues
- `InfrastructureScanner` - Analyzes YAML/JSON config files

**Design Pattern:** Strategy Pattern - Each scanner implements the same interface but with different detection strategies.

### Layer 2: ML Model Layer

**Responsibility:** Apply machine learning for intelligent analysis

**Components:**
- `RiskScorer` - RandomForest model for vulnerability risk scoring
- `FalsePositiveFilter` - ML classifier to reduce false positives
- `ModelTrainer` - Training utilities and evaluation metrics

**Design Pattern:** Singleton-like behavior for model loading (models are loaded once and reused)

### Layer 3: Analysis Layer

**Responsibility:** Process and enrich vulnerability data

**Components:**
- `Prioritizer` - Multi-factor prioritization engine
- `RemediationEngine` - Provides fix guidance
- `ImpactAnalyzer` - Assesses business impact

**Design Pattern:** Chain of Responsibility - Each analyzer adds information to vulnerabilities sequentially

### Layer 4: Orchestration Layer

**Responsibility:** Coordinate the complete workflow

**Components:**
- `SecurityScanner` - Main orchestrator
- `CLI` - Command-line interface
- `ReportGenerator` - Output generation

**Design Pattern:** Facade Pattern - Provides simple interface to complex subsystem

## Data Flow

```
1. Input: Repository Path
   ↓
2. Scanner Selection (based on --scan-types)
   ↓
3. Parallel Scanning (ThreadPoolExecutor)
   ├─ Code Scanner → Vulnerabilities
   ├─ Dependency Scanner → Vulnerabilities
   ├─ Container Scanner → Vulnerabilities
   └─ Infrastructure Scanner → Vulnerabilities
   ↓
4. Vulnerability Aggregation
   ↓
5. ML Risk Scoring
   ├─ Feature Extraction
   ├─ Model Prediction
   └─ Risk Score Assignment
   ↓
6. False Positive Filtering
   ├─ Feature Extraction
   ├─ FP Probability Prediction
   └─ Filtering (threshold: 0.7)
   ↓
7. Business Impact Analysis
   ├─ Data Exposure Assessment
   ├─ Availability Impact
   ├─ Compliance Mapping
   └─ Reputation Risk
   ↓
8. Prioritization
   ├─ Multi-Factor Scoring
   ├─ Priority Level Assignment
   └─ Sorting by Priority
   ↓
9. Remediation Guidance
   ├─ Pattern Matching
   ├─ Fix Selection
   └─ Example Generation
   ↓
10. Report Generation
    ├─ JSON (complete data)
    └─ HTML (visualizations)
    ↓
11. Output: Reports + Console Summary
```

## Module Responsibilities

### src/scanners/

**BaseScanner**
- Defines scanner interface
- Provides utility methods (file reading, code snippet extraction)
- Defines `Vulnerability` dataclass

**CodeScanner**
- Executes Bandit on Python files
- Parses Bandit JSON output
- Maps test IDs to CWEs and descriptions
- Handles encoding issues

**DependencyScanner**
- Locates requirements files (requirements.txt, Pipfile, pyproject.toml)
- Runs Safety CLI
- Fallback to manual CVE database for known vulnerabilities
- Extracts fixed versions from advisories

**ContainerScanner**
- Parses Dockerfile syntax
- Checks for security anti-patterns (latest tag, root user, exposed ports)
- Detects hardcoded secrets in ENV
- Validates best practices (HEALTHCHECK, USER directive)

**InfrastructureScanner**
- Parses YAML/JSON configuration files
- Recursively searches for hardcoded credentials
- Detects insecure settings (debug mode, disabled SSL)
- Kubernetes and Docker Compose specific checks

### src/ml_models/

**RiskScorer**
- 6-dimensional feature extraction
- RandomForest classification (10 risk classes: 1-10)
- Feature importance calculation
- Model persistence with joblib

**FalsePositiveFilter**
- 5-dimensional feature extraction
- Binary classification (genuine vs false positive)
- Precision-optimized with class weights
- Threshold-based filtering

**ModelTrainer**
- Synthetic data generation for training
- Cross-validation utilities
- Model evaluation metrics
- Reusable training pipeline

### src/analyzers/

**Prioritizer**
- Composite scoring algorithm (weighted sum)
- Exploitability calculation based on CWE and type
- Ease of remediation estimation
- Threat landscape relevance (CVE age, trending)
- Priority level assignment (CRITICAL/HIGH/MEDIUM/LOW)

**RemediationEngine**
- Pattern database with 30+ entries
- CWE-specific remediation
- Before/after code examples
- Step-by-step instructions
- OWASP reference links

**ImpactAnalyzer**
- Multi-dimensional impact scoring
- Data exposure risk (based on file context)
- Availability impact (DoS potential)
- Compliance violation mapping
- Reputation damage assessment

### src/utils/

**Logger**
- Rich console output
- Structured logging
- Configurable verbosity

**ReportGenerator**
- JSON serialization
- HTML template rendering (Jinja2)
- Plotly chart generation
- Summary statistics

## Design Decisions

### 1. Parallel Scanner Execution

**Decision:** Use `ThreadPoolExecutor` for parallel scanning

**Rationale:**
- Scanners are I/O bound (file reading, subprocess execution)
- Threads provide good performance for I/O operations
- Simpler than multiprocessing for this use case
- Thread-safe vulnerability aggregation

### 2. ML Model Choice: RandomForest

**Decision:** Use RandomForestClassifier for both risk scoring and FP filtering

**Rationale:**
- Handles non-linear relationships well
- Robust to outliers
- Provides feature importance
- No need for feature scaling
- Good accuracy with moderate training data

### 3. Vulnerability Data Structure

**Decision:** Use dataclass with optional fields

**Rationale:**
- Type safety with Python type hints
- Easy serialization with `asdict()`
- Default values for optional fields
- Clear schema definition

### 4. Scanner Independence

**Decision:** Each scanner is completely independent

**Rationale:**
- Easy to add new scanners
- Scanners can fail without affecting others
- Parallel execution without shared state
- Clean separation of concerns

### 5. Remediation Pattern Database

**Decision:** Hardcoded dictionary of remediation patterns

**Rationale:**
- Fast lookup
- Version controlled with code
- Easy to extend
- No external dependencies
- Could be moved to JSON/YAML later if needed

## Scalability Considerations

### Horizontal Scalability
- Scanners can be distributed across multiple machines
- Results aggregated via message queue
- ML models can be served via REST API

### Performance Optimization
- Parallel scanner execution
- Lazy loading of ML models
- Caching of scan results
- Incremental scanning (only changed files)

### Memory Management
- Streaming file reading for large repositories
- Chunked vulnerability processing
- Model loaded once and reused

## Security Considerations

### Input Validation
- Path traversal prevention
- Command injection prevention in subprocess calls
- YAML/JSON parsing safety (safe_load)

### Secrets Management
- No credentials in code
- Environment variables for configuration
- Secrets excluded from reports

### Safe Execution
- Sandboxed subprocess execution
- Timeout limits on external tools
- Resource limits (file size, recursion depth)

## Integration Patterns

### CI/CD Integration
```yaml
# Example GitHub Actions
- name: Security Scan
  run: |
    python -m src.main --repo-path . --severity-threshold CRITICAL
```

### Pre-commit Hook
```bash
#!/bin/bash
python -m src.main --repo-path . --scan-types code
```

### API Integration (Future)
```python
from src.main import SecurityScanner

scanner = SecurityScanner(repo_path="./app")
results = scanner.scan()
# Process results programmatically
```

## Extension Points

### Adding New Scanners
1. Create class inheriting from `BaseScanner`
2. Implement `scan()` method
3. Return list of `Vulnerability` objects
4. Register in `src/scanners/__init__.py`
5. Add to `SecurityScanner._initialize_scanners()`

### Adding New Remediation Patterns
1. Add entry to `RemediationEngine._build_remediation_database()`
2. Include description, steps, code examples
3. Add OWASP/CWE references

### Custom ML Models
1. Inherit from base model classes
2. Implement required methods
3. Update model path in configuration
4. Retrain on domain-specific data

## Testing Strategy

### Unit Tests
- Each scanner tested independently
- ML models tested with known inputs
- Analyzers tested with synthetic data

### Integration Tests
- End-to-end workflow on test repository
- Report generation validation
- CLI argument parsing

### Test Data
- `test_repo/` contains intentionally vulnerable code
- Covers all vulnerability types
- Known expected results

## Performance Metrics

**Typical Scan Times (on test_repo):**
- Code Scanner: 0.5-1.5s
- Dependency Scanner: 0.3-0.8s
- Container Scanner: 0.1-0.2s
- Infrastructure Scanner: 0.1-0.3s
- ML Processing: 0.2-0.5s
- **Total: 1.5-3.5s**

**Memory Usage:**
- Base: ~50MB
- With ML models loaded: ~150MB
- Peak during scanning: ~200MB

## Future Enhancements

1. **Database Backend** - PostgreSQL for scan history
2. **REST API** - FastAPI endpoint for programmatic access
3. **Real-time Monitoring** - Watch mode for continuous scanning
4. **Multi-language Support** - JavaScript, Go, Java scanners
5. **Distributed Execution** - Celery task queue
6. **Advanced ML** - Deep learning for pattern recognition
7. **SARIF Output** - Standard format for tool interoperability
