# SC-GUARD

**Smart Contract Vulnerability Detection and Risk-Aware Enforcement System**

A command-line tool that analyzes Solidity smart contracts using static analysis and interpretable machine learning to detect vulnerabilities and enforce deployment policies.

## Overview

**Academic Research Project**  
**Domain**: Blockchain Security, Smart Contract Analysis  
**Approach**: Static Analysis + Classical ML

### Core Principles

- **Static-first**: Slither + AST provides deterministic security signals
- **ML refinement**: Random Forest reduces false positives and assigns risk probabilities
- **Explainable**: Feature importance and clear justifications for all decisions
- **Interpretable**: No deep learning or black-box models

## Vulnerability Detection

SC-GUARD detects **4 critical vulnerability types**:

| Vulnerability                | Description                                       | Example Attack                  |
| ---------------------------- | ------------------------------------------------- | ------------------------------- |
| **Reentrancy**               | External calls allow callback before state update | The DAO hack ($60M loss)        |
| **Unchecked External Calls** | call/send/delegatecall without return value check | Silent fund transfer failures   |
| **Access Control**           | Missing modifiers, tx.origin usage                | Unauthorized function execution |
| **Dangerous Constructs**     | tx.origin for auth, selfdestruct                  | Phishing, contract destruction  |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INPUT: Contract.sol                      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  STATIC ANALYSIS MODULE                                          │
│  ├─ Slither: Vulnerability detectors                            │
│  ├─ AST Extraction: External calls, state modifications         │
│  └─ Call Graph: Cycle detection (reentrancy indicator)          │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  FEATURE VECTOR (16 dimensions)                                  │
│  [external_calls, delegatecalls, state_writes, cycles, ...]     │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  MACHINE LEARNING MODULE                                         │
│  ├─ Random Forest (100 trees, max_depth=10)                     │
│  ├─ Multi-label classification (per vulnerability type)         │
│  └─ Output: Probabilities [0.0-1.0] for each vulnerability      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  RISK SCORING ENGINE                                             │
│  risk_score = Σ(probability × weight) / total_weight × 10       │
│  Weights: Reentrancy(3.0), Access Control(2.5), ...             │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  ENFORCEMENT POLICY                                              │
│  ├─ Risk 0-3:  ALLOW (Deploy safely)                            │
│  ├─ Risk 4-6:  WARN (Manual review recommended)                 │
│  └─ Risk 7-10: BLOCK (Prevent deployment)                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT: Decision + Justification + Recommendations              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Prerequisites

- **Python**: 3.8 or higher
- **Solidity Compiler**: solc (managed via solc-select)
- **OS**: Linux, macOS, or Windows

### 2. Installation

```bash
# Clone repository
git clone <repository-url>
cd sc-guard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Solidity compiler versions
solc-select install 0.4.25
solc-select install 0.8.0
solc-select use 0.8.0  # Set default

# Install sc-guard as CLI tool
pip install -e .
```

### 3. Basic Usage

```bash
# Analyze a single contract
sc-guard scan mycontract.sol

# Output as JSON
sc-guard scan mycontract.sol --json > report.json

# Verbose mode (show analysis steps)
sc-guard scan mycontract.sol --verbose

# Show version
sc-guard version
```

### 4. Train ML Models (After Dataset Preparation)

```bash
# Train on SmartBugs dataset
sc-guard train --dataset datasets/smartbugs-curated/ --output-dir models/

# Custom test split (default 30%)
sc-guard train --dataset datasets/ --test-split 0.2
```

---

## Project Structure

```
sc-guard/
├── src/
│   ├── analyzers/
│   │   ├── slither_analyzer.py     # Slither integration
│   │   ├── ast_extractor.py        # AST feature extraction
│   │   └── graph_builder.py        # Call graph analysis
│   ├── data/
│   │   ├── label_generator.py      # SmartBugs label parsing
│   │   └── feature_builder.py      # Dataset construction
│   ├── ml/
│   │   └── train_model.py          # Random Forest training
│   ├── scoring/
│   │   └── risk_engine.py          # Risk score calculation
│   ├── enforcement/
│   │   └── policy.py               # Deployment policy enforcement
│   ├── cli/
│   │   └── main.py                 # Command-line interface
│   └── utils/
│       ├── logger.py               # Logging utilities
│       ├── config.py               # Configuration management
│       └── file_utils.py           # File handling
├── datasets/
│   └── smartbugs-curated/          # SmartBugs vulnerable contracts
├── models/                         # Trained ML models (.pkl files)
├── outputs/                        # Analysis results (CSV, JSON)
├── config/
│   └── config.yaml                 # Configuration file
├── tests/                          # Unit tests (pytest)
├── docs/                           # Documentation
├── requirements.txt                # Python dependencies
├── setup.py                        # Package setup
└── README.md                       # This file
```

---

## Example Output

```bash
$ sc-guard scan vulnerable_dao.sol
```

```
┌───────────────────────────────────────────────────┐
│       sc-guard Smart Contract Scanner             │
└───────────────────────────────────────────────────┘
Analyzing: vulnerable_dao.sol

→ Running static analysis...
→ Running ML vulnerability detection...
→ Calculating risk score...
→ Applying enforcement policy...

╔═══════════════════════════════════════════════════╗
║  ✗ BLOCK                                          ║
║  Risk Score: 8.4/10 (CRITICAL)                    ║
╚═══════════════════════════════════════════════════╝

Detected Vulnerabilities:
  • reentrancy

Justification:
  Risk score 8.4/10 exceeds safety threshold. High probability
  of: reentrancy (85%). Deployment blocked to prevent potential
  exploits.

Recommendations:
  1. Implement checks-effects-interactions pattern
  2. Add ReentrancyGuard modifier from OpenZeppelin
  3. Use transfer() instead of call() for ETH transfers
  4. Review all functions with external calls
```

---

## Technical Details

### Feature Extraction (16 features)

| Feature                        | Type | Description                                     |
| ------------------------------ | ---- | ----------------------------------------------- |
| `external_call_count`          | int  | Number of call/send/transfer                    |
| `delegatecall_count`           | int  | Number of delegatecall                          |
| `state_writes_before_call`     | int  | State changes before external call              |
| `state_writes_after_call`      | int  | State changes after external call (reentrancy!) |
| `has_cycle_with_external_call` | bool | Call graph cycle with external call             |
| `uses_tx_origin`               | bool | tx.origin used for authentication               |
| `has_selfdestruct`             | bool | selfdestruct present                            |
| ...                            | ...  | (9 more features)                               |

### ML Model: Random Forest

**Why Random Forest?**

- Handles non-linear patterns (reentrancy is complex!)
- Feature importance for explainability
- Robust to outliers and missing data
- Works with small datasets (300-500 contracts)

**Hyperparameters**:

- `n_estimators=100` (100 decision trees)
- `max_depth=10` (prevent overfitting)
- `class_weight="balanced"` (handle class imbalance)

**Training Strategy**:

- Multi-label: Separate model per vulnerability type
- Train/test split: 70/30
- Cross-validation: 5-fold

**Evaluation Metrics**:

- Precision, Recall, F1-score
- ROC-AUC
- Confusion matrix

---

## Dataset

**Source**: [SmartBugs Curated Dataset](https://github.com/smartbugs/smartbugs-curated)

**Statistics**:

- **Vulnerable Contracts**: 143 (SmartBugs)
- **Safe Contracts**: ~200 (verified contracts from Etherscan)
- **Total**: ~350 contracts
- **Solidity Versions**: 0.4.x - 0.8.x

**Labels**: 5 binary labels per contract

- `reentrancy`
- `unchecked_external_call`
- `access_control`
- `dangerous_construct`
- `overall_vulnerable`

---

## Development Roadmap

### Phase 1: Dataset Collection (Completed)

- SmartBugs dataset integration
- Vulnerability metadata parsing

### Phase 2: Static Analysis (In Progress)

- Slither integration
- AST feature extraction
- Call graph analysis

### Phase 3-9: Remaining Tasks

- [ ] Dataset labeling and feature construction
- [ ] ML model training and evaluation
- [ ] Risk scoring engine
- [ ] Enforcement policy implementation
- [ ] CLI refinement
- [ ] Unit testing (pytest)
- [ ] Documentation and final report

---

## Technology Stack

| Component       | Technology   | Purpose                               |
| --------------- | ------------ | ------------------------------------- |
| Static Analysis | Slither      | Vulnerability detection, AST access   |
| Graph Analysis  | NetworkX     | Call graph, cycle detection           |
| ML Framework    | scikit-learn | Random Forest, Logistic Regression    |
| CLI Framework   | Click        | Command-line interface                |
| Terminal UI     | Rich         | Colored output, tables, progress bars |
| Testing         | pytest       | Unit tests                            |
| Language        | Python 3.8+  | Core implementation                   |

---

## Configuration

Edit [config/config.yaml](config/config.yaml) to customize:

```yaml
# Risk thresholds
risk_thresholds:
  allow: 3.0 # ALLOW if risk ≤ 3.0
  warn: 7.0 # WARN if 3.0 < risk ≤ 7.0, BLOCK if risk > 7.0

# Vulnerability weights for risk calculation
vulnerability_weights:
  reentrancy: 3.0
  unchecked_external_call: 2.0
  access_control: 2.5
  dangerous_construct: 2.5
```

---

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/test_slither_analyzer.py
```

---

## Academic Context

**Project Type**: Final-year undergraduate research project  
**Timeline**: January 2026 - May 2026 (4-5 months)  
**Contribution**: Combines static analysis with interpretable ML for vulnerability detection

**Key Differentiators**:

1. **Static-first approach**: ML refines, doesn't replace static analysis
2. **Explainability**: Feature importance + clear justifications
3. **Risk-aware enforcement**: Not just detection, but actionable decisions
4. **Semester-feasible**: Classical ML, no GPUs or large datasets required

---

## Contributing

This is an academic project. Contributions, suggestions, and feedback are welcome!

---

## License

See [LICENSE](LICENSE) file.

---

## Acknowledgments

- **SmartBugs Team**: Curated vulnerability dataset
- **Trail of Bits**: Slither static analysis framework
- **OpenZeppelin**: Secure contract patterns and best practices

---

**Built for blockchain security**
