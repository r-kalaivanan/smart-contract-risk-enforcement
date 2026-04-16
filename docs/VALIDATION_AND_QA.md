# ✅ Validation and Quality Assurance in SC-GUARD

This document summarizes how SC-GUARD is validated and how quality is assured across:

- Static analysis and feature extraction
- Machine learning models
- Dataset and labels
- Command-line/API behavior
- CI workflows, style, and security checks

The goal is to show that SC-GUARD is not just a prototype, but a **tested, measurable, and reproducible** system.

---

## 1. Test Strategy Overview

SC-GUARD combines multiple layers of validation:

- **Unit and integration tests** (pytest) for analyzers and core logic
- **Static linting and formatting checks** (flake8, black)
- **Cross-validation and test-set evaluation** for ML models
- **End-to-end contract scans** on known vulnerable/safe contracts
- **Continuous Integration (CI)** across multiple OS / Python versions
- **Model-level evaluation scripts** for regression checks

The combination of these mechanisms provides defense-in-depth against regressions.

---

## 2. Automated Testing (pytest)

### 2.1 Test Suite

- Location: [tests](../tests)
- Example: [tests/test_slither_analyzer.py](../tests/test_slither_analyzer.py)
- Tests cover:
  - Successful initialization and execution of the `SlitherAnalyzer`
  - Correct extraction of features from known vulnerable Solidity contracts
  - Basic sanity checks on call graph and feature counts

The test suite is run automatically in CI (see Section 5) and can also be run locally:

```bash
pytest tests/ -v --cov=src --cov-report=term
```

### 2.2 Coverage

- Command: `pytest tests/ -v --cov=src --cov-report=xml --cov-report=term`
- Purpose:
  - Ensure core logic in `src/` is exercised by automated tests
  - Produce `coverage.xml` for integration with Codecov and CI quality gates

While not every path is covered, this provides **baseline regression protection** for analyzers and utilities.

---

## 3. Static Analysis, Linting, and Formatting

### 3.1 Linting with flake8

Configured in [ .github/workflows/test.yml ](../.github/workflows/test.yml):

```bash
flake8 src/ --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 src/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
```

This ensures:

- **No syntax errors or undefined names** enter the codebase
- Cyclomatic complexity is bounded (`--max-complexity=10`)
- Style violations are reported to keep the codebase readable

### 3.2 Formatting with black

Also in CI:

```bash
black --check src/
```

- Enforces a **consistent code style**.
- `--check` mode fails if files are not formatted, preventing drift.

These checks run automatically on every push and pull request, alongside tests.

---

## 4. Machine Learning Model Validation

Validation of ML models is handled in multiple scripts and modules:

- Training: [scripts/train_models.py](../scripts/train_models.py)
- Model class and evaluation: [src/ml/train_model.py](../src/ml/train_model.py)
- Quick and improved training experiments:
  - [scripts/train_quick_improved.py](../scripts/train_quick_improved.py)
  - [scripts/train_improved_ac_model.py](../scripts/train_improved_ac_model.py)
- Global evaluation: [scripts/evaluate_all_models.py](../scripts/evaluate_all_models.py)

### 4.1 Train/Test Split and Cross-Validation

Dataset preparation (see [docs/QUICKSTART.md](../docs/QUICKSTART.md)) creates:

- `outputs/train_dataset.csv` — ~80% of labeled contracts (training)
- `outputs/test_dataset.csv` — ~20% (held-out test set)

In [scripts/train_models.py](../scripts/train_models.py):

- For each vulnerability type (`reentrancy`, `access_control`, `unchecked_external_call`, `dangerous_construct`):
  - A `VulnerabilityClassifier` (Random Forest) is trained on `X_train, y_train`.
  - **5-fold cross-validation** is used on the training set via `cross_val_score(..., cv=5, scoring='f1')`.
  - This guards against overfitting and gives a more reliable estimate of generalization.

### 4.2 Test-Set Evaluation

Still in `train_single_model` (train_models.py):

- After training, the model is evaluated on `X_test, y_test` using:
  - Accuracy
  - Precision
  - Recall
  - F1 Score
  - Confusion Matrix
  - ROC-AUC (when both classes are present)

Implementation: [src/ml/train_model.py](../src/ml/train_model.py) `VulnerabilityClassifier.evaluate`:

- Uses `precision_recall_fscore_support`, `confusion_matrix`, and `roc_auc_score`.
- Prints a structured summary for each model:
  - `Accuracy`, `Precision`, `Recall`, `F1 Score`, `ROC-AUC` (if defined)
  - Confusion matrix (TP, FP, TN, FN)

### 4.3 Global Evaluation of All Models

The script [scripts/evaluate_all_models.py](../scripts/evaluate_all_models.py) provides a **unified regression check**:

- Loads `outputs/test_dataset.csv`.
- For each model:
  - Loads the corresponding `.pkl` from `models/`.
  - Computes **F1, Precision, Recall, ROC-AUC** on the test set.
  - Counts the number of positive/negative samples used.
  - Assigns a qualitative status: `EXCELLENT`, `GOOD`, `MODERATE`, or `NEEDS IMPROVEMENT`.
- Prints a summary table and an **overall rating** based on average F1.

This script is ideal to:

- Detect regressions after code or feature changes
- Confirm that retrained models still meet target metrics

### 4.4 Advanced Access-Control Model Validation

The script [scripts/train_improved_ac_model.py](../scripts/train_improved_ac_model.py) adds additional QA for the **access control** model:

- Uses **SMOTE** for class balancing.
- Uses `GridSearchCV` with `StratifiedKFold(n_splits=5)` and scoring=`'f1'`.
- Reports:
  - Best hyperparameters and best cross-validated F1
  - Classification report on the **original test set**
  - Detailed confusion matrix and key metrics (F1, ROC-AUC)
  - Top 10 most important features (feature importance analysis)

This demonstrates a more rigorous **model selection and evaluation pipeline** for the hardest class.

### 4.5 Quick Iteration Experiments

The script [scripts/train_quick_improved.py](../scripts/train_quick_improved.py):

- Tries multiple training strategies quickly:
  - Different rebalancing and hyperparameter strategies
  - Each strategy uses 5-fold cross-validation (F1) and test-set F1.
- Selects and reports the **best strategy + model**, including cross-validation and test-set scores.

This is useful for rapid experimentation while still enforcing basic validation discipline.

---

## 5. Dataset and Label Quality

Dataset curation is based on the **SmartBugs Curated** dataset:

- Location: [datasets/smartbugs-curated](../datasets/smartbugs-curated)
- Ground truth: [datasets/smartbugs-curated/vulnerabilities.json](../datasets/smartbugs-curated/vulnerabilities.json)

Key aspects:

- Contracts are labeled by vulnerability category (e.g., reentrancy, access control, unchecked low-level calls, etc.).
- The script [scripts/build_dataset.py](../scripts/build_dataset.py):
  - Converts raw contracts + labels into ML-ready CSVs.
  - Produces **train/test splits** as described above.

Label handling and encoding logic:

- Implemented in [src/data/label_encoder.py](../src/data/label_encoder.py) and [src/data/label_generator.py](../src/data/label_generator.py).
- Encodes multi-label vulnerabilities into individual binary targets:
  - `label_reentrancy`
  - `label_access_control`
  - `label_unchecked_external_call`
  - `label_dangerous_construct`

By building directly from a well-known academic dataset and keeping the preprocessing scripts under version control, SC-GUARD ensures **transparent and reproducible labeling**.

---

## 6. End-to-End Behavioral Testing

Beyond unit tests and model-level metrics, SC-GUARD validates **real user flows**.

### 6.1 CLI and API Smoke Tests

In [ .github/workflows/test.yml ](../.github/workflows/test.yml):

- CLI help and version commands:

```bash
sc-guard --help
sc-guard version
```

- Sample scan on a known vulnerable contract (Linux runner):

```bash
sc-guard scan test_contracts/ReentrancyVulnerable.sol --json > test_output.json
```

These checks validate that:

- The package installs correctly (`pip install -e .`).
- The CLI entrypoint works on **all supported OSes**.
- At least one end-to-end scan (parsing → feature extraction → model inference → JSON output) succeeds in CI.

### 6.2 Manual / Scripted Test Contracts

Additional testing is performed via [scripts/test_models.py](../scripts/test_models.py):

- Runs trained models on sample contracts such as:
  - [test_contracts/ComplexVulnerable.sol](../test_contracts/ComplexVulnerable.sol)
  - Other vulnerable patterns (reentrancy, tx.origin, unchecked calls, dangerous constructs).
- Prints per-model predictions and probabilities, plus an overall risk level.

This serves as a **manual regression check** and a demonstration of how SC-GUARD behaves on realistic inputs.

---

## 7. Continuous Integration (CI) Pipeline

The GitHub Actions workflow [ .github/workflows/test.yml ](../.github/workflows/test.yml) defines the main QA pipeline:

### 7.1 Multi-OS, Multi-Python Matrix

- OS: `ubuntu-latest`, `windows-latest`, `macos-latest`
- Python: `3.9`, `3.10`, `3.11`

This ensures compatibility and catches environment-specific issues early.

### 7.2 Steps in CI

1. **Checkout & Python setup**
2. **Dependency installation** (`pip install -r requirements.txt` + `pip install -e .`)
3. **System dependencies** for Solidity compiler:
   - `solc` via `apt` on Linux
   - `solidity` via `brew` on macOS
4. **Linting with flake8** (strict + relaxed pass)
5. **Format check with black**
6. **Run pytest** with coverage and generate `coverage.xml`
7. **Upload coverage to Codecov** (for a representative matrix entry)
8. **CLI smoke tests** (`sc-guard --help`, `sc-guard version`)
9. **Sample scan** on a real contract (Linux)
10. **Upload artifacts** (coverage + test output) for inspection

These steps run automatically on:

- `push` to `main` and `develop`
- `pull_request` targeting `main` or `develop`
- Manual trigger via `workflow_dispatch`

This gives continuous feedback on code health and prevents untested changes from being merged silently.

---

## 8. Security and Static Analysis QA

Although SC-GUARD itself is a static analysis tool, the implementation also receives basic security-focused QA:

- **Solidity compiler availability** is checked in CI to ensure Solidity analysis paths remain functional.
- **Slither-based analyzers** are indirectly validated via tests and sample scans.
- The contract test set includes **intentionally vulnerable contracts** (e.g., reentrancy, unchecked low-level calls, dangerous constructs), ensuring the tool can flag known issues.

While a full-fledged formal verification of SC-GUARD itself is out of scope, these measures help ensure that:

- Static analysis results remain stable across environments
- Obvious regressions in detection logic are caught early

---

## 9. Reproducibility and Experiment Tracking

Reproducibility is an important aspect of quality assurance:

- **Deterministic feature extraction**:
  - Implemented in [src/analyzers/ast_extractor.py](../src/analyzers/ast_extractor.py) and [src/analyzers/graph_builder.py](../src/analyzers/graph_builder.py).
  - Same contract code → same feature vector.

- **Version-controlled scripts**:
  - Data building: [scripts/build_dataset.py](../scripts/build_dataset.py)
  - Training: [scripts/train_models.py](../scripts/train_models.py)
  - Evaluation: [scripts/evaluate_all_models.py](../scripts/evaluate_all_models.py)

- **Model artifacts**:
  - Stored under [models](../models) as `.pkl` files.
  - Their performance characteristics are documented in [docs/MODEL_PERFORMANCE_SUMMARY.md](../docs/MODEL_PERFORMANCE_SUMMARY.md) and [docs/PROJECT_SUMMARY.md](../docs/PROJECT_SUMMARY.md).

Anyone can reproduce results by following [docs/QUICKSTART.md](../docs/QUICKSTART.md):

1. Build dataset
2. Train models
3. Evaluate and compare metrics
4. Run end-to-end scans on example contracts

---

## 10. Limitations and Future QA Improvements

Current QA gives strong guarantees for a student/academic-grade project, but there is room for further hardening:

- **Additional unit tests**
  - More direct tests for feature extraction edge cases and call graph construction.
- **Integration tests for the REST API**
  - Automated tests hitting the FastAPI endpoints under [api](../api).
- **Property-based tests**
  - Use tools like `hypothesis` to generate arbitrary feature vectors or small contract snippets and assert invariants (e.g., monotonic risk scores).
- **Performance regression tests**
  - Measure runtime per contract and track over time to ensure scalability.

Despite these limitations, the existing **multi-layered QA stack** (tests, CI, metrics, and dataset transparency) already provides a solid foundation for trusting SC-GUARD’s behavior.
