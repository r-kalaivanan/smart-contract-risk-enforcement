# 🤖 Machine Learning and Risk Scoring in SC-GUARD

This chapter explains how SC-GUARD uses classical machine learning to detect smart contract vulnerabilities and how it converts model outputs into a unified **0–10 risk score** for decision-making.

It covers:

- ML design choices and model architecture
- The four vulnerability-specific classifiers
- Training and evaluation pipeline
- How predictions are turned into probabilities
- How the risk engine aggregates probabilities into a numeric score and category
- How this risk score is used in enforcement and reporting

---

## 1. Design Philosophy: Why Classical ML?

The ML component is implemented in [src/ml/train_model.py](../src/ml/train_model.py) and related scripts under [scripts](../scripts).

SC-GUARD deliberately uses **classical machine learning** (Random Forest, Logistic Regression) instead of deep learning.

### 1.1 Rationale

From the module docstring in `train_model.py`:

- **Explainability**
  - Random Forests expose **feature importances**, which map directly to code patterns (e.g., `state_writes_after_call`).
- **Data Efficiency**
  - Works well with **hundreds** of contracts (SmartBugs scale), whereas deep learning would need thousands.
- **Speed and Simplicity**
  - Training completes in seconds on CPU.
  - No GPUs, simpler to debug and reproduce.
- **Project Scope**
  - Fits academic/semester constraints while providing meaningful results.

---

## 2. Model Architecture: One Classifier per Vulnerability

SC-GUARD trains **four independent binary classifiers**, all using the same 16-dimensional feature vector described in [docs/ML_COMPONENT_EXPLAINED.md](../docs/ML_COMPONENT_EXPLAINED.md):

- `reentrancy_rf.pkl` — Reentrancy detection
- `access_control_rf.pkl` — Access-control issues
- `unchecked_external_call_rf.pkl` — Unchecked low-level calls
- `dangerous_construct_rf.pkl` — Dangerous patterns (e.g., `tx.origin`, `selfdestruct`)

Each classifier is an instance of the `VulnerabilityClassifier`:

- Implementation: [src/ml/train_model.py](../src/ml/train_model.py)

### 2.1 VulnerabilityClassifier Overview

Key responsibilities:

- Initialize the underlying ML model (`RandomForestClassifier` or `LogisticRegression`).
- Train on `(X_train, y_train)` where `X_train` are features and `y_train` are binary labels for one vulnerability.
- Predict binary labels on new contracts (`predict`).
- Predict probabilities for the positive class (`predict_proba`).
- Evaluate metrics (accuracy, precision, recall, F1, ROC-AUC, confusion matrix).
- Expose feature importance for interpretability.

### 2.2 Default Random Forest Configuration

When `model_type="random_forest"`, the classifier uses:

- `n_estimators=100` — 100 decision trees.
- `max_depth=10` — Limit depth to reduce overfitting.
- `min_samples_split=5` — Require at least 5 samples to split an internal node.
- `class_weight="balanced"` — Automatically handle class imbalance.
- `random_state=42` — Deterministic behavior.
- `n_jobs=-1` — Use all CPU cores during training.

Logistic Regression is also supported (primarily as a baseline) but Random Forest is the **primary production model**.

---

## 3. Training and Evaluation Pipeline

High-level training flow is orchestrated by [scripts/train_models.py](../scripts/train_models.py). See also [docs/ML_COMPONENT_EXPLAINED.md](../docs/ML_COMPONENT_EXPLAINED.md) and [docs/MODEL_PERFORMANCE_SUMMARY.md](../docs/MODEL_PERFORMANCE_SUMMARY.md).

### 3.1 Inputs

- Feature matrices `X_train`, `X_test` from [outputs/train_dataset.csv](../outputs/train_dataset.csv) and [outputs/test_dataset.csv](../outputs/test_dataset.csv).
- Label vectors `y_train`, `y_test` for each vulnerability:
  - `label_reentrancy`
  - `label_access_control`
  - `label_unchecked_external_call`
  - `label_dangerous_construct`

### 3.2 Per-Model Training

In `train_single_model` (train_models.py):

1. Instantiate a `VulnerabilityClassifier` with `model_type="random_forest"` and the appropriate `vulnerability_type`.
2. Call `clf.train(X_train, y_train)`:
   - Prints:
     - Number of training samples
     - Number of features
     - Positive class ratio (to expose class imbalance).
3. Perform **5-fold cross-validation** on the training set using `cross_val_score` (F1 scoring).
4. Evaluate on the **held-out test set**:
   - Print classification report.
   - Call `clf.evaluate(X_test, y_test)` to compute accuracy, precision, recall, F1, ROC-AUC, and confusion matrix.
5. Extract feature importance with `clf.get_feature_importance(feature_names)` for interpretability.
6. Save the fitted model as a `.pkl` file in [models](../models).

### 3.3 Global Evaluation Across Models

- Script: [scripts/evaluate_all_models.py](../scripts/evaluate_all_models.py)
- Purpose: Quick regression check across all four models.

For each model:

- Load model from `models/*.pkl`.
- Load features and labels from `outputs/test_dataset.csv`.
- Compute F1, Precision, Recall, ROC-AUC and print a summary.
- Classify model status as `EXCELLENT`, `GOOD`, `MODERATE`, or `NEEDS IMPROVEMENT`.
- Compute an **average F1** across models and provide an overall assessment.

This provides a compact view of ML performance that can be easily re-run after any feature or model change.

---

## 4. Prediction: From Features to Vulnerability Probabilities

During analysis (CLI or API), the feature extraction pipeline produces a feature vector for the target contract. The ML models then run inference.

### 4.1 End-to-End Inference Flow

Example: CLI flow in [src/cli/main.py](../src/cli/main.py):

1. Static analysis and feature extraction produce `features: ContractFeatures`.
2. Call graph metrics are added (e.g., `max_call_depth`, `has_cycle_with_external_call`).
3. Convert `features` to a NumPy vector via `features.to_vector()`.
4. Load each trained model from [models](../models):
   - `reentrancy_rf.pkl`
   - `access_control_rf.pkl`
   - `unchecked_external_call_rf.pkl`
   - `dangerous_construct_rf.pkl`
5. For each model:
   - `prediction = clf.predict(feature_vector)[0]` → binary label (0 = safe, 1 = vulnerable).
   - `probability = clf.predict_proba(feature_vector)[0]` → vulnerability probability.
6. Collect all probabilities into a dictionary, for example:

```python
{
  "reentrancy": 0.85,
  "access_control": 0.10,
  "unchecked_external_call": 0.32,
  "dangerous_construct": 0.05
}
```

These probabilities are then passed to the **risk scoring engine**.

---

## 5. Risk Scoring Engine

The risk engine converts vulnerability probabilities into a single, human-friendly **0–10 risk score** and qualitative risk category.

Implementation: [src/scoring/risk_engine.py](../src/scoring/risk_engine.py).

### 5.1 RiskAssessment Data Structure

The result of risk scoring is captured in the `RiskAssessment` dataclass:

- `overall_risk_score: float` — numeric score 0–10.
- `vulnerability_probabilities: Dict[str, float]` — per-vulnerability probabilities.
- `top_risk_factors: List[str]` — explanation strings (e.g., dominant vulnerabilities and important features).
- `confidence: float` — how decisive the predictions are (0–1).

### 5.2 Severity Weights

Different vulnerabilities have different security impact. The engine uses weights:

```python
VULNERABILITY_WEIGHTS = {
    "reentrancy": 3.0,
    "unchecked_external_call": 2.0,
    "access_control": 2.5,
    "dangerous_construct": 2.5,
}
```

- **Reentrancy (3.0)** — Critical class (e.g., The DAO hack).
- **Access Control (2.5)** — High impact (unauthorized control).
- **Dangerous Construct (2.5)** — High impact (`tx.origin`, `selfdestruct`).
- **Unchecked Call (2.0)** — Medium-high impact (silent failures, DoS).

Total weight ≈ 10, allowing an intuitive 0–10 risk scale.

### 5.3 Risk Score Formula

Core logic in `calculate_risk`:

1. Compute weighted sum of probabilities:

```python
weighted_sum = 0.0
for vuln_type, probability in vulnerability_probabilities.items():
    weight = self.VULNERABILITY_WEIGHTS.get(vuln_type, 1.0)
    weighted_sum += probability * weight
```

2. Normalize to 0–10:

```python
risk_score = (weighted_sum / self.total_weight) * 10
risk_score = min(max(risk_score, 0.0), 10.0)
risk_score = round(risk_score, 1)
```

3. Identify **top risk factors**:

- Vulnerability types with probability > 0.5 are highlighted.
- If feature importances are provided, the top 3 with importance > 0.1 are included.

4. Compute **confidence** based on how far each probability is from 0.5:

```python
distances = [abs(p - 0.5) for p in probabilities.values()]
confidence = np.mean(distances) / 0.5  # 0–1 scale
```

### 5.4 Example Calculation

If ML models output:

- `reentrancy`: 0.90
- `access_control`: 0.20
- `unchecked_external_call`: 0.10
- `dangerous_construct`: 0.00

Then the weighted contributions are:

- Reentrancy: `0.90 × 3.0 = 2.70`
- Access Control: `0.20 × 2.5 = 0.50`
- Unchecked Call: `0.10 × 2.0 = 0.20`
- Dangerous Construct: `0.00 × 2.5 = 0.00`

Total weighted sum = `3.40`. After normalization and rounding, the risk score is near the **upper end** of the scale (e.g., ~8–9/10), leading to a **HIGH or CRITICAL** category.

More detailed numeric examples and rounding explanations are given in [docs/RISK_CALCULATION_EXPLAINED.md](../docs/RISK_CALCULATION_EXPLAINED.md).

### 5.5 Risk Categories

`RiskScoringEngine.get_risk_category(risk_score)` maps numeric score to category:

- `< 3.0` → `LOW`
- `3.0–<5.0` → `MEDIUM`
- `5.0–<7.0` → `HIGH`
- `≥ 7.0` → `CRITICAL`

These categories are used in reporting and policy decisions.

---

## 6. Using Risk Scores in Enforcement and Reporting

Risk scores are consumed by downstream components to make high-level decisions.

### 6.1 Policy Enforcement

The policy engine (see [src/enforcement/policy.py](../src/enforcement/policy.py)) can:

- Define thresholds like:
  - `LOW` → Allow deployment.
  - `MEDIUM` → Require manual review.
  - `HIGH` / `CRITICAL` → Block deployment or require security sign-off.

This allows SC-GUARD to integrate with CI/CD pipelines and **gate deployments** based on quantified risk.

### 6.2 Reporting and CLI Output

CLI and API layers incorporate risk information into human-readable reports:

- Overall risk score (e.g., `Risk Score: 1.7/10 (LOW)`).
- Per-vulnerability probabilities.
- Top risk factors (vulnerabilities and features).

For detailed narrative explanations, see:

- [docs/PROJECT_DEMO_GUIDE.md](../docs/PROJECT_DEMO_GUIDE.md)
- [docs/ML_COMPONENT_EXPLAINED.md](../docs/ML_COMPONENT_EXPLAINED.md)
- [docs/RISK_CALCULATION_EXPLAINED.md](../docs/RISK_CALCULATION_EXPLAINED.md)

---

## 7. Limitations and Future Improvements

While SC-GUARD’s ML and risk scoring are effective for academic-scale analysis, there are natural limitations:

- **Data Size and Diversity**
  - Models are trained on a curated dataset (~137 contracts). Real-world diversity is much larger.
- **Static Feature Set**
  - Only 16 engineered features; may miss new vulnerability patterns.
- **Calibration**
  - Probabilities are not explicitly calibrated (e.g., via Platt scaling or isotonic regression).

### 7.1 Potential Enhancements

- Add probability calibration for better-aligned risk scores.
- Explore additional features (e.g., gas usage patterns, invariants).
- Periodically retrain with more recent contract datasets (e.g., mainnet verified contracts).
- Incorporate **uncertainty estimates** (e.g., via ensembles or Bayesian methods).

Despite these limitations, the current design provides a **transparent and interpretable** link from static analysis features to ML predictions and finally to a **single, actionable risk score**, making SC-GUARD suitable for educational use and early-stage security analysis.
