# 📊 Dataset Construction and Analysis in SC-GUARD

This chapter explains how SC-GUARD builds its machine learning dataset from real-world smart contracts, and how that dataset is analyzed and prepared for training and evaluation.

It covers:

- Data sources and licensing
- Label schema and vulnerability categories
- Feature extraction pipeline (static analysis → features)
- Dataset building script and output artifacts
- Train/test split strategy and label distributions
- Basic dataset analysis and class imbalance considerations
- Reproducibility and how to rebuild the dataset

---

## 1. Data Sources

### 1.1 SmartBugs Curated Dataset

SC-GUARD is built on top of the **SmartBugs Curated** dataset (ICSE 2020):

- Location in this project: [datasets/smartbugs-curated](../datasets/smartbugs-curated)
- Key files:
  - [datasets/smartbugs-curated/dataset](../datasets/smartbugs-curated/dataset) — Solidity contracts grouped by vulnerability category
  - [datasets/smartbugs-curated/vulnerabilities.json](../datasets/smartbugs-curated/vulnerabilities.json) — Ground-truth vulnerability labels
  - [datasets/smartbugs-curated/versions.csv](../datasets/smartbugs-curated/versions.csv) — Solidity compiler versions
  - [datasets/smartbugs-curated/ICSE2020_curated_69.txt](../datasets/smartbugs-curated/ICSE2020_curated_69.txt) — Curated contract list
  - [datasets/smartbugs-curated/README.md](../datasets/smartbugs-curated/README.md) — Dataset documentation

Characteristics:

- Real and synthetic Solidity contracts
- Labeled by known vulnerability categories (reentrancy, access control, unchecked low-level calls, etc.)
- Widely used in academic research, giving SC-GUARD a **transparent and reproducible** data foundation.

### 1.2 Licensing

- SmartBugs Curated ships with an MIT-style license (see [datasets/smartbugs-curated/LICENSE](../datasets/smartbugs-curated/LICENSE)).
- SC-GUARD respects this license and only uses the dataset for **research and educational** purposes.

---

## 2. Label Schema and Vulnerability Categories

SC-GUARD converts the rich labels from SmartBugs into four main **binary targets**, one per model:

- `label_reentrancy`
- `label_access_control`
- `label_unchecked_external_call`
- `label_dangerous_construct`

Label encoding is implemented under [src/data](../src/data):

- [src/data/label_encoder.py](../src/data/label_encoder.py)
- [src/data/label_generator.py](../src/data/label_generator.py)

### 2.1 Multi-Label to Binary Targets

Many contracts may contain **multiple vulnerabilities**. The label pipeline:

1. Reads vulnerability annotations from `vulnerabilities.json`.
2. Maps each contract to one or more vulnerability types.
3. Produces a **multi-label row**, with each label column set to `0` or `1`.

Example (conceptual row in `outputs/dataset.csv`):

- `contract_name`: `ReentrancyDAO.sol`
- `category`: `reentrancy`
- `label_reentrancy`: `1`
- `label_access_control`: `0`
- `label_unchecked_external_call`: `0`
- `label_dangerous_construct`: `0`

This structure allows SC-GUARD to train **separate classifiers** for each vulnerability type while still sharing the same feature space.

---

## 3. Feature Extraction Pipeline

Features are built via static analysis and graph analysis modules under [src/analyzers](../src/analyzers):

- Static analysis and AST: [src/analyzers/slither_analyzer.py](../src/analyzers/slither_analyzer.py)
- AST-based features: [src/analyzers/ast_extractor.py](../src/analyzers/ast_extractor.py)
- Call graph metrics: [src/analyzers/graph_builder.py](../src/analyzers/graph_builder.py)
- High-level feature container: `ContractFeatures` in `ast_extractor.py`

### 3.1 Steps Per Contract

For each Solidity file in the dataset:

1. **Static Analysis** (Slither)
   - Parse and compile with an appropriate Solidity version.
   - Build an **AST** (Abstract Syntax Tree).
   - Extract contract structure: functions, state variables, modifiers, visibility.

2. **AST Feature Extraction** (ASTFeatureExtractor)
   - Count external calls (`call`, `delegatecall`, `send`, `transfer`).
   - Analyze state writes **before vs. after** external calls (reentrancy risk).
   - Count public/external/private functions and modifiers.
   - Detect dangerous constructs: `tx.origin`, `selfdestruct`, unchecked calls.

3. **Call Graph Metrics** (CallGraphBuilder)
   - Build a directed function call graph.
   - Detect cycles and count external calls inside cycles.
   - Compute `max_call_depth`.

4. **Feature Vector Assembly**
   - All features are stored in a `ContractFeatures` dataclass and exported as a numeric vector.
   - Columns in `outputs/dataset.csv` use names like `feat_external_call_count`, `feat_has_cycle_with_external_call`, etc.

The entry point for this pipeline when building the dataset is the **FeatureBuilder** class.

- Implementation: [src/data/feature_builder.py](../src/data/feature_builder.py)

FeatureBuilder coordinates:

- Iterating over all contracts in `datasets/smartbugs-curated/dataset/`
- Running analysis and feature extraction
- Joining features with labels and metadata into a single `pandas.DataFrame`.

---

## 4. Dataset Builder Script

The script [scripts/build_dataset.py](../scripts/build_dataset.py) orchestrates the full **dataset construction** process.

### 4.1 High-Level Process

As documented in the script header:

1. Load contracts from `datasets/smartbugs-curated/`.
2. Extract features using `SlitherAnalyzer` + `ASTFeatureExtractor` (via `FeatureBuilder`).
3. Generate labels from `vulnerabilities.json`.
4. Save:
   - Full dataset
   - 80% training split
   - 20% test split

### 4.2 Key Implementation Details

Relevant code (simplified):

- Dataset path: `dataset_path = "datasets/smartbugs-curated"`
- Builder initialization:

  ```python
  builder = FeatureBuilder(dataset_path)
  df = builder.build_dataset()
  ```

- Error handling:
  - If dataset path is missing or the resulting DataFrame is empty, the script aborts with a clear error message.

- Reporting:
  - Total number of contracts processed.
  - Number of feature columns (`feat_*`).
  - Number of label columns (`label_*`).

### 4.3 Output Artifacts

The script writes to [outputs](../outputs):

- `outputs/dataset.csv`
  - Full dataset with one row per contract.
  - Columns include:
    - Metadata: `contract_name`, `category`, etc.
    - Features: `feat_*`
    - Labels: `label_*`

- `outputs/train_dataset.csv`
  - Approximately 80% of rows from `dataset.csv`.

- `outputs/test_dataset.csv`
  - Remaining ~20% of rows.

These CSVs are later used by [scripts/train_models.py](../scripts/train_models.py) and other training/evaluation scripts.

---

## 5. Train/Test Split Strategy

After building the full DataFrame `df`, the script performs a train/test split:

```python
train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df['category'] if 'category' in df.columns else None
)
```

### 5.1 Stratification by Category

- If the `category` column is available, the split is **stratified by category**.
- This keeps the proportion of contracts per vulnerability category similar in both train and test sets.

If stratification fails for any reason, the script falls back to a **random split** with the same `test_size` and `random_state`:

```python
train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42
)
```

### 5.2 Size Summary

The script prints the final split sizes, for example (numbers are illustrative):

- Training set: `N_train` samples (~80%) → `outputs/train_dataset.csv`
- Test set: `N_test` samples (~20%) → `outputs/test_dataset.csv`

This provides a quick sanity check that **all contracts** were included and that the split ratio is as expected.

---

## 6. Label Distributions and Class Imbalance

To understand vulnerability prevalence, `build_dataset.py` prints a **label distribution summary**:

```python
label_cols = [c for c in df.columns if c.startswith('label_')]
print("Vulnerability Distribution:")
for col in label_cols:
    vuln_name = col.replace('label_', '')
    total = df[col].sum()
    train_count = train_df[col].sum()
    test_count = test_df[col].sum()
    print(f"  {vuln_name:30s}: {total:3d} total ({train_count:3d} train, {test_count:2d} test)")
```

This reports, for each label:

- **Total** number of vulnerable contracts in the entire dataset
- Number in **training** split
- Number in **test** split

### 6.1 Per-Model Sample Counts

As summarized in [docs/LEARNING_GUIDE.md](../docs/LEARNING_GUIDE.md), the approximate training sample sizes per model (for illustration) are:

| Model                            | Positive (Vulnerable) | Negative (Safe) |
| -------------------------------- | --------------------- | --------------- |
| `reentrancy_rf.pkl`              | 40                    | 97              |
| `access_control_rf.pkl`          | 14                    | 123             |
| `unchecked_external_call_rf.pkl` | 49                    | 88              |
| `dangerous_construct_rf.pkl`     | 39                    | 98              |

This highlights that some tasks (e.g., access control) are **highly imbalanced**, which influences model choice and training strategy (see `train_improved_ac_model.py`).

### 6.2 Implications

- Models trained on imbalanced data are more likely to **miss rare vulnerabilities**.
- SC-GUARD mitigates this at the training stage using techniques like:
  - Class weights (`class_weight='balanced'` or custom weights)
  - Oversampling via **SMOTE** (see `train_quick_improved.py` and `train_improved_ac_model.py`).

---

## 7. Basic Dataset Analysis

While SC-GUARD does not ship a full EDA notebook, several scripts and docs capture key dataset properties:

- [docs/PROJECT_SUMMARY.md](../docs/PROJECT_SUMMARY.md)
  - Explains dataset size and category breakdown.
  - Shows how features relate to vulnerability detection.

- [docs/LEARNING_GUIDE.md](../docs/LEARNING_GUIDE.md)
  - Connects dataset statistics to ML concepts (class imbalance, overfitting, etc.).

- [docs/MODEL_PERFORMANCE_SUMMARY.md](../docs/MODEL_PERFORMANCE_SUMMARY.md)
  - Links dataset properties to resulting F1, precision, recall, and ROC-AUC metrics.

Together, these resources show **how dataset construction decisions affect model behavior**.

---

## 8. Reproducibility: Rebuilding the Dataset

You can rebuild the dataset from scratch using the provided scripts.

### 8.1 Prerequisites

- Ensure dataset is present at `datasets/smartbugs-curated/` (already included in this repo).
- Install dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

### 8.2 Build the Dataset

From the project root:

```bash
python scripts/build_dataset.py
```

Expected outputs:

- `outputs/dataset.csv`
- `outputs/train_dataset.csv`
- `outputs/test_dataset.csv`

If successful, the script will print a dataset summary and label distribution.

### 8.3 Train and Evaluate Models

Once the dataset is built:

```bash
python scripts/train_models.py
python scripts/evaluate_all_models.py
```

These scripts will:

- Train all four vulnerability models.
- Evaluate them on the test set and print metrics.

This demonstrates **end-to-end reproducibility** from raw contracts to trained models and performance reports.

---

## 9. Limitations and Future Data Work

While the current dataset pipeline is robust for research and demonstration, there are known limitations:

- **Dataset Scope**
  - Focused on SmartBugs Curated; may not cover all modern Solidity patterns or DeFi-specific vulnerabilities.

- **Label Granularity**
  - Labels are coarse-grained (e.g., "reentrancy" vs. specific subtypes).

- **Real-World Noise**
  - Contracts in the wild may differ significantly from curated examples.

### 9.1 Potential Improvements

- Incorporate additional datasets (e.g., real mainnet contracts with verified source).
- Add more fine-grained vulnerability labels and derive new target columns.
- Create dedicated EDA notebooks (Jupyter) to visualize feature distributions and correlations.
- Introduce temporal splits (train on older contracts, test on newer ones) to better simulate deployment reality.

Despite these limitations, the current dataset construction pipeline provides a **clear, documented, and reproducible** path from labeled Solidity contracts to ML-ready feature matrices, which is essential for trustworthy security analysis.
