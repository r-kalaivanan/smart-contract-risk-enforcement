# 🚀 SC-GUARD Quick Start - Phase 3

## STEP 1: Build Dataset (5-10 min)

```bash
python scripts\build_dataset.py
```

**Creates:**

- `outputs/dataset.csv` (full dataset)
- `outputs/train_dataset.csv` (80% training)
- `outputs/test_dataset.csv` (20% testing)

**Success:** See "✅ Successfully processed: 137"

---

## STEP 2: Train Models (2-5 min per model)

```bash
python scripts\train_models.py
```

**Creates:**

- `models/reentrancy_rf.pkl`
- `models/access_control_rf.pkl`
- `models/unchecked_external_call_rf.pkl`
- `models/dangerous_construct_rf.pkl`

**Success:** See "F1 Score > 0.70" for each model

---

## STEP 3: Test Models (30 sec)

```bash
python scripts\test_models.py
```

**Output:** Vulnerability predictions on test contract

**Success:** See predictions with probabilities

---

## 🐛 Quick Troubleshooting

| Error                        | Solution                                    |
| ---------------------------- | ------------------------------------------- |
| "No module named sklearn"    | `pip install scikit-learn`                  |
| "Dataset not found"          | Check `datasets/smartbugs-curated/` exists  |
| "Slither compilation failed" | Normal for some contracts, script continues |
| "No models found"            | Run Step 2 first                            |

---

## ✅ Completion Checklist

- [ ] `outputs/` has 3 CSV files
- [ ] `models/` has 4 .pkl files
- [ ] Test script shows predictions

**All done? → Move to Phase 4 (Risk Scoring)**

---

## 📖 Full Guide

See `docs/PHASE3_EXECUTION_GUIDE.md` for detailed instructions
