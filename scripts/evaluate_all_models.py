"""
Test All Models - Quick Performance Check

Evaluates all 4 models on test set with improved Access Control model.
"""

import sys
from pathlib import Path
import pandas as pd
import pickle
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

def evaluate_all_models():
    """Test all 4 vulnerability models."""
    
    print("="*80)
    print("SC-GUARD MODEL EVALUATION REPORT")
    print("="*80)
    
    # Load test data
    test_df = pd.read_csv('outputs/test_dataset.csv')
    
    feature_cols = [col for col in test_df.columns if col not in 
                    ['contract_name', 'category', 'label_reentrancy', 'label_access_control', 
                     'label_unchecked_external_call', 'label_dangerous_construct']]
    
    X_test = test_df[feature_cols].values
    
    models = {
        'Reentrancy': ('models/reentrancy_rf.pkl', 'label_reentrancy'),
        'Access Control': ('models/access_control_rf.pkl', 'label_access_control'),
        'Unchecked Call': ('models/unchecked_external_call_rf.pkl', 'label_unchecked_external_call'),
        'Dangerous Construct': ('models/dangerous_construct_rf.pkl', 'label_dangerous_construct'),
    }
    
    results = []
    
    for name, (model_path, label_col) in models.items():
        print(f"\n{'='*80}")
        print(f"Testing: {name}")
        print(f"{'='*80}")
        
        try:
            # Load model
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            # Get labels
            y_test = test_df[label_col].values
            
            # Predict
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Compute metrics
            f1 = f1_score(y_test, y_pred, zero_division=0)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            except:
                roc_auc = 0.0
            
            # Count samples
            n_positive = y_test.sum()
            n_negative = len(y_test) - n_positive
            
            # Print results
            print(f"Test Samples: {len(y_test)} ({n_positive} vulnerable, {n_negative} safe)")
            print(f"F1 Score:     {f1:.3f}")
            print(f"Precision:    {precision:.3f}")
            print(f"Recall:       {recall:.3f}")
            print(f"ROC-AUC:      {roc_auc:.3f}")
            
            # Performance assessment
            if f1 >= 0.80:
                status = "✅ EXCELLENT"
            elif f1 >= 0.60:
                status = "✅ GOOD"
            elif f1 >= 0.40:
                status = "⚠️ MODERATE"
            else:
                status = "❌ NEEDS IMPROVEMENT"
            
            print(f"Status:       {status}")
            
            results.append({
                'Model': name,
                'F1': f1,
                'Precision': precision,
                'Recall': recall,
                'ROC-AUC': roc_auc,
                'Status': status
            })
            
        except FileNotFoundError:
            print(f"❌ Model not found: {model_path}")
            results.append({
                'Model': name,
                'F1': 0.0,
                'Precision': 0.0,
                'Recall': 0.0,
                'ROC-AUC': 0.0,
                'Status': '❌ NOT FOUND'
            })
    
    # Summary table
    print("\n" + "="*80)
    print("SUMMARY: ALL MODELS")
    print("="*80 + "\n")
    
    print(f"{'Model':<25} {'F1':>8} {'Precision':>10} {'Recall':>8} {'ROC-AUC':>9} {'Status':>20}")
    print("-" * 90)
    
    for r in results:
        print(f"{r['Model']:<25} {r['F1']:>7.3f} {r['Precision']:>10.3f} {r['Recall']:>8.3f} {r['ROC-AUC']:>9.3f} {r['Status']:>20}")
    
    # Average F1
    avg_f1 = sum(r['F1'] for r in results) / len(results)
    print("-" * 90)
    print(f"{'AVERAGE':<25} {avg_f1:>7.3f}")
    print("\n" + "="*80)
    
    # Overall assessment
    if avg_f1 >= 0.70:
        print("🎉 OVERALL: EXCELLENT - Production ready!")
    elif avg_f1 >= 0.55:
        print("✅ OVERALL: GOOD - Ready for deployment")
    elif avg_f1 >= 0.40:
        print("⚠️ OVERALL: MODERATE - Consider improvements")
    else:
        print("❌ OVERALL: NEEDS WORK - Significant improvements needed")
    
    print("="*80)
    
    return results


if __name__ == '__main__':
    results = evaluate_all_models()
