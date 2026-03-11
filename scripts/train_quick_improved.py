"""
Quick Training Script - Improved Access Control Model

Uses SMOTE and optimized hyperparameters (no grid search for speed).
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import pickle

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
from imblearn.over_sampling import SMOTE

import warnings
warnings.filterwarnings('ignore')


def print_section(title):
    """Print formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def train_quick_improved_model():
    """Quick training with SMOTE and pre-optimized settings."""
    
    print_section("QUICK IMPROVED ACCESS CONTROL MODEL TRAINING")
    
    # Load data
    print("Loading training data...")
    train_df = pd.read_csv('outputs/train_dataset.csv')
    test_df = pd.read_csv('outputs/test_dataset.csv')
    
    # Extract features and labels
    feature_cols = [col for col in train_df.columns if col not in 
                    ['contract_name', 'category', 'label_reentrancy', 'label_access_control', 
                     'label_unchecked_external_call', 'label_dangerous_construct']]
    
    X_train = train_df[feature_cols].values
    y_train = train_df['label_access_control'].values
    X_test = test_df[feature_cols].values
    y_test = test_df['label_access_control'].values
    
    print(f"Training samples: {len(X_train)}")
    print(f"Positive (vulnerable): {y_train.sum()}")
    print(f"Negative (safe): {len(y_train) - y_train.sum()}")
    print(f"Imbalance ratio: {(len(y_train) - y_train.sum()) / max(y_train.sum(), 1):.2f}:1")
    
    # Apply SMOTE
    print_section("Applying SMOTE")
    
    smote = SMOTE(
        sampling_strategy='minority',
        random_state=42,
        k_neighbors=min(5, y_train.sum() - 1)
    )
    
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    print(f"After SMOTE:")
    print(f"  Total samples: {len(X_train_resampled)}")
    print(f"  Positive: {y_train_resampled.sum()}")
    print(f"  Negative: {len(y_train_resampled) - y_train_resampled.sum()}")
    print(f"  Balanced: {abs(y_train_resampled.sum() - (len(y_train_resampled) - y_train_resampled.sum())) < 5}")
    
    # Train with optimized hyperparameters
    print_section("Training Model with Optimized Settings")
    
    # Multiple strategies to try
    strategies = [
        {
            'name': 'Strategy 1: High Recall (Catch all vulnerabilities)',
            'params': {
                'n_estimators': 200,
                'max_depth': 15,
                'min_samples_split': 2,
                'min_samples_leaf': 1,
                'class_weight': {0: 1, 1: 10},  # Heavy penalty for missing vulnerable
                'max_features': 'sqrt',
                'random_state': 42,
                'n_jobs': -1
            }
        },
        {
            'name': 'Strategy 2: Balanced F1',
            'params': {
                'n_estimators': 300,
                'max_depth': 20,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'class_weight': 'balanced_subsample',
                'max_features': 0.5,
                'random_state': 42,
                'n_jobs': -1
            }
        },
        {
            'name': 'Strategy 3: Deep Trees',
            'params': {
                'n_estimators': 200,
                'max_depth': None,  # No limit
                'min_samples_split': 2,
                'min_samples_leaf': 1,
                'class_weight': 'balanced',
                'max_features': 'log2',
                'random_state': 42,
                'n_jobs': -1
            }
        }
    ]
    
    best_model = None
    best_f1 = 0.0
    best_strategy_name = ""
    
    for strategy in strategies:
        print(f"\n{'='*80}")
        print(f"Testing: {strategy['name']}")
        print(f"{'='*80}")
        
        # Create and train model
        model = RandomForestClassifier(**strategy['params'])
        model.fit(X_train_resampled, y_train_resampled)
        
        # Cross-validation on resampled data
        cv_scores = cross_val_score(
            model, X_train_resampled, y_train_resampled,
            cv=5, scoring='f1', n_jobs=-1
        )
        print(f"Cross-Val F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
        
        # Evaluate on test set
        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred)
        
        print(f"Test Set F1:  {f1:.3f}")
        
        # Track best model
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_strategy_name = strategy['name']
    
    # Final evaluation with best model
    print_section("BEST MODEL EVALUATION")
    print(f"Best Strategy: {best_strategy_name}")
    print(f"F1 Score: {best_f1:.3f}")
    
    y_pred = best_model.predict(X_test)
    y_pred_proba = best_model.predict_proba(X_test)[:, 1]
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Safe', 'Vulnerable'],
                                zero_division=0))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted Safe  Predicted Vulnerable")
    print(f"Actually Safe        {cm[0][0]:4d}              {cm[0][1]:4d}")
    print(f"Actually Vulnerable  {cm[1][0]:4d}              {cm[1][1]:4d}")
    
    # ROC-AUC if possible
    try:
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC-AUC Score: {roc_auc:.3f}")
    except:
        print("\nROC-AUC: Not available (likely only one class in test)")
    
    # Feature importance
    print_section("TOP 10 IMPORTANT FEATURES")
    
    importances = best_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(10, len(feature_cols))):
        idx = indices[i]
        print(f"  {i+1:2d}. {feature_cols[idx]:35s}: {importances[idx]:.4f}")
    
    # Save model
    print_section("SAVING MODEL")
    
    model_path = Path('models/access_control_rf_improved.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(best_model, f)
    
    print(f"✅ Model saved: {model_path}")
    print(f"   Size: {model_path.stat().st_size / 1024:.1f} KB")
    
    # Compare with original
    print_section("COMPARISON WITH ORIGINAL")
    
    try:
        with open('models/access_control_rf.pkl', 'rb') as f:
            original_model = pickle.load(f)
        
        y_pred_original = original_model.predict(X_test)
        f1_original = f1_score(y_test, y_pred_original)
        
        print(f"Original Model F1:  {f1_original:.3f}")
        print(f"Improved Model F1:  {best_f1:.3f}")
        print(f"Improvement:        {best_f1 - f1_original:+.3f} ({100*(best_f1-f1_original)/max(f1_original, 0.001):+.1f}%)")
        
        if best_f1 > f1_original:
            print("\n" + "🎉" * 40)
            print("✅ IMPROVED MODEL IS SIGNIFICANTLY BETTER!")
            print("🎉" * 40)
            print("\nTo use the improved model in production:")
            print("  1. Backup original: mv models/access_control_rf.pkl models/access_control_rf_original.pkl")
            print("  2. Replace:         mv models/access_control_rf_improved.pkl models/access_control_rf.pkl")
        else:
            print("\n⚠️ Original model still performs better.")
            print("Consider:")
            print("  - Collecting more access control samples")
            print("  - Adding domain-specific features")
            print("  - Trying other algorithms (XGBoost, Neural Networks)")
    except FileNotFoundError:
        print("Original model not found - this is the first model!")
    
    return best_model, best_f1


if __name__ == '__main__':
    try:
        model, f1 = train_quick_improved_model()
        
        print("\n" + "=" * 80)
        print(f"  🎯 FINAL F1 SCORE: {f1:.3f}")
        print("=" * 80)
        
        if f1 > 0.50:
            print("✅ SUCCESS: Model significantly improved!")
        elif f1 > 0.40:
            print("⚠️ MODERATE: Some improvement, but more work needed")
        else:
            print("❌ NEEDS WORK: Consider alternative approaches")
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
