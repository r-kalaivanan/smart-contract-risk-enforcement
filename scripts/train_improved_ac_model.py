"""
Improved Training Script with SMOTE and Hyperparameter Tuning

Specifically optimized for Access Control model improvement.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import pickle

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.preprocessing import StandardScaler

import warnings
warnings.filterwarnings('ignore')


def print_section(title):
    """Print formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def train_improved_access_control_model():
    """
    Train improved Access Control model with:
    1. SMOTE for handling class imbalance
    2. Feature scaling
    3. Hyperparameter tuning with GridSearchCV
    4. Increased class weights
    5. Stratified cross-validation
    """
    
    print_section("IMPROVED ACCESS CONTROL MODEL TRAINING")
    
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
    print(f"Imbalance ratio: {(len(y_train) - y_train.sum()) / y_train.sum():.2f}:1")
    
    # ==========================================
    # STRATEGY 1: SMOTE for Synthetic Sampling
    # ==========================================
    print_section("Applying SMOTE (Synthetic Minority Over-sampling)")
    
    # Use SMOTE to create synthetic samples of the minority class
    # This will balance the dataset by generating new vulnerable contract samples
    smote = SMOTE(
        sampling_strategy='minority',  # Only oversample minority class
        random_state=42,
        k_neighbors=min(5, y_train.sum() - 1)  # Adjust k_neighbors based on minority samples
    )
    
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    print(f"After SMOTE:")
    print(f"  Total samples: {len(X_train_resampled)}")
    print(f"  Positive: {y_train_resampled.sum()}")
    print(f"  Negative: {len(y_train_resampled) - y_train_resampled.sum()}")
    print(f"  New ratio: {(len(y_train_resampled) - y_train_resampled.sum()) / y_train_resampled.sum():.2f}:1")
    
    # ==========================================
    # STRATEGY 2: Hyperparameter Grid Search
    # ==========================================
    print_section("Hyperparameter Tuning with GridSearchCV")
    
    # Define parameter grid - more aggressive for imbalanced data
    param_grid = {
        'n_estimators': [100, 200, 300],  # More trees can help
        'max_depth': [10, 15, 20, None],  # Try deeper trees
        'min_samples_split': [2, 5, 10],  # Allow smaller splits
        'min_samples_leaf': [1, 2, 4],    # Allow smaller leaves
        'class_weight': ['balanced', 'balanced_subsample', {0: 1, 1: 10}],  # Heavy penalty for misclassifying vulnerable
        'max_features': ['sqrt', 'log2', 0.5],  # Feature sampling strategies
    }
    
    # Create base model
    rf_base = RandomForestClassifier(
        random_state=42,
        n_jobs=-1,
        bootstrap=True
    )
    
    # Grid search with stratified k-fold
    print("Searching for best hyperparameters...")
    print(f"Testing {np.prod([len(v) for v in param_grid.values()])} combinations...")
    
    grid_search = GridSearchCV(
        estimator=rf_base,
        param_grid=param_grid,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        scoring='f1',  # Optimize for F1 score
        n_jobs=-1,
        verbose=1,
        return_train_score=True
    )
    
    grid_search.fit(X_train_resampled, y_train_resampled)
    
    print(f"\nBest hyperparameters found:")
    for param, value in grid_search.best_params_.items():
        print(f"  {param}: {value}")
    print(f"\nBest CV F1 Score: {grid_search.best_score_:.3f}")
    
    # Get best model
    best_model = grid_search.best_estimator_
    
    # ==========================================
    # STRATEGY 3: Evaluate on Original Test Set
    # ==========================================
    print_section("Evaluation on Test Set")
    
    y_pred = best_model.predict(X_test)
    y_pred_proba = best_model.predict_proba(X_test)[:, 1]
    
    # Compute metrics
    f1 = f1_score(y_test, y_pred)
    try:
        roc_auc = roc_auc_score(y_test, y_pred_proba)
    except:
        roc_auc = 0.0
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Safe', 'Vulnerable'],
                                zero_division=0))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted Safe  Predicted Vulnerable")
    print(f"Actually Safe        {cm[0][0]:4d}              {cm[0][1]:4d}")
    print(f"Actually Vulnerable  {cm[1][0]:4d}              {cm[1][1]:4d}")
    
    print(f"\nKey Metrics:")
    print(f"  F1 Score: {f1:.3f}")
    print(f"  ROC-AUC:  {roc_auc:.3f}")
    
    # ==========================================
    # STRATEGY 4: Feature Importance Analysis
    # ==========================================
    print_section("Feature Importance (Top 10)")
    
    importances = best_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    feature_names = feature_cols
    for i in range(min(10, len(feature_names))):
        idx = indices[i]
        print(f"  {i+1}. {feature_names[idx]:35s}: {importances[idx]:.4f}")
    
    # ==========================================
    # Save Model
    # ==========================================
    print_section("Saving Improved Model")
    
    model_path = Path('models/access_control_rf_improved.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(best_model, f)
    
    print(f"Model saved to: {model_path}")
    print(f"Model size: {model_path.stat().st_size / 1024:.1f} KB")
    
    # ==========================================
    # Comparison with Original Model
    # ==========================================
    print_section("COMPARISON WITH ORIGINAL MODEL")
    
    try:
        with open('models/access_control_rf.pkl', 'rb') as f:
            original_model = pickle.load(f)
        
        y_pred_original = original_model.predict(X_test)
        f1_original = f1_score(y_test, y_pred_original)
        
        print(f"Original Model F1:  {f1_original:.3f}")
        print(f"Improved Model F1:  {f1:.3f}")
        print(f"Improvement:        {f1 - f1_original:+.3f} ({100*(f1-f1_original)/max(f1_original, 0.001):+.1f}%)")
        
        if f1 > f1_original:
            print("\n✅ IMPROVED MODEL IS BETTER!")
            # Offer to replace original
            print("\nTo use the improved model, run:")
            print("  mv models/access_control_rf_improved.pkl models/access_control_rf.pkl")
        else:
            print("\n⚠️ Original model still performs better. Consider:")
            print("  - Collecting more training data")
            print("  - Adding more access-control specific features")
            print("  - Trying different algorithms (XGBoost, LightGBM)")
    except FileNotFoundError:
        print("Original model not found for comparison.")
    
    print_section("TRAINING COMPLETE")
    
    return best_model, f1


if __name__ == '__main__':
    # Check if imblearn is installed
    try:
        import imblearn
    except ImportError:
        print("ERROR: imbalanced-learn not installed!")
        print("Install with: pip install imbalanced-learn")
        sys.exit(1)
    
    model, f1_score = train_improved_access_control_model()
    
    print(f"\n🎯 Final F1 Score: {f1_score:.3f}")
    
    if f1_score > 0.50:
        print("✅ Successfully improved Access Control model!")
    else:
        print("⚠️ Still needs improvement. Consider additional strategies.")
