"""
Train ML Models for SC-GUARD

This script trains separate Random Forest classifiers for each vulnerability type.

Process:
1. Load train/test datasets from outputs/
2. Extract features (X) and labels (y) for each vulnerability type
3. Train Random Forest model with cross-validation
4. Evaluate on test set
5. Save trained models to models/ directory

Usage:
    python scripts/train_models.py
    
Output:
    models/reentrancy_rf.pkl
    models/access_control_rf.pkl
    models/unchecked_external_call_rf.pkl
    models/dangerous_construct_rf.pkl
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from ml.train_model import VulnerabilityClassifier
from data.label_encoder import ContractLabels
from analyzers.ast_extractor import ContractFeatures
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score


def print_header(title, width=80):
    """Print section header."""
    print()
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    print()


def train_single_model(
    vuln_type: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: list
) -> VulnerabilityClassifier:
    """
    Train and evaluate a single vulnerability detection model.
    
    Args:
        vuln_type: Vulnerability type name
        X_train: Training features
        y_train: Training labels
        X_test: Test features
        y_test: Test labels
        feature_names: List of feature names
        
    Returns:
        Trained VulnerabilityClassifier
    """
    print_header(f"Training Model: {vuln_type.upper().replace('_', ' ')}")
    
    # Create classifier
    clf = VulnerabilityClassifier(
        model_type="random_forest",
        vulnerability_type=vuln_type
    )
    
    # Train model
    clf.train(X_train, y_train)
    
    # Cross-validation on training set
    print("\n[Cross-Validation]")
    cv_scores = cross_val_score(
        clf.model, X_train, y_train, 
        cv=5, 
        scoring='f1'
    )
    print(f"  5-Fold CV F1 Score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    # Evaluate on test set
    print("\n[Test Set Evaluation]")
    y_pred = clf.predict(X_test)
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(
        y_test, y_pred, 
        target_names=['Safe', 'Vulnerable'],
        zero_division=0
    ))
    
    # Detailed metrics
    metrics = clf.evaluate(X_test, y_test)
    
    # Feature importance
    print("\n[Top 5 Most Important Features]")
    importance = clf.get_feature_importance(feature_names)
    for i, (feature, score) in enumerate(list(importance.items())[:5], 1):
        print(f"  {i}. {feature:40s}: {score:.4f}")
    
    return clf


def main():
    """Main training pipeline."""
    print()
    print("*" * 80)
    print("SC-GUARD MODEL TRAINING PIPELINE".center(80))
    print("*" * 80)
    print()
    
    # Check if datasets exist
    train_path = Path("outputs/train_dataset.csv")
    test_path = Path("outputs/test_dataset.csv")
    
    if not train_path.exists() or not test_path.exists():
        print("ERROR: Dataset files not found!")
        print(f"  Expected: {train_path}")
        print(f"  Expected: {test_path}")
        print()
        print("Please run: python scripts/build_dataset.py")
        return 1
    
    # Load datasets
    print("[Step 1] Loading Datasets...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    print(f"  Training set: {len(train_df)} samples")
    print(f"  Test set:     {len(test_df)} samples")
    
    # Extract feature columns
    feature_names = ContractFeatures.feature_names()
    X_train = train_df[feature_names].values
    X_test = test_df[feature_names].values
    
    print(f"  Feature dimensions: {X_train.shape[1]} features")
    
    # Get vulnerability types
    label_names = ContractLabels.label_names()
    print(f"\n[Step 2] Training Models for {len(label_names)} Vulnerability Types")
    print(f"  Types: {', '.join(label_names)}")
    
    # Train separate model for each vulnerability type
    trained_models = {}
    
    for vuln_type in label_names:
        # Extract labels for this vulnerability type
        y_train = train_df[f'label_{vuln_type}'].values
        y_test = test_df[f'label_{vuln_type}'].values
        
        # Check if we have positive samples
        train_positives = y_train.sum()
        test_positives = y_test.sum()
        
        if train_positives == 0:
            print(f"\n[WARNING] Skipping {vuln_type}: No positive training samples")
            continue
        
        print(f"\n  Training samples: {train_positives} vulnerable / {len(y_train)} total")
        print(f"  Test samples:     {test_positives} vulnerable / {len(y_test)} total")
        
        # Train model
        clf = train_single_model(
            vuln_type=vuln_type,
            X_train=X_train,
            y_train=y_train,
            X_test=X_test,
            y_test=y_test,
            feature_names=feature_names
        )
        
        # Save model
        model_path = Path("models") / f"{vuln_type}_rf.pkl"
        clf.save_model(str(model_path))
        
        trained_models[vuln_type] = clf
        
        input("\nPress Enter to continue to next model...")
    
    # Final summary
    print_header("TRAINING COMPLETE")
    
    print(f"Models trained: {len(trained_models)}/{len(label_names)}")
    print()
    print("Saved models:")
    for vuln_type in trained_models.keys():
        model_path = Path("models") / f"{vuln_type}_rf.pkl"
        print(f"  ✓ {model_path}")
    
    print()
    print("Next steps:")
    print("  1. Test models: python scripts/test_models.py")
    print("  2. Use CLI: sc-guard scan <contract.sol>")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
