"""
Model Training Module

Trains interpretable ML classifiers for vulnerability detection.

Why Classical ML (Not Deep Learning)?
1. Explainability: Feature importance directly maps to code patterns
2. Data Efficiency: Works with 300-500 contracts (DL needs thousands)
3. Speed: Training in seconds, not hours
4. Semester Feasibility: No GPU required, easy to debug

Model Selection:
1. Logistic Regression (Baseline)
   - Pros: Fast, linear feature importance, probabilistic output
   - Cons: Assumes linear separability
   - Use Case: Establishes baseline performance

2. Random Forest (Primary)
   - Pros: Handles non-linear patterns, robust to outliers, feature importance
   - Cons: Can overfit with too many trees
   - Use Case: Main production model
   - Hyperparameters: 100 trees, max_depth=10 (prevent overfitting)

Training Strategy:
- Multi-label classification: Separate model per vulnerability type
- Cross-validation: 5-fold to ensure robustness
- Metrics: Precision, Recall, F1 (not just accuracy—class imbalance!)

Output:
- Trained models saved as .pkl files
- Feature importance rankings
- Evaluation metrics (confusion matrix, ROC curves)
"""

import numpy as np
import pickle
from pathlib import Path
from typing import Dict, List, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score,
    precision_recall_fscore_support
)
from sklearn.model_selection import cross_val_score


class VulnerabilityClassifier:
    """
    Trains and evaluates vulnerability detection models.
    
    Usage:
        clf = VulnerabilityClassifier(model_type="random_forest")
        clf.train(X_train, y_train)
        predictions = clf.predict(X_test)
        clf.save_model("models/reentrancy_rf.pkl")
    """
    
    def __init__(self, model_type: str = "random_forest", vulnerability_type: str = "reentrancy"):
        """
        Initialize classifier.
        
        Args:
            model_type: "random_forest" or "logistic_regression"
            vulnerability_type: Name of vulnerability being detected
        """
        self.model_type = model_type
        self.vulnerability_type = vulnerability_type
        self.model = None
        self.feature_importance = None
        
        # Initialize model
        if model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=100,         # 100 decision trees
                max_depth=10,              # Prevent overfitting
                min_samples_split=5,       # Require 5 samples to split node
                random_state=42,           # Reproducibility
                class_weight="balanced",   # Handle class imbalance
                n_jobs=-1                  # Use all CPU cores
            )
        elif model_type == "logistic_regression":
            self.model = LogisticRegression(
                max_iter=1000,
                random_state=42,
                class_weight="balanced"
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the model.
        
        Args:
            X_train: Feature matrix (n_samples, n_features)
            y_train: Binary labels (n_samples,)
        """
        print(f"[Training] {self.vulnerability_type} - {self.model_type}")
        print(f"  Training samples: {X_train.shape[0]}")
        print(f"  Features: {X_train.shape[1]}")
        print(f"  Positive class ratio: {y_train.sum() / len(y_train):.2%}")
        
        self.model.fit(X_train, y_train)
        
        # Extract feature importance (Random Forest only)
        if self.model_type == "random_forest":
            self.feature_importance = self.model.feature_importances_
        
        print(f"  ✓ Training complete")
    
    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """
        Predict binary labels.
        
        Args:
            X_test: Feature matrix
            
        Returns:
            Binary predictions (0 or 1)
        """
        return self.model.predict(X_test)
    
    def predict_proba(self, X_test: np.ndarray) -> np.ndarray:
        """
        Predict vulnerability probabilities.
        
        Args:
            X_test: Feature matrix
            
        Returns:
            Probability of positive class (vulnerability present)
        """
        proba = self.model.predict_proba(X_test)
        return proba[:, 1]  # Probability of class 1 (vulnerable)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Comprehensive model evaluation.
        
        Args:
            X_test: Test feature matrix
            y_test: True labels
            
        Returns:
            Dictionary with metrics:
                - accuracy, precision, recall, f1_score
                - confusion_matrix
                - roc_auc
        """
        y_pred = self.predict(X_test)
        y_proba = self.predict_proba(X_test)
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='binary', zero_division=0
        )
        
        accuracy = (y_pred == y_test).mean()
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        # ROC-AUC (only if both classes present)
        try:
            roc_auc = roc_auc_score(y_test, y_proba)
        except:
            roc_auc = None
        
        results = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "confusion_matrix": conf_matrix.tolist(),
            "roc_auc": roc_auc
        }
        
        # Print results
        print(f"\n[Evaluation] {self.vulnerability_type}")
        print(f"  Accuracy:  {accuracy:.3f}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall:    {recall:.3f}")
        print(f"  F1 Score:  {f1:.3f}")
        if roc_auc:
            print(f"  ROC-AUC:   {roc_auc:.3f}")
        print(f"\n  Confusion Matrix:")
        print(f"    TN={conf_matrix[0,0]}, FP={conf_matrix[0,1]}")
        print(f"    FN={conf_matrix[1,0]}, TP={conf_matrix[1,1]}")
        
        return results
    
    def get_feature_importance(self, feature_names: List[str]) -> Dict[str, float]:
        """
        Get feature importance rankings.
        
        Args:
            feature_names: List of feature names
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.feature_importance is None:
            return {}
        
        importance_dict = dict(zip(feature_names, self.feature_importance))
        # Sort by importance (descending)
        sorted_importance = dict(
            sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        )
        
        return sorted_importance
    
    def save_model(self, output_path: str):
        """
        Save trained model to disk.
        
        Args:
            output_path: Path to save .pkl file
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"[Save] Model saved to {output_path}")
    
    @staticmethod
    def load_model(model_path: str):
        """
        Load trained model from disk.
        
        Args:
            model_path: Path to .pkl file
            
        Returns:
            VulnerabilityClassifier instance with loaded model
        """
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        # Create classifier instance and attach model
        clf = VulnerabilityClassifier()
        clf.model = model
        return clf
