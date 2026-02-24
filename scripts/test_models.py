"""
Test Trained Models on Sample Contracts

This script validates that trained models can:
1. Load successfully from disk
2. Make predictions on new contracts
3. Output reasonable vulnerability probabilities

Usage:
    python scripts/test_models.py
"""

import sys
from pathlib import Path
import numpy as np

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from analyzers.slither_analyzer import SlitherAnalyzer
from analyzers.ast_extractor import ASTFeatureExtractor
from ml.train_model import VulnerabilityClassifier


def print_header(title, width=80):
    """Print section header."""
    print()
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    print()


def test_single_contract(contract_path: str):
    """
    Test all models on a single contract.
    
    Args:
        contract_path: Path to .sol file
    """
    print_header(f"Testing: {Path(contract_path).name}")
    
    # Step 1: Extract features
    print("[Step 1] Extracting features...")
    try:
        analyzer = SlitherAnalyzer(contract_path)
        analyzer.analyze()
        extractor = ASTFeatureExtractor(analyzer.slither)
        features = extractor.extract()
        feature_vector = features.to_vector().reshape(1, -1)
        print(f"  ✓ Features extracted: {feature_vector.shape}")
    except Exception as e:
        print(f"  ✗ Feature extraction failed: {e}")
        return
    
    # Step 2: Load and test each model
    print("\n[Step 2] Testing vulnerability models...")
    
    models_dir = Path("models")
    if not models_dir.exists():
        print(f"  ✗ Models directory not found: {models_dir}")
        print("    Please run: python scripts/train_models.py")
        return
    
    model_files = list(models_dir.glob("*_rf.pkl"))
    if not model_files:
        print(f"  ✗ No trained models found in {models_dir}")
        print("    Please run: python scripts/train_models.py")
        return
    
    print(f"  Found {len(model_files)} models\n")
    
    predictions = {}
    
    for model_file in sorted(model_files):
        vuln_type = model_file.stem.replace("_rf", "")
        
        try:
            # Load model
            clf = VulnerabilityClassifier.load_model(str(model_file))
            
            # Make prediction
            prediction = clf.predict(feature_vector)[0]
            probability = clf.predict_proba(feature_vector)[0]
            
            predictions[vuln_type] = {
                'prediction': prediction,
                'probability': probability
            }
            
            status = "🔴 VULNERABLE" if prediction == 1 else "🟢 SAFE"
            print(f"  {vuln_type:30s}: {status} (prob: {probability:.3f})")
            
        except Exception as e:
            print(f"  {vuln_type:30s}: ✗ Error - {e}")
    
    # Step 3: Overall risk assessment
    print("\n[Step 3] Overall Risk Assessment")
    
    if predictions:
        avg_probability = np.mean([p['probability'] for p in predictions.values()])
        vulnerable_count = sum(p['prediction'] for p in predictions.values())
        
        print(f"  Vulnerabilities detected: {vulnerable_count}/{len(predictions)}")
        print(f"  Average risk probability: {avg_probability:.3f}")
        
        if avg_probability > 0.7:
            risk_level = "HIGH RISK"
        elif avg_probability > 0.4:
            risk_level = "MEDIUM RISK"
        else:
            risk_level = "LOW RISK"
        
        print(f"  Risk Level: {risk_level}")


def main():
    """Test models on sample contracts."""
    print()
    print("*" * 80)
    print("SC-GUARD MODEL TESTING".center(80))
    print("*" * 80)
    
    # Test contracts
    test_contracts = [
        "test_contracts/ComplexVulnerable.sol",
        # Add more test contracts here
    ]
    
    for contract in test_contracts:
        contract_path = Path(contract)
        
        if not contract_path.exists():
            print(f"\n⚠️  Contract not found: {contract}")
            continue
        
        test_single_contract(str(contract_path))
        print()
    
    print("*" * 80)
    print("Testing Complete".center(80))
    print("*" * 80)
    print()


if __name__ == "__main__":
    main()
