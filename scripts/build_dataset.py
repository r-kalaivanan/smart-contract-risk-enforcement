"""
Build ML Dataset from SmartBugs Curated Contracts

This script processes all contracts in the SmartBugs dataset and creates
train/test splits ready for machine learning.

Process:
1. Load contracts from datasets/smartbugs-curated/
2. Extract features using SlitherAnalyzer + ASTFeatureExtractor
3. Generate labels using vulnerabilities.json
4. Save full dataset, train split (80%), test split (20%)

Usage:
    python scripts/build_dataset.py
    
Output:
    outputs/dataset.csv         (Full dataset)
    outputs/train_dataset.csv   (80% train split)
    outputs/test_dataset.csv    (20% test split)
"""

import sys
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from data.feature_builder import FeatureBuilder


def print_header(title, width=80):
    """Print section header."""
    print()
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    print()


def main():
    """Build complete ML dataset."""
    print()
    print("*" * 80)
    print("SC-GUARD DATASET BUILDER".center(80))
    print("*" * 80)
    
    dataset_path = "datasets/smartbugs-curated"
    
    # Check if dataset exists
    if not Path(dataset_path).exists():
        print(f"\nERROR: Dataset not found at {dataset_path}")
        return 1
    
    print_header("Step 1: Building Feature Dataset")
    
    # Build features
    builder = FeatureBuilder(dataset_path)
    df = builder.build_dataset()
    
    if df is None or len(df) == 0:
        print("ERROR: Failed to build dataset")
        return 1
    
    print(f"\n✓ Dataset built: {len(df)} contracts processed")
    print(f"  Features: {len([c for c in df.columns if c.startswith('feat_')])} columns")
    print(f"  Labels: {len([c for c in df.columns if c.startswith('label_')])} columns")
    
    # Save full dataset
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    
    full_path = output_dir / "dataset.csv"
    df.to_csv(full_path, index=False)
    print(f"  Saved: {full_path}")
    
    print_header("Step 2: Creating Train/Test Splits")
    
    # Split dataset (80% train, 20% test, stratified by category)
    try:
        train_df, test_df = train_test_split(
            df,
            test_size=0.2,
            random_state=42,
            stratify=df['category'] if 'category' in df.columns else None
        )
    except Exception as e:
        print(f"  Warning: Stratified split failed ({e}), using random split")
        train_df, test_df = train_test_split(
            df,
            test_size=0.2,
            random_state=42
        )
    
    # Save splits
    train_path = output_dir / "train_dataset.csv"
    test_path = output_dir / "test_dataset.csv"
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    print(f"  Training set: {len(train_df)} samples ({len(train_df)/len(df)*100:.1f}%)")
    print(f"    Saved: {train_path}")
    print(f"  Test set: {len(test_df)} samples ({len(test_df)/len(df)*100:.1f}%)")
    print(f"    Saved: {test_path}")
    
    print_header("Dataset Summary")
    
    # Label distribution
    label_cols = [c for c in df.columns if c.startswith('label_')]
    print("Vulnerability Distribution:")
    for col in label_cols:
        vuln_name = col.replace('label_', '')
        total = df[col].sum()
        train_count = train_df[col].sum()
        test_count = test_df[col].sum()
        print(f"  {vuln_name:30s}: {total:3d} total ({train_count:3d} train, {test_count:2d} test)")
    
    print()
    print("✓ Dataset building complete!")
    print()
    print("Next step: python scripts/train_models.py")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
