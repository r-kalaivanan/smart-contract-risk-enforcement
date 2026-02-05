"""
Feature Builder Module

Processes entire SmartBugs dataset to build ML training data:
1. Iterate through all contracts
2. Extract 16 security features per contract
3. Attach vulnerability labels
4. Save as CSV for ML training

Handles:
- Compilation failures gracefully
- Progress tracking for 143 contracts
- Feature normalization
- Train/test splitting
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.slither_analyzer import SlitherAnalyzer
from analyzers.ast_extractor import ASTFeatureExtractor, ContractFeatures
from data.dataset_loader import DatasetLoader
from data.label_encoder import LabelEncoder, ContractLabels


class FeatureBuilder:
    """
    Builds ML-ready dataset from SmartBugs contracts.
    
    Usage:
        builder = FeatureBuilder("datasets/smartbugs-curated")
        dataset_df = builder.build_dataset()
        dataset_df.to_csv("outputs/dataset.csv")
    """
    
    def __init__(self, dataset_root: str):
        """
        Initialize feature builder.
        
        Args:
            dataset_root: Path to smartbugs-curated directory
        """
        self.dataset_root = Path(dataset_root)
        self.loader = DatasetLoader(str(self.dataset_root))
        
    def extract_features_from_contract(
        self, 
        contract_path: Path
    ) -> Optional[ContractFeatures]:
        """
        Extract 16 security features from a single contract.
        
        Args:
            contract_path: Path to .sol file
            
        Returns:
            ContractFeatures object, or None if compilation fails
        """
        try:
            # Step 1: Compile with Slither
            analyzer = SlitherAnalyzer(str(contract_path))
            analyzer.analyze()
            
            # Step 2: Extract features
            extractor = ASTFeatureExtractor(analyzer.slither)
            features = extractor.extract()
            
            return features
        except Exception as e:
            # Compilation or extraction failed
            print(f"  ⚠️  Failed to extract features: {e}")
            return None
    
    def build_dataset(
        self,
        output_path: Optional[str] = None,
        verbose: bool = True
    ) -> pd.DataFrame:
        """
        Process all contracts and build complete dataset.
        
        Args:
            output_path: Path to save CSV (optional)
            verbose: Print progress messages
            
        Returns:
            pandas DataFrame with features and labels
        """
        if verbose:
            print("=" * 70)
            print("BUILDING DATASET FROM SMARTBUGS CONTRACTS")
            print("=" * 70)
            self.loader.print_stats()
            print()
        
        # Collect all data
        dataset_rows = []
        
        # Iterate through all contracts
        contracts = list(self.loader.iter_contracts())
        
        if verbose:
            print(f"\n🔍 Processing {len(contracts)} contracts...")
            print("=" * 70)
        
        success_count = 0
        fail_count = 0
        
        for contract_info in tqdm(contracts, desc="Extracting features", disable=not verbose):
            contract_name = contract_info['name']
            contract_path = contract_info['path']
            category = contract_info['category']
            json_labels = contract_info['labels']
            
            if verbose:
                print(f"\n📄 {contract_name} ({category})")
            
            # Extract features
            features = self.extract_features_from_contract(contract_path)
            
            if features is None:
                fail_count += 1
                continue
            
            # Encode labels
            if json_labels:
                labels = LabelEncoder.encode_from_json(json_labels)
            else:
                # Fallback to category-based labeling
                labels = LabelEncoder.encode_from_category(category)
            
            # Build row: contract_name + 16 features + 4 labels
            feature_vector = features.to_vector()
            label_vector = labels.to_array()
            
            row = {
                'contract_name': contract_name,
                'category': category,
            }
            
            # Add features
            for i, name in enumerate(ContractFeatures.feature_names()):
                row[name] = feature_vector[i]
            
            # Add labels
            for i, name in enumerate(ContractLabels.label_names()):
                row[f'label_{name}'] = label_vector[i]
            
            dataset_rows.append(row)
            success_count += 1
            
            if verbose:
                print(f"  ✅ Success ({success_count}/{len(contracts)})")
        
        # Create DataFrame
        df = pd.DataFrame(dataset_rows)
        
        if verbose:
            print("\n" + "=" * 70)
            print("DATASET BUILD SUMMARY")
            print("=" * 70)
            print(f"✅ Successfully processed: {success_count}")
            print(f"❌ Failed to process: {fail_count}")
            print(f"📊 Total rows in dataset: {len(df)}")
            print(f"📐 Feature columns: {len(ContractFeatures.feature_names())}")
            print(f"🏷️  Label columns: {len(ContractLabels.label_names())}")
            
            # Print label distribution
            print("\n📊 Label Distribution:")
            for label in ContractLabels.label_names():
                col = f'label_{label}'
                if col in df.columns:
                    count = df[col].sum()
                    pct = (count / len(df) * 100) if len(df) > 0 else 0
                    print(f"  {label:30s}: {count:3d} ({pct:5.1f}%)")
        
        # Save to CSV if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(output_file, index=False)
            if verbose:
                print(f"\n💾 Saved dataset to: {output_file}")
        
        return df
    
    def split_dataset(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into train/test sets.
        
        Args:
            df: Complete dataset DataFrame
            test_size: Fraction for test set (default 0.2 = 20%)
            random_state: Random seed for reproducibility
            
        Returns:
            (train_df, test_df)
        """
        from sklearn.model_selection import train_test_split
        
        train_df, test_df = train_test_split(
            df,
            test_size=test_size,
            random_state=random_state,
            stratify=df['label_reentrancy']  # Stratify by reentrancy label
        )
        
        return train_df, test_df
    
    def save_dataset_to_csv(self, output_path: str):
        """
        Save full dataset to CSV for inspection/debugging.
        
        Args:
            output_path: Path to save features.csv
        """
        # Implementation will be added in next phase
        pass
    
    def load_labels(self) -> pd.DataFrame:
        """
        Load labels.json as pandas DataFrame.
        
        Returns:
            DataFrame with columns: contract_name, reentrancy, ...
        """
        import json
        with open(self.labels_path, 'r') as f:
            data = json.load(f)
        
        # Flatten nested structure
        rows = []
        for item in data:
            row = {"contract_name": item["contract_name"]}
            row.update(item["labels"])
            rows.append(row)
        
        return pd.DataFrame(rows)
    
    def normalize_features(self, X_train: np.ndarray, X_test: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Standardize features to zero mean and unit variance.
        
        Why normalize?
        - ML models perform better with scaled features
        - Prevents features with large ranges from dominating
        - Random Forest is somewhat robust, but still recommended
        
        Args:
            X_train: Training features
            X_test: Test features
            
        Returns:
            (X_train_scaled, X_test_scaled)
        """
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)  # Use training statistics
        
        return X_train_scaled, X_test_scaled
