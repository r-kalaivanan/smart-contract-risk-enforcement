"""
Dataset Loader Module

Loads the SmartBugs curated dataset structure:
- Discovers all .sol files across vulnerability categories
- Reads vulnerabilities.json for ground truth labels
- Provides iterator for batch processing

Dataset Structure:
    datasets/smartbugs-curated/
        vulnerabilities.json       <- Ground truth labels
        dataset/
            access_control/        <- 18 contracts
            arithmetic/            <- 15 contracts
            bad_randomness/        <- 8 contracts
            denial_of_service/     <- 6 contracts
            front_running/         <- 4 contracts
            reentrancy/            <- 41 contracts
            unchecked_low_level_calls/ <- 24 contracts
            time_manipulation/     <- 11 contracts
            short_addresses/       <- 3 contracts
            other/                 <- 3 contracts
"""

from typing import List, Dict, Optional
from pathlib import Path
import json


class DatasetLoader:
    """
    Loads SmartBugs curated dataset for feature extraction.
    
    Usage:
        loader = DatasetLoader("datasets/smartbugs-curated")
        for contract_info in loader.iter_contracts():
            print(contract_info['path'])
    """
    
    def __init__(self, dataset_root: str):
        """
        Initialize dataset loader.
        
        Args:
            dataset_root: Path to smartbugs-curated directory
        """
        self.dataset_root = Path(dataset_root)
        self.dataset_dir = self.dataset_root / "dataset"
        self.vuln_json_path = self.dataset_root / "vulnerabilities.json"
        
        # Load vulnerability labels
        self.vulnerability_labels = self._load_vulnerability_labels()
        
    def _load_vulnerability_labels(self) -> Dict[str, Dict]:
        """
        Load vulnerabilities.json containing ground truth labels.
        
        Returns:
            Dict mapping contract name to vulnerability info
        """
        if not self.vuln_json_path.exists():
            print(f"Warning: vulnerabilities.json not found at {self.vuln_json_path}")
            return {}
        
        with open(self.vuln_json_path, 'r', encoding='utf-8') as f:
            vuln_list = json.load(f)
        
        # Convert list to dict keyed by contract name
        vuln_dict = {}
        for entry in vuln_list:
            name = entry['name']
            vuln_dict[name] = entry
        
        return vuln_dict
    
    def get_all_contracts(self) -> List[Path]:
        """
        Get paths to all .sol files in the dataset.
        
        Returns:
            List of Path objects to Solidity files
        """
        contracts = []
        
        if not self.dataset_dir.exists():
            print(f"Warning: Dataset directory not found at {self.dataset_dir}")
            return contracts
        
        # Recursively find all .sol files
        for sol_file in self.dataset_dir.rglob("*.sol"):
            # Skip README files
            if sol_file.name.lower() == "readme.md":
                continue
            contracts.append(sol_file)
        
        return sorted(contracts)
    
    def get_contract_category(self, contract_path: Path) -> str:
        """
        Determine vulnerability category from directory structure.
        
        Args:
            contract_path: Path to .sol file
            
        Returns:
            Category name (e.g., 'reentrancy', 'access_control')
        """
        # Get parent directory name
        try:
            relative = contract_path.relative_to(self.dataset_dir)
            category = relative.parts[0] if relative.parts else "unknown"
            return category
        except ValueError:
            return "unknown"
    
    def get_contract_labels(self, contract_name: str) -> Dict:
        """
        Get vulnerability labels for a contract from vulnerabilities.json.
        
        Args:
            contract_name: Name of .sol file (e.g., "simple_dao.sol")
            
        Returns:
            Dict with vulnerability info, or empty dict if not found
        """
        return self.vulnerability_labels.get(contract_name, {})
    
    def iter_contracts(self) -> Dict:
        """
        Iterator yielding contract information for batch processing.
        
        Yields:
            Dict with keys:
                - name: Contract filename
                - path: Full path to .sol file
                - category: Vulnerability category directory
                - labels: Ground truth vulnerability labels from JSON
        """
        for contract_path in self.get_all_contracts():
            contract_name = contract_path.name
            category = self.get_contract_category(contract_path)
            labels = self.get_contract_labels(contract_name)
            
            yield {
                'name': contract_name,
                'path': contract_path,
                'category': category,
                'labels': labels
            }
    
    def get_dataset_stats(self) -> Dict:
        """
        Get statistics about the dataset.
        
        Returns:
            Dict with dataset statistics
        """
        contracts = self.get_all_contracts()
        
        # Count by category
        category_counts = {}
        for contract in contracts:
            category = self.get_contract_category(contract)
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Count labeled vs unlabeled
        labeled_count = len(self.vulnerability_labels)
        
        return {
            'total_contracts': len(contracts),
            'labeled_contracts': labeled_count,
            'unlabeled_contracts': len(contracts) - labeled_count,
            'categories': category_counts
        }
    
    def print_stats(self):
        """Print dataset statistics."""
        stats = self.get_dataset_stats()
        
        print("=" * 60)
        print("SMARTBUGS DATASET STATISTICS")
        print("=" * 60)
        print(f"\nTotal contracts: {stats['total_contracts']}")
        print(f"Labeled contracts: {stats['labeled_contracts']}")
        print(f"Unlabeled contracts: {stats['unlabeled_contracts']}")
        
        print("\nContracts by category:")
        for category, count in sorted(stats['categories'].items()):
            print(f"  {category:30s}: {count:3d}")
