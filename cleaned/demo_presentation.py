"""
SC-GUARD Professional Demo Script

This script demonstrates the complete feature extraction and validation pipeline
for presentation purposes. All outputs are professional.

Demo Flow:
1. Dataset overview
2. Feature extraction on sample contract
3. Comprehensive feature validation
4. Dataset statistics
5. Summary of capabilities
"""

import sys
from pathlib import Path
import pandas as pd
import time

sys.path.insert(0, str(Path(__file__).parent / '..' / 'src'))

# Note: In the cleaned copy we keep the demo script only; Slither and AST modules
# may not be available here. This copy is for presentation and review.


def print_header(title, width=80):
    """Print professional section header."""
    print()
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    print()


def print_subsection(title):
    """Print subsection header."""
    print()
    print(f"--- {title} ---")
    print()


def main():
    print_header("SC-GUARD: Demo (cleaned copy)")
    print("This folder contains the presentation demo and final output example.")
    print("Run this script in the project root where the full modules are available.")


if __name__ == "__main__":
    main()
