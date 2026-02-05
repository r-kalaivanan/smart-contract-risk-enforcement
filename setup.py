"""
Setup script for sc-guard package installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
with open(readme_path, 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
with open(requirements_path, 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="sc-guard",
    version="0.1.0",
    author="sc-guard Development Team",
    description="Smart Contract Vulnerability Detection and Risk-Aware Enforcement System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/sc-guard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sc-guard=src.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml"],
    },
)
