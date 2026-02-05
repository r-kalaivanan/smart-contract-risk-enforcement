#!/usr/bin/env python3
"""
sc-guard CLI - Smart Contract Vulnerability Scanner

Usage:
    sc-guard scan Contract.sol              # Analyze single contract
    sc-guard scan contracts/ --recursive     # Analyze directory
    sc-guard scan Contract.sol --json        # JSON output
    sc-guard train --dataset datasets/       # Train ML models
    sc-guard version                         # Show version

Why Click Framework?
- Decorator-based API (clean, readable)
- Automatic help generation
- Argument validation
- Cross-platform support

Why Rich Library?
- Beautiful terminal tables
- Colored output (red for BLOCK, yellow for WARN, green for ALLOW)
- Progress bars for batch processing
- Markdown rendering in terminal
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from pathlib import Path
import json
import sys

# Import sc-guard modules (will be implemented)
# from src.analyzers.slither_analyzer import SlitherAnalyzer
# from src.analyzers.ast_extractor import ASTFeatureExtractor
# from src.analyzers.graph_builder import CallGraphBuilder
# from src.ml.train_model import VulnerabilityClassifier
# from src.scoring.risk_engine import RiskScoringEngine
# from src.enforcement.policy import PolicyEngine

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="sc-guard")
def cli():
    """
    sc-guard: Smart Contract Vulnerability Detection System
    
    A static analysis and ML-based tool for detecting high-risk 
    vulnerabilities in Solidity smart contracts.
    """
    pass


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='Output results as JSON')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed analysis')
@click.option('--models-dir', default='models/', help='Directory containing trained models')
def scan(contract_path: str, json_output: bool, verbose: bool, models_dir: str):
    """
    Analyze a Solidity contract for vulnerabilities.
    
    Example:
        sc-guard scan mycontract.sol
        sc-guard scan mycontract.sol --json > report.json
    """
    contract_path = Path(contract_path)
    
    if not contract_path.exists():
        console.print(f"[red]Error:[/red] Contract file not found: {contract_path}")
        sys.exit(1)
    
    if not contract_path.suffix == '.sol':
        console.print(f"[red]Error:[/red] File must be a Solidity contract (.sol)")
        sys.exit(1)
    
    # Show banner
    if not json_output:
        console.print(Panel.fit(
            "[bold cyan]sc-guard[/bold cyan] Smart Contract Scanner",
            border_style="cyan"
        ))
        console.print(f"[dim]Analyzing:[/dim] {contract_path.name}\n")
    
    try:
        # Phase 1: Static Analysis
        if verbose and not json_output:
            console.print("[cyan]→[/cyan] Running static analysis...")
        
        # TODO: Implement in next phase
        # analyzer = SlitherAnalyzer(str(contract_path))
        # findings = analyzer.analyze()
        # features = ASTFeatureExtractor(analyzer.slither).extract()
        # graph_metrics = CallGraphBuilder(analyzer.slither).analyze()
        
        # Phase 2: ML Prediction
        if verbose and not json_output:
            console.print("[cyan]→[/cyan] Running ML vulnerability detection...")
        
        # TODO: Load models and predict
        # probabilities = {...}
        
        # Phase 3: Risk Scoring
        if verbose and not json_output:
            console.print("[cyan]→[/cyan] Calculating risk score...")
        
        # TODO: Calculate risk
        # risk_engine = RiskScoringEngine()
        # risk_assessment = risk_engine.calculate_risk(probabilities)
        
        # Phase 4: Enforcement
        if verbose and not json_output:
            console.print("[cyan]→[/cyan] Applying enforcement policy...\n")
        
        # TODO: Make decision
        # policy_engine = PolicyEngine()
        # result = policy_engine.enforce(...)
        
        # PLACEHOLDER OUTPUT (remove after implementation)
        result = {
            "decision": "WARN",
            "risk_score": 5.2,
            "risk_category": "MEDIUM",
            "detected_vulnerabilities": ["reentrancy"],
            "justification": "Moderate risk detected",
            "recommendations": [
                "Implement checks-effects-interactions pattern",
                "Add ReentrancyGuard modifier"
            ]
        }
        
        # Display results
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            display_results(result, contract_path.name)
    
    except Exception as e:
        if json_output:
            print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red]Error during analysis:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--dataset', required=True, help='Path to dataset directory')
@click.option('--output-dir', default='models/', help='Directory to save trained models')
@click.option('--test-split', default=0.3, help='Fraction of data for testing (default 0.3)')
def train(dataset: str, output_dir: str, test_split: float):
    """
    Train ML models on labeled dataset.
    
    Example:
        sc-guard train --dataset datasets/smartbugs-curated/
    """
    console.print(Panel.fit(
        "[bold cyan]sc-guard[/bold cyan] Model Training",
        border_style="cyan"
    ))
    
    console.print(f"\n[cyan]Dataset:[/cyan] {dataset}")
    console.print(f"[cyan]Output:[/cyan] {output_dir}")
    console.print(f"[cyan]Test Split:[/cyan] {test_split:.0%}\n")
    
    # TODO: Implement training pipeline
    console.print("[yellow]Training not yet implemented[/yellow]")
    console.print("This will be implemented in Phase 5 (ML Module)")


@cli.command()
def version():
    """Show sc-guard version and dependencies."""
    console.print("[bold cyan]sc-guard[/bold cyan] v0.1.0")
    console.print("Python Smart Contract Vulnerability Scanner\n")
    
    console.print("[dim]Dependencies:[/dim]")
    console.print("  - Slither (static analysis)")
    console.print("  - scikit-learn (machine learning)")
    console.print("  - networkx (graph analysis)")


def display_results(result: dict, contract_name: str):
    """
    Display analysis results in terminal.
    
    Args:
        result: Enforcement result dictionary
        contract_name: Name of analyzed contract
    """
    # Risk Score Panel
    decision = result["decision"]
    risk_score = result["risk_score"]
    risk_category = result["risk_category"]
    
    # Color based on decision
    if decision == "ALLOW":
        color = "green"
        icon = "✓"
    elif decision == "WARN":
        color = "yellow"
        icon = "⚠"
    else:  # BLOCK
        color = "red"
        icon = "✗"
    
    console.print(Panel(
        f"[bold {color}]{icon} {decision}[/bold {color}]\n"
        f"Risk Score: [{color}]{risk_score:.1f}/10[/{color}] ({risk_category})",
        title=f"[bold]Decision for {contract_name}[/bold]",
        border_style=color
    ))
    
    # Detected Vulnerabilities
    if result.get("detected_vulnerabilities"):
        console.print("\n[bold red]Detected Vulnerabilities:[/bold red]")
        for vuln in result["detected_vulnerabilities"]:
            console.print(f"  • {vuln}")
    
    # Justification
    console.print(f"\n[bold]Justification:[/bold]")
    console.print(f"  {result['justification']}")
    
    # Recommendations
    if result.get("recommendations"):
        console.print(f"\n[bold cyan]Recommendations:[/bold cyan]")
        for i, rec in enumerate(result["recommendations"], 1):
            console.print(f"  {i}. {rec}")


if __name__ == '__main__':
    cli()
