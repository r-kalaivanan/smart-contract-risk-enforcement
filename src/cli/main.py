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
import warnings

# Suppress sklearn version warnings for cleaner output
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')
warnings.filterwarnings('ignore', message='.*InconsistentVersionWarning.*')

# Import sc-guard modules (will be implemented)
# from src.analyzers.slither_analyzer import SlitherAnalyzer
# from src.analyzers.ast_extractor import ASTFeatureExtractor
# from src.analyzers.graph_builder import CallGraphBuilder
# from src.ml.train_model import VulnerabilityClassifier
from src.scoring.risk_engine import RiskScoringEngine  # Needed for display functions
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
@click.option('--report', type=click.Choice(['html', 'pdf'], case_sensitive=False), help='Generate HTML or PDF report')
@click.option('--output', '-o', type=click.Path(), help='Output path for report (auto-generated if not specified)')
def scan(contract_path: str, json_output: bool, verbose: bool, models_dir: str, report: str, output: str):
    """
    Analyze a Solidity contract for vulnerabilities.
    
    Example:
        sc-guard scan mycontract.sol
        sc-guard scan mycontract.sol --json > report.json
        sc-guard scan mycontract.sol --report html
        sc-guard scan mycontract.sol --report pdf --output report.pdf
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
        
        # Import modules
        from src.analyzers.slither_analyzer import SlitherAnalyzer
        from src.analyzers.ast_extractor import ASTFeatureExtractor
        from src.analyzers.graph_builder import CallGraphBuilder
        from src.ml.train_model import VulnerabilityClassifier
        from src.scoring.risk_engine import RiskScoringEngine
        from src.enforcement.policy import PolicyEngine
        
        # Step 1: Run Slither
        analyzer = SlitherAnalyzer(str(contract_path))
        findings = analyzer.analyze()
        
        # Step 2: Extract features
        extractor = ASTFeatureExtractor(analyzer.slither)
        features = extractor.extract()
        
        # Step 3: Add graph metrics
        graph_builder = CallGraphBuilder(analyzer.slither)
        graph_features = graph_builder.analyze()
        features.max_call_depth = graph_features.max_call_depth
        features.has_cycle_with_external_call = graph_features.has_cycles and graph_features.external_calls_in_cycles > 0
        features.external_calls_in_cycles = graph_features.external_calls_in_cycles
        
        feature_vector = features.to_vector().reshape(1, -1)
        
        if verbose and not json_output:
            display_feature_analysis(features, console)
        
        # Phase 2: ML Prediction
        if verbose and not json_output:
            console.print("\n[cyan]→[/cyan] Running ML vulnerability detection...")
        
        # Load models and predict
        models = {}
        ml_predictions = {}
        
        # Map to actual model file names
        model_files = {
            "reentrancy": "reentrancy_rf.pkl",
            "access_control": "access_control_rf.pkl",
            "unchecked_call": "unchecked_external_call_rf.pkl",
            "dangerous_construct": "dangerous_construct_rf.pkl"
        }
        
        for vuln_type, filename in model_files.items():
            model_path = Path(models_dir) / filename
            if model_path.exists():
                try:
                    # Load model using static method
                    model = VulnerabilityClassifier.load_model(str(model_path))
                    models[vuln_type] = model
                    
                    # Get prediction
                    proba = model.predict_proba(feature_vector)
                    if len(proba.shape) > 1:
                        proba_vuln = proba[0]  # Single sample probability
                    else:
                        proba_vuln = proba[0] if proba[0] < 1 else 0.5
                    
                    prediction = 1 if proba_vuln >= 0.5 else 0
                    ml_predictions[vuln_type] = {
                        'prediction': prediction,
                        'proba_vuln': proba_vuln,  # Store the actual vulnerable probability
                        'confidence': proba_vuln if prediction == 1 else (1 - proba_vuln)  # Display confidence
                    }
                except Exception as e:
                    if verbose:
                        console.print(f"[dim]Warning: Could not load {vuln_type} model: {e}[/dim]")
        
        if verbose and not json_output:
            display_ml_predictions(ml_predictions, console)
        
        # Phase 3: Risk Scoring
        if verbose and not json_output:
            console.print("\n[cyan]→[/cyan] Calculating risk score...")
        
        # Calculate risk
        risk_engine = RiskScoringEngine()
        # Use actual vulnerable probability for risk calculation (not display confidence)
        probabilities = {k: v['proba_vuln'] for k, v in ml_predictions.items()}
        risk_obj = risk_engine.calculate_risk(probabilities)
        
        # Convert to dict for easier handling
        risk_assessment = {
            'risk_score': risk_obj.overall_risk_score,
            'risk_category': 'HIGH' if risk_obj.overall_risk_score >= 7 else ('MEDIUM' if risk_obj.overall_risk_score >= 4 else 'LOW'),
            'components': {k: v * RiskScoringEngine.VULNERABILITY_WEIGHTS.get(k, 1.0) for k, v in probabilities.items()},
            'confidence': risk_obj.confidence
        }
        
        if verbose and not json_output:
            display_risk_breakdown(risk_assessment, console)
        
        # Phase 4: Enforcement
        if verbose and not json_output:
            console.print("\n[cyan]→[/cyan] Applying enforcement policy...\n")
        
        # Make decision
        policy_engine = PolicyEngine()
        detected_vulns = [k for k, v in ml_predictions.items() if v['prediction'] == 1]
        result_obj = policy_engine.enforce(
            risk_score=risk_assessment['risk_score'],
            risk_category=risk_assessment['risk_category'],
            vulnerability_probabilities=probabilities,
            static_findings=findings
        )
        result = result_obj.to_dict()
        
        # Display results
        if json_output:
            result['feature_vector'] = features.to_vector().tolist()
            result['ml_predictions'] = ml_predictions
            result['risk_assessment'] = risk_assessment
            print(json.dumps(result, indent=2))
        else:
            display_results(result, contract_path.name)
        
        # Generate report if requested
        if report:
            from src.reporting.html_generator import generate_report
            from datetime import datetime
            
            # Prepare comprehensive result for report
            report_data = {
                **result,
                'ml_predictions': ml_predictions,
                'risk_assessment': risk_assessment,
                'features': {
                    'external_call_count': features.external_call_count,
                    'delegatecall_count': features.delegatecall_count,
                    'send_transfer_count': features.send_transfer_count,
                    'state_writes_before_call': features.state_writes_before_call,
                    'state_writes_after_call': features.state_writes_after_call,
                    'public_function_count': features.public_function_count,
                    'external_function_count': features.external_function_count,
                    'private_function_count': features.private_function_count,
                    'has_access_control_modifier': features.has_access_control_modifier,
                    'has_reentrancy_guard': features.has_reentrancy_guard,
                    'uses_tx_origin': features.uses_tx_origin,
                    'has_selfdestruct': features.has_selfdestruct,
                    'unchecked_call_count': features.unchecked_call_count,
                    'max_call_depth': features.max_call_depth,
                    'has_cycle_with_external_call': features.has_cycle_with_external_call,
                    'external_calls_in_cycles': features.external_calls_in_cycles
                }
            }
            
            # Determine output path
            if output:
                output_path = Path(output)
            else:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                base_name = contract_path.stem
                output_path = Path(f"outputs/{base_name}_{timestamp}.{report}")
            
            # Generate report
            if not json_output:
                console.print(f"\n[cyan]→[/cyan] Generating {report.upper()} report...")
            
            success = generate_report(report_data, contract_path.name, report, output_path)
            
            if success and not json_output:
                console.print(f"[green]✓[/green] Report saved: {output_path}")
    
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


def display_feature_analysis(features, console):
    """Display extracted security features in a nice table."""  
    from src.analyzers.ast_extractor import ContractFeatures
    
    console.print("\n[bold cyan] Extracted Security Features (16 dimensions):[/bold cyan]")
    
    # Create feature table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Feature", style="dim", width=35)
    table.add_column("Value", justify="right")
    table.add_column("Risk Indicator", width=30)
    
    feature_interpretations = {
        'external_call_count': ('High count = more attack surface', 'yellow' if features.external_call_count > 2 else 'green'),
        'delegatecall_count': ('Any delegatecall = risky', 'red' if features.delegatecall_count > 0 else 'green'),
        'send_transfer_count': ('Ether transfers', 'yellow' if features.send_transfer_count > 0 else 'dim'),
        'state_writes_before_call': ('State changes before call', 'dim'),
        'state_writes_after_call': ('Reentrancy risk if > 0', 'red' if features.state_writes_after_call > 0 else 'green'),
        'public_function_count': ('Attack entry points', 'yellow' if features.public_function_count > 5 else 'dim'),
        'external_function_count': ('External interfaces', 'dim'),
        'private_function_count': ('Internal functions', 'dim'),
        'has_access_control_modifier': ('Onlyowner/modifiers', 'green' if features.has_access_control_modifier else 'red'),
        'has_reentrancy_guard': ('ReentrancyGuard modifier', 'green' if features.has_reentrancy_guard else 'yellow'),
        'uses_tx_origin': ('AUTH vulnerability!', 'red' if features.uses_tx_origin else 'green'),
        'has_selfdestruct': ('Contract can self-destruct', 'yellow' if features.has_selfdestruct else 'dim'),
        'unchecked_call_count': ('Unchecked external calls', 'red' if features.unchecked_call_count > 0 else 'green'),
        'max_call_depth': ('Function call depth', 'yellow' if features.max_call_depth > 3 else 'dim'),
        'has_cycle_with_external_call': ('Cyclic call + ext call', 'red' if features.has_cycle_with_external_call else 'green'),
        'external_calls_in_cycles': ('Ext calls in loops', 'red' if features.external_calls_in_cycles > 0 else 'green'),
    }
    
    feature_names = ContractFeatures.feature_names()
    feature_values = features.to_vector()
    
    for name, value in zip(feature_names, feature_values):
        interpretation, color = feature_interpretations.get(name, ('', 'dim'))
        value_str = f"[bold white]{int(value)}[/bold white]" if value > 0 else f"[dim]{int(value)}[/dim]"
        table.add_row(
            name,
            value_str,
            f"[{color}]{interpretation}[/{color}]"
        )
    
    console.print(table)


def display_ml_predictions(ml_predictions, console):
    """Display ML model predictions with confidence scores."""
    console.print("\n[bold cyan] Machine Learning Predictions:[/bold cyan]")
    console.print("[dim]4 Random Forest classifiers (100 trees each, max_depth=10)[/dim]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Vulnerability Type", width=25)
    table.add_column("Prediction", justify="center", width=15)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Risk Level", width=20)
    
    vuln_display_names = {
        'reentrancy': 'Reentrancy',
        'access_control': 'Access Control',
        'unchecked_call': 'Unchecked Call',
        'dangerous_construct': 'Dangerous Construct'
    }
    
    for vuln_type, prediction_data in ml_predictions.items():
        pred = prediction_data['prediction']
        conf = prediction_data['confidence']
        
        if pred == 1:
            pred_str = "[bold red]VULNERABLE[/bold red]"
            conf_str = f"[red]{conf*100:.1f}%[/red]"
            if conf >= 0.8:
                risk_str = "[red]HIGH CONFIDENCE[/red]"
            elif conf >= 0.6:
                risk_str = "[yellow]MODERATE[/yellow]"
            else:
                risk_str = "[yellow]LOW CONFIDENCE[/yellow]"
        else:
            pred_str = "[green]SAFE[/green]"
            conf_str = f"[green]{conf*100:.1f}%[/green]"
            # Show confidence assessment for SAFE predictions too
            if conf >= 0.8:
                risk_str = "[green]HIGH CONFIDENCE[/green]"
            elif conf >= 0.6:
                risk_str = "[dim]MODERATE[/dim]"
            else:
                risk_str = "[yellow]LOW CONFIDENCE[/yellow]"
        
        table.add_row(
            vuln_display_names.get(vuln_type, vuln_type),
            pred_str,
            conf_str,
            risk_str
        )
    
    console.print(table)


def display_risk_breakdown(risk_assessment, console):
    """Display risk score calculation breakdown."""
    console.print("\n[bold cyan] Risk Score Calculation:[/bold cyan]")
    
    risk_score = risk_assessment['risk_score']
    risk_category = risk_assessment['risk_category']
    
    # Show formula
    console.print("\n[dim]Formula: Σ(vulnerability_weight × ML_confidence)[/dim]")
    console.print("[dim]Weights: reentrancy=3.0, access_control=2.5, unchecked_call=2.0, dangerous=2.5[/dim]\n")
    
    # Show breakdown table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", width=25)
    table.add_column("Weight", justify="center")
    table.add_column("ML Confidence", justify="center")
    table.add_column("Contribution", justify="right")
    
    # Use actual weights from RiskScoringEngine
    weights = RiskScoringEngine.VULNERABILITY_WEIGHTS.copy()
    # Map the key names used in display to actual model names
    weights['unchecked_call'] = weights.get('unchecked_external_call', 2.0)
    
    if 'components' in risk_assessment:
        for vuln_type, contribution in risk_assessment['components'].items():
            weight = weights.get(vuln_type, 0)
            conf = contribution / weight if weight > 0 else 0
            table.add_row(
                vuln_type.replace('_', ' ').title(),
                f"{weight:.1f}",
                f"{conf*100:.1f}%",
                f"[cyan]{contribution:.2f}[/cyan]"
            )
    
    console.print(table)
    
    # Show final score
    if risk_category == "HIGH":
        score_color = "red"
    elif risk_category == "MEDIUM":
        score_color = "yellow"
    else:
        score_color = "green"
    
    console.print(f"\n[bold]Total Risk Score: [{score_color}]{risk_score:.1f}/10[/{score_color}] ({risk_category})[/bold]")


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
