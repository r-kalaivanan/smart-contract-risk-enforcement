"""
HTML Report Generator

Generates HTML and PDF security reports from scan results.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json


class HTMLReportGenerator:
    """
    Generate HTML reports from scan results.
    
    Features:
    - Beautiful, responsive HTML design
    - Executive summary
    - Detailed vulnerability analysis
    - Security recommendations
    - Optional PDF export
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialize report generator.
        
        Args:
            templates_dir: Path to templates directory. If None, uses default location.
        """
        if templates_dir is None:
            # Default to templates/ in project root
            templates_dir = Path(__file__).parent.parent.parent / "templates"
        
        self.templates_dir = Path(templates_dir)
        
        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate_html(
        self,
        scan_result: Dict[str, Any],
        contract_name: str,
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate HTML report from scan results.
        
        Args:
            scan_result: Complete scan result dictionary
            contract_name: Name of the scanned contract
            output_path: Optional path to save HTML file. If None, returns HTML string.
            
        Returns:
            str: HTML content
        """
        # Load template
        template = self.env.get_template('report.html')
        
        # Prepare template context
        context = {
            'contract_name': contract_name,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'decision': scan_result.get('decision', 'UNKNOWN'),
            'risk_score': scan_result.get('risk_score', 0),
            'risk_category': scan_result.get('risk_category', 'UNKNOWN'),
            'detected_vulnerabilities': scan_result.get('detected_vulnerabilities', []),
            'justification': scan_result.get('justification', 'No justification provided.'),
            'recommendations': scan_result.get('recommendations', []),
            'ml_predictions': scan_result.get('ml_predictions'),
            'risk_assessment': scan_result.get('risk_assessment'),
            'features': scan_result.get('features')
        }
        
        # Render template
        html_content = template.render(**context)
        
        # Save to file if path provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding='utf-8')
            print(f"✅ HTML report saved to: {output_path}")
        
        return html_content
    
    def generate_pdf(
        self,
        scan_result: Dict[str, Any],
        contract_name: str,
        output_path: Path
    ) -> bool:
        """
        Generate PDF report from scan results.
        
        Requires weasyprint library for HTML to PDF conversion.
        
        Args:
            scan_result: Complete scan result dictionary
            contract_name: Name of the scanned contract
            output_path: Path to save PDF file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            from weasyprint import HTML
        except ImportError:
            print("❌ Error: weasyprint not installed. Run: pip install weasyprint")
            return False
        
        try:
            # Generate HTML first
            html_content = self.generate_html(scan_result, contract_name)
            
            # Convert to PDF
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            HTML(string=html_content).write_pdf(
                str(output_path),
                stylesheets=None,
                presentational_hints=True
            )
            
            print(f"✅ PDF report saved to: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return False
    
    def generate_json(
        self,
        scan_result: Dict[str, Any],
        output_path: Path,
        pretty: bool = True
    ) -> bool:
        """
        Save scan results as JSON file.
        
        Args:
            scan_result: Complete scan result dictionary
            output_path: Path to save JSON file
            pretty: Whether to pretty-print JSON (default: True)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(scan_result, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(scan_result, f, ensure_ascii=False)
            
            print(f"✅ JSON report saved to: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error generating JSON: {e}")
            return False


def generate_report(
    scan_result: Dict[str, Any],
    contract_name: str,
    output_format: str = 'html',
    output_path: Optional[Path] = None
) -> bool:
    """
    Convenience function to generate reports in various formats.
    
    Args:
        scan_result: Complete scan result dictionary
        contract_name: Name of the scanned contract
        output_format: Output format ('html', 'pdf', or 'json')
        output_path: Path to save report. If None, auto-generates filename.
        
    Returns:
        bool: True if successful, False otherwise
        
    Example:
        >>> from src.reporting.html_generator import generate_report
        >>> generate_report(result, "MyContract.sol", "html", "report.html")
    """
    if output_path is None:
        # Auto-generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{contract_name.replace('.sol', '')}_{timestamp}"
        output_path = Path(f"outputs/{base_name}.{output_format}")
    
    generator = HTMLReportGenerator()
    
    if output_format.lower() == 'html':
        generator.generate_html(scan_result, contract_name, output_path)
        return True
    elif output_format.lower() == 'pdf':
        return generator.generate_pdf(scan_result, contract_name, output_path)
    elif output_format.lower() == 'json':
        return generator.generate_json(scan_result, output_path)
    else:
        print(f"❌ Unsupported format: {output_format}")
        return False


# Example usage
if __name__ == "__main__":
    # Sample scan result for testing
    sample_result = {
        "decision": "WARN",
        "risk_score": 5.2,
        "risk_category": "MEDIUM",
        "detected_vulnerabilities": ["reentrancy", "access_control"],
        "justification": "Risk score 5.2/10 indicates moderate risk. Potential vulnerabilities detected.",
        "recommendations": [
            "Implement checks-effects-interactions pattern",
            "Add ReentrancyGuard modifier from OpenZeppelin",
            "Use transfer() instead of call() for ETH transfers"
        ],
        "ml_predictions": {
            "reentrancy": {
                "prediction": 1,
                "proba_vuln": 0.85,
                "confidence": 0.85
            },
            "access_control": {
                "prediction": 1,
                "proba_vuln": 0.72,
                "confidence": 0.72
            }
        }
    }
    
    # Generate HTML report
    generator = HTMLReportGenerator()
    generator.generate_html(sample_result, "TestContract.sol", Path("test_report.html"))
    print("Test report generated!")
