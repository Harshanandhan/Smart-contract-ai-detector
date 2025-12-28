#!/usr/bin/env python3
"""
AI/ML Smart Contract Vulnerability Detector
Main detection script

Author: Harshanandhan Reddy Gajulapalli
Email: harshanandhanreddy820@gmail.com
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add utils to path
sys.path.insert(0, str(Path(__file__).parent / 'utils'))

try:
    from utils.feature_extractor import FeatureExtractor
    from utils.slither_integration import SlitherAnalyzer
    from utils.report_generator import ReportGenerator
except ImportError:
    print(f"{Fore.YELLOW}[!] Utils modules not found. Some features may be limited.")


class SmartContractDetector:
    """Main detector class combining AI/ML models"""
    
    def __init__(self, model_type='hybrid', device='cpu'):
        """
        Initialize detector
        
        Args:
            model_type: 'codebert', 'lstm', or 'hybrid'
            device: 'cpu' or 'cuda'
        """
        self.model_type = model_type
        self.device = device
        
        print(f"{Fore.CYAN}[*] Initializing {model_type} detector...")
        
        # Load CodeBERT model
        if model_type in ['codebert', 'hybrid']:
            self.codebert_tokenizer = self._load_codebert_tokenizer()
            self.codebert_model = self._load_codebert_model()
        
        # Load LSTM model
        if model_type in ['lstm', 'hybrid']:
            self.lstm_model = self._load_lstm_model()
        
        # Initialize Slither analyzer
        try:
            self.slither = SlitherAnalyzer()
        except:
            self.slither = None
            print(f"{Fore.YELLOW}[!] Slither not available")
    
    def _load_codebert_tokenizer(self):
        """Load CodeBERT tokenizer"""
        try:
            tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
            print(f"{Fore.GREEN}[+] CodeBERT tokenizer loaded")
            return tokenizer
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load CodeBERT tokenizer: {e}")
            return None
    
    def _load_codebert_model(self):
        """Load fine-tuned CodeBERT model"""
        try:
            # Try to load fine-tuned model first
            model_path = Path('models/codebert_finetuned.pt')
            
            if model_path.exists():
                model = AutoModelForSequenceClassification.from_pretrained(
                    "microsoft/codebert-base",
                    num_labels=2
                )
                model.load_state_dict(torch.load(model_path, map_location=self.device))
                model.eval()
                print(f"{Fore.GREEN}[+] Fine-tuned CodeBERT model loaded")
            else:
                # Use base model for demo
                print(f"{Fore.YELLOW}[!] Fine-tuned model not found, using base CodeBERT")
                model = AutoModelForSequenceClassification.from_pretrained(
                    "microsoft/codebert-base",
                    num_labels=2
                )
                model.eval()
            
            return model.to(self.device)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load CodeBERT model: {e}")
            return None
    
    def _load_lstm_model(self):
        """Load LSTM model"""
        try:
            import tensorflow as tf
            model_path = Path('models/lstm_detector.h5')
            
            if model_path.exists():
                model = tf.keras.models.load_model(str(model_path))
                print(f"{Fore.GREEN}[+] LSTM model loaded")
                return model
            else:
                print(f"{Fore.YELLOW}[!] LSTM model not found")
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load LSTM model: {e}")
            return None
    
    def analyze(self, code: str, chain='ethereum') -> Dict:
        """
        Analyze smart contract for vulnerabilities
        
        Args:
            code: Solidity source code
            chain: Blockchain (ethereum, polygon, bsc)
        
        Returns:
            Dictionary with detection results
        """
        print(f"\n{Fore.CYAN}[*] Analyzing contract on {chain}...")
        
        results = {
            'code': code[:200] + '...',  # Truncate for display
            'chain': chain,
            'vulnerabilities': [],
            'models_used': [],
            'overall_risk': 'Unknown'
        }
        
        # CodeBERT Analysis
        if self.model_type in ['codebert', 'hybrid'] and self.codebert_model:
            codebert_result = self._analyze_with_codebert(code)
            results['models_used'].append('CodeBERT')
            if codebert_result['vulnerable']:
                results['vulnerabilities'].extend(codebert_result['findings'])
        
        # LSTM Analysis
        if self.model_type in ['lstm', 'hybrid'] and self.lstm_model:
            lstm_result = self._analyze_with_lstm(code)
            results['models_used'].append('LSTM')
            if lstm_result['vulnerable']:
                results['vulnerabilities'].extend(lstm_result['findings'])
        
        # Slither Analysis
        if self.slither:
            slither_result = self._analyze_with_slither(code)
            results['models_used'].append('Slither')
            if slither_result['findings']:
                results['vulnerabilities'].extend(slither_result['findings'])
        
        # Calculate overall risk
        results['overall_risk'] = self._calculate_risk(results['vulnerabilities'])
        
        return results
    
    def _analyze_with_codebert(self, code: str) -> Dict:
        """Analyze using CodeBERT"""
        try:
            # Tokenize
            inputs = self.codebert_tokenizer(
                code,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            )
            
            # Predict
            with torch.no_grad():
                outputs = self.codebert_model(**inputs.to(self.device))
                predictions = torch.softmax(outputs.logits, dim=1)
                vulnerable_prob = predictions[0][1].item()
            
            # Interpret results
            findings = []
            if vulnerable_prob > 0.7:  # High confidence threshold
                findings.append({
                    'type': 'AI-Detected Vulnerability',
                    'severity': 'HIGH' if vulnerable_prob > 0.85 else 'MEDIUM',
                    'confidence': f"{vulnerable_prob * 100:.1f}%",
                    'model': 'CodeBERT',
                    'description': 'AI model detected potential vulnerability pattern',
                    'line': 0  # Would need AST parsing for exact line
                })
            
            return {
                'vulnerable': vulnerable_prob > 0.7,
                'confidence': vulnerable_prob,
                'findings': findings
            }
            
        except Exception as e:
            print(f"{Fore.RED}[!] CodeBERT analysis failed: {e}")
            return {'vulnerable': False, 'findings': []}
    
    def _analyze_with_lstm(self, code: str) -> Dict:
        """Analyze using LSTM (placeholder - would use opcodes)"""
        # This would:
        # 1. Compile to bytecode
        # 2. Extract opcodes
        # 3. Tokenize opcodes
        # 4. Run through LSTM
        
        # For demo purposes
        return {
            'vulnerable': False,
            'findings': []
        }
    
    def _analyze_with_slither(self, code: str) -> Dict:
        """Analyze using Slither static analyzer"""
        if not self.slither:
            return {'findings': []}
        
        try:
            findings = self.slither.analyze(code)
            return {'findings': findings}
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Slither analysis failed: {e}")
            return {'findings': []}
    
    def _calculate_risk(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level"""
        if not vulnerabilities:
            return 'LOW'
        
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        
        if critical_count > 0 or high_count >= 2:
            return 'CRITICAL'
        elif high_count > 0:
            return 'HIGH'
        elif len(vulnerabilities) >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def analyze_file(self, filepath: str, chain='ethereum') -> Dict:
        """Analyze contract from file"""
        try:
            with open(filepath, 'r') as f:
                code = f.read()
            return self.analyze(code, chain)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {filepath}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}")
            return None
    
    def generate_report(self, results: Dict, output_path: Optional[str] = None):
        """Generate PDF report"""
        try:
            report_gen = ReportGenerator(results)
            if output_path:
                report_gen.generate_pdf(output_path)
                print(f"{Fore.GREEN}[+] Report saved: {output_path}")
            else:
                # Generate with timestamp
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"vuln_report_{timestamp}.pdf"
                report_gen.generate_pdf(filename)
                print(f"{Fore.GREEN}[+] Report saved: {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Report generation failed: {e}")


def print_results(results: Dict):
    """Print scan results to console"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}SCAN RESULTS")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    print(f"{Fore.YELLOW}Chain: {results['chain']}")
    print(f"{Fore.YELLOW}Models Used: {', '.join(results['models_used'])}")
    print(f"{Fore.YELLOW}Overall Risk: {Style.BRIGHT}{results['overall_risk']}\n")
    
    if not results['vulnerabilities']:
        print(f"{Fore.GREEN}[+] No vulnerabilities detected!")
    else:
        print(f"{Fore.RED}[!] Found {len(results['vulnerabilities'])} potential vulnerabilities:\n")
        
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            severity_color = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.GREEN
            }.get(vuln.get('severity', 'MEDIUM'), Fore.WHITE)
            
            print(f"{severity_color}[{i}] {vuln.get('type', 'Unknown')}")
            print(f"    Severity: {vuln.get('severity', 'N/A')}")
            print(f"    Confidence: {vuln.get('confidence', 'N/A')}")
            print(f"    Model: {vuln.get('model', 'N/A')}")
            print(f"    Description: {vuln.get('description', 'N/A')}")
            if vuln.get('line'):
                print(f"    Line: {vuln['line']}")
            print()
    
    print(f"{Fore.CYAN}{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='AI/ML Smart Contract Vulnerability Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python detector.py --file MyToken.sol
  python detector.py --file MyToken.sol --model hybrid --chain polygon
  python detector.py --file MyToken.sol --report output.pdf
  python detector.py --dir contracts/ --json results.json

Author: Harshanandhan Reddy Gajulapalli
Email: harshanandhanreddy820@gmail.com
        '''
    )
    
    parser.add_argument('--file', help='Solidity file to analyze')
    parser.add_argument('--dir', help='Directory of contracts to analyze')
    parser.add_argument('--model', choices=['codebert', 'lstm', 'hybrid'], 
                        default='hybrid', help='Detection model (default: hybrid)')
    parser.add_argument('--chain', default='ethereum', 
                        choices=['ethereum', 'polygon', 'bsc'],
                        help='Blockchain network')
    parser.add_argument('--report', help='Generate PDF report')
    parser.add_argument('--json', help='Export results as JSON')
    parser.add_argument('--device', choices=['cpu', 'cuda'], default='cpu',
                        help='Device for AI models')
    
    args = parser.parse_args()
    
    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)
    
    # Initialize detector
    detector = SmartContractDetector(model_type=args.model, device=args.device)
    
    # Analyze file
    if args.file:
        results = detector.analyze_file(args.file, chain=args.chain)
        
        if results:
            print_results(results)
            
            # Generate report
            if args.report:
                detector.generate_report(results, args.report)
            
            # Export JSON
            if args.json:
                with open(args.json, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"{Fore.GREEN}[+] Results exported: {args.json}")
    
    # Batch analyze directory
    elif args.dir:
        print(f"{Fore.CYAN}[*] Batch analysis not yet implemented")
        print(f"{Fore.YELLOW}[!] Feature coming in next version")


if __name__ == '__main__':
    main()
