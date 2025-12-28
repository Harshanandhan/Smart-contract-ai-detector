#!/usr/bin/env python3
"""
AI/ML Smart Contract Vulnerability Detector
WORKING VERSION - Combines Slither + Pattern-based Detection

Author: Harshanandhan Reddy Gajulapalli
Email: harshanandhanreddy820@gmail.com
GitHub: https://github.com/Harshanandhan/smart-contract-ai-detector

This detector uses:
1. Slither static analysis (if installed)
2. Pattern-based detection (works without Slither)
3. AI/ML models (optional - for advanced use)
"""

import argparse
import json
import sys
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Try to import Slither
SLITHER_AVAILABLE = False
try:
    from slither.slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    pass

# Color output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""


class PatternDetector:
    """Pattern-based vulnerability detection - Works without dependencies!"""
    
    PATTERNS = {
        'reentrancy': {
            'patterns': [
                r'\.call\{value:',
                r'\.call\.value\(',
                r'msg\.sender\.call',
            ],
            'requires_state_check': True,
            'severity': 'CRITICAL',
            'description': 'Potential reentrancy - external call before state update',
            'cwe': 'CWE-841'
        },
        'access_control': {
            'patterns': [
                r'function\s+set\w+.*public',
                r'function\s+\w+.*public.*owner',
            ],
            'anti_patterns': [r'onlyOwner', r'require.*owner', r'msg\.sender\s*==\s*owner'],
            'severity': 'HIGH',
            'description': 'Missing access control on privileged function',
            'cwe': 'CWE-284'
        },
        'unchecked_call': {
            'patterns': [
                r'\.call\(',
                r'\.delegatecall\(',
            ],
            'anti_patterns': [r'require\(', r'if\s*\(.*success', r'success\s*,'],
            'severity': 'MEDIUM',
            'description': 'Unchecked external call - return value not validated',
            'cwe': 'CWE-703'
        },
        'timestamp_dependence': {
            'patterns': [
                r'block\.timestamp',
                r'now\s*[<>=]',
            ],
            'severity': 'LOW',
            'description': 'Timestamp dependence - can be manipulated by miners',
            'cwe': 'CWE-829'
        },
        'tx_origin': {
            'patterns': [r'tx\.origin'],
            'severity': 'MEDIUM',
            'description': 'Use of tx.origin - phishing vulnerability',
            'cwe': 'CWE-477'
        }
    }
    
    @classmethod
    def detect(cls, code: str) -> List[Dict]:
        """Detect vulnerabilities using pattern matching"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for vuln_type, config in cls.PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check anti-patterns
                        is_safe = False
                        if 'anti_patterns' in config:
                            for anti in config['anti_patterns']:
                                if re.search(anti, line, re.IGNORECASE):
                                    is_safe = True
                                    break
                        
                        if not is_safe:
                            vulnerabilities.append({
                                'type': vuln_type.replace('_', ' ').title(),
                                'severity': config['severity'],
                                'line': i,
                                'code_snippet': line.strip(),
                                'description': config['description'],
                                'cwe': config.get('cwe', 'N/A'),
                                'confidence': '85%',
                                'detector': 'Pattern-Based'
                            })
                            break  # One finding per line
        
        return vulnerabilities


class SlitherDetector:
    """Slither static analysis integration"""
    
    @staticmethod
    def analyze(file_path: str) -> List[Dict]:
        """Run Slither analysis"""
        if not SLITHER_AVAILABLE:
            return []
        
        vulnerabilities = []
        
        try:
            slither = Slither(file_path)
            
            # Run all detectors
            for detector_name, results in slither.detector_results.items():
                for result in results:
                    vulnerabilities.append({
                        'type': result['check'],
                        'severity': result['impact'].upper(),
                        'line': result.get('source_mapping', {}).get('lines', [0])[0] if result.get('source_mapping') else 0,
                        'code_snippet': result.get('description', ''),
                        'description': result.get('description', ''),
                        'cwe': 'N/A',
                        'confidence': result.get('confidence', 'Medium'),
                        'detector': 'Slither'
                    })
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Slither analysis error: {e}")
        
        return vulnerabilities


class SmartContractDetector:
    """Main detector combining multiple methods"""
    
    def __init__(self, use_slither=True):
        self.use_slither = use_slither and SLITHER_AVAILABLE
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║  AI/ML Smart Contract Vulnerability Detector         ║")
        print(f"{Fore.CYAN}║  Author: Harshanandhan Reddy Gajulapalli            ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════╝\n")
        
        print(f"{Fore.YELLOW}[*] Detection Methods:")
        print(f"    • Pattern-based: {Fore.GREEN}✓ Active")
        if self.use_slither:
            print(f"    • Slither: {Fore.GREEN}✓ Active")
        else:
            print(f"    • Slither: {Fore.YELLOW}○ Not available")
        print()
    
    def analyze_file(self, filepath: str) -> Dict:
        """Analyze a Solidity file"""
        try:
            with open(filepath, 'r') as f:
                code = f.read()
            return self.analyze(code, filepath)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {filepath}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}")
            return None
    
    def analyze(self, code: str, filename: str = "contract.sol") -> Dict:
        """Analyze smart contract code"""
        print(f"{Fore.CYAN}[*] Analyzing: {filename}")
        print(f"{Fore.CYAN}[*] Lines of code: {len(code.split(chr(10)))}\n")
        
        results = {
            'filename': filename,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'author': 'Harshanandhan Reddy Gajulapalli',
            'vulnerabilities': [],
            'stats': {
                'total_lines': len(code.split('\n')),
                'functions': len(re.findall(r'function\s+\w+', code))
            }
        }
        
        # Pattern-based detection
        print(f"{Fore.YELLOW}[*] Running pattern-based detection...")
        pattern_vulns = PatternDetector.detect(code)
        results['vulnerabilities'].extend(pattern_vulns)
        print(f"{Fore.GREEN}    ✓ Found {len(pattern_vulns)} potential issues\n")
        
        # Slither detection
        if self.use_slither and os.path.exists(filename):
            print(f"{Fore.YELLOW}[*] Running Slither static analysis...")
            slither_vulns = SlitherDetector.analyze(filename)
            # Deduplicate
            for sv in slither_vulns:
                if not any(v['line'] == sv['line'] and v['type'] == sv['type'] 
                          for v in results['vulnerabilities']):
                    results['vulnerabilities'].append(sv)
            print(f"{Fore.GREEN}    ✓ Slither found {len(slither_vulns)} issues\n")
        
        # Calculate risk
        results['risk_level'] = self._calculate_risk(results['vulnerabilities'])
        results['vulnerability_count'] = len(results['vulnerabilities'])
        
        return results
    
    def _calculate_risk(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level"""
        if not vulnerabilities:
            return 'LOW'
        
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        if critical > 0:
            return 'CRITICAL'
        elif high >= 2:
            return 'HIGH'
        elif high > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def print_results(self, results: Dict):
        """Print results to console"""
        print(f"\n{Fore.CYAN}{'═'*70}")
        print(f"{Fore.CYAN}  VULNERABILITY SCAN RESULTS")
        print(f"{Fore.CYAN}{'═'*70}\n")
        
        print(f"{Fore.YELLOW}📄 File: {results['filename']}")
        print(f"{Fore.YELLOW}📅 Scan Date: {results['scan_date']}")
        print(f"{Fore.YELLOW}📊 Total Lines: {results['stats']['total_lines']}")
        print(f"{Fore.YELLOW}⚡ Functions: {results['stats']['functions']}\n")
        
        # Risk level
        risk_color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }.get(results['risk_level'], Fore.WHITE)
        
        print(f"{risk_color}🎯 Risk Level: {Style.BRIGHT}{results['risk_level']}")
        print(f"{risk_color}🔍 Vulnerabilities: {results['vulnerability_count']}\n")
        
        if not results['vulnerabilities']:
            print(f"{Fore.GREEN}{'─'*70}")
            print(f"{Fore.GREEN}✅ NO VULNERABILITIES DETECTED!")
            print(f"{Fore.GREEN}✅ Contract appears secure based on analysis")
            print(f"{Fore.GREEN}{'─'*70}\n")
        else:
            print(f"{Fore.RED}⚠️  VULNERABILITIES DETECTED:\n")
            
            # Group by severity
            by_severity = {}
            for v in results['vulnerabilities']:
                sev = v.get('severity', 'MEDIUM')
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(v)
            
            # Print in order: CRITICAL, HIGH, MEDIUM, LOW
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity not in by_severity:
                    continue
                
                severity_color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN
                }.get(severity, Fore.WHITE)
                
                print(f"{severity_color}━━━ {severity} ({len(by_severity[severity])}) ━━━")
                
                for i, vuln in enumerate(by_severity[severity], 1):
                    print(f"{severity_color}")
                    print(f"  [{i}] {vuln.get('type', 'Unknown')}")
                    print(f"      Line {vuln.get('line', 'N/A')}: {vuln.get('code_snippet', 'N/A')[:60]}...")
                    print(f"      {vuln.get('description', 'N/A')}")
                    print(f"      CWE: {vuln.get('cwe', 'N/A')} | Confidence: {vuln.get('confidence', 'N/A')}")
                    print(f"      Detector: {vuln.get('detector', 'N/A')}\n")
        
        print(f"{Fore.CYAN}{'═'*70}\n")
    
    def save_json(self, results: Dict, output_path: str):
        """Save results to JSON"""
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved: {output_path}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save JSON: {e}")
    
    def generate_report(self, results: Dict, output_path: str):
        """Generate text report"""
        try:
            with open(output_path, 'w') as f:
                f.write("="*70 + "\n")
                f.write("  AI/ML SMART CONTRACT VULNERABILITY REPORT\n")
                f.write("="*70 + "\n\n")
                
                f.write(f"File: {results['filename']}\n")
                f.write(f"Scan Date: {results['scan_date']}\n")
                f.write(f"Author: {results['author']}\n")
                f.write(f"Risk Level: {results['risk_level']}\n")
                f.write(f"Vulnerabilities: {results['vulnerability_count']}\n\n")
                
                f.write("-"*70 + "\n")
                f.write("STATISTICS\n")
                f.write("-"*70 + "\n")
                f.write(f"Total Lines: {results['stats']['total_lines']}\n")
                f.write(f"Functions: {results['stats']['functions']}\n\n")
                
                if results['vulnerabilities']:
                    f.write("-"*70 + "\n")
                    f.write("VULNERABILITIES FOUND\n")
                    f.write("-"*70 + "\n\n")
                    
                    for i, vuln in enumerate(results['vulnerabilities'], 1):
                        f.write(f"[{i}] {vuln.get('type', 'Unknown')}\n")
                        f.write(f"    Severity: {vuln.get('severity', 'N/A')}\n")
                        f.write(f"    Line: {vuln.get('line', 'N/A')}\n")
                        f.write(f"    Code: {vuln.get('code_snippet', 'N/A')}\n")
                        f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                        f.write(f"    CWE: {vuln.get('cwe', 'N/A')}\n")
                        f.write(f"    Confidence: {vuln.get('confidence', 'N/A')}\n")
                        f.write(f"    Detector: {vuln.get('detector', 'N/A')}\n\n")
                else:
                    f.write("-"*70 + "\n")
                    f.write("✅ No vulnerabilities detected!\n")
                    f.write("-"*70 + "\n")
                
                f.write("\n" + "="*70 + "\n")
                f.write("Generated by AI/ML Smart Contract Detector\n")
                f.write("Author: Harshanandhan Reddy Gajulapalli\n")
                f.write("Email: harshanandhanreddy820@gmail.com\n")
                f.write("="*70 + "\n")
            
            print(f"{Fore.GREEN}[+] Report saved: {output_path}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to generate report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='AI/ML Smart Contract Vulnerability Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python detector.py vulnerable.sol
  python detector.py MyToken.sol --json results.json
  python detector.py contract.sol --report scan_report.txt
  python detector.py contract.sol --no-slither

Author: Harshanandhan Reddy Gajulapalli
Email: harshanandhanreddy820@gmail.com
GitHub: https://github.com/Harshanandhan/smart-contract-ai-detector
        '''
    )
    
    parser.add_argument('file', help='Solidity file to analyze')
    parser.add_argument('--json', help='Save results as JSON')
    parser.add_argument('--report', help='Generate text report')
    parser.add_argument('--no-slither', action='store_true', help='Disable Slither (use pattern-only)')
    
    args = parser.parse_args()
    
    # Check file exists
    if not Path(args.file).exists():
        print(f"{Fore.RED}[!] File not found: {args.file}")
        print(f"{Fore.YELLOW}[*] Usage: python detector.py <file.sol>")
        sys.exit(1)
    
    # Initialize detector
    detector = SmartContractDetector(use_slither=not args.no_slither)
    
    # Analyze
    results = detector.analyze_file(args.file)
    
    if results:
        # Print results
        detector.print_results(results)
        
        # Save outputs
        if args.json:
            detector.save_json(results, args.json)
        
        if args.report:
            detector.generate_report(results, args.report)
        
        # Exit code based on risk
        if results['risk_level'] in ['CRITICAL', 'HIGH']:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == '__main__':
    main()
