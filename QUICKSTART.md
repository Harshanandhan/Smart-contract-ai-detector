# Quick Start Guide - 2 Minutes to First Scan!

Get the AI/ML Smart Contract Vulnerability Detector running in 2 minutes.

## ⚡ Ultra Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Harshanandhan/smart-contract-ai-detector.git
cd smart-contract-ai-detector

# 2. Install minimal dependencies (optional - works without!)
pip install colorama

# 3. Run your first scan!
python detector.py --file sample_contracts/vulnerable.sol
```

**That's it!** The detector works immediately with pattern-based detection.

---

## 📋 Installation Options

### Option 1: Minimal (No Dependencies)
```bash
# Just Python 3.8+ needed
python detector.py --file your_contract.sol
```

### Option 2: With Colorful Output
```bash
pip install colorama
python detector.py --file your_contract.sol
```

### Option 3: Full Installation (For Advanced Features)
```bash
pip install -r requirements.txt
python detector.py --file your_contract.sol --slither
```

---

## 🎯 Basic Usage

### Scan a Contract
```bash
python detector.py --file MyToken.sol
```

### Save Results as JSON
```bash
python detector.py --file MyToken.sol --json results.json
```

### Generate Text Report
```bash
python detector.py --file MyToken.sol --report scan_report.txt
```

### Use All Features
```bash
python detector.py --file MyToken.sol --json results.json --report report.txt
```

---

## 📊 Example Output

```
[*] AI/ML Smart Contract Vulnerability Detector
[*] Author: Harshanandhan Reddy Gajulapalli

[*] Analyzing vulnerable.sol...
[*] Running pattern-based detection...

======================================================================
  VULNERABILITY SCAN RESULTS
======================================================================

File: vulnerable.sol
Scan Date: 2024-12-28 10:30:00
Total Lines: 75
Functions: 7

Risk Level: CRITICAL
Vulnerabilities Found: 5

[!] Vulnerabilities Detected:

[1] Reentrancy
    Severity: CRITICAL
    Line: 25
    Code: (bool success, ) = msg.sender.call{value: amount}("");...
    Description: Potential reentrancy vulnerability - external call before state update
    Confidence: 85%
    Model: Pattern-Based Detection

[2] Access Control
    Severity: HIGH
    Line: 33
    Code: owner = newOwner;...
    Description: Missing access control - privileged function without protection
    Confidence: 85%
    Model: Pattern-Based Detection

[3] Unchecked Call
    Severity: MEDIUM
    Line: 42
    Code: recipient.call{value: amount}("");...
    Description: Unchecked external call - return value not validated
    Confidence: 85%
    Model: Pattern-Based Detection

[4] Timestamp Dependence
    Severity: LOW
    Line: 50
    Code: require(block.timestamp % 2 == 0, "Can only claim on...
    Description: Timestamp dependence - can be manipulated by miners
    Confidence: 85%
    Model: Pattern-Based Detection

[5] Tx Origin
    Severity: MEDIUM
    Line: 57
    Code: require(tx.origin == owner, "Not owner");...
    Description: Use of tx.origin - phishing vulnerability
    Confidence: 85%
    Model: Pattern-Based Detection

======================================================================
```

---

## 🧪 Test with Sample Contracts

### Test Vulnerable Contract
```bash
python detector.py --file sample_contracts/vulnerable.sol
```

**Expected:** 5 vulnerabilities detected (CRITICAL risk)

### Test Secure Contract
```bash
python detector.py --file sample_contracts/secure.sol
```

**Expected:** 0 vulnerabilities detected (LOW risk)

---

## 🚀 Next Steps

### 1. Scan Your Own Contracts
```bash
python detector.py --file /path/to/your/contract.sol
```

### 2. Batch Scan Multiple Files
```bash
for file in contracts/*.sol; do
    python detector.py --file "$file" --json "results_$(basename $file).json"
done
```

### 3. Integrate with CI/CD
```bash
# In your GitHub Actions or GitLab CI
python detector.py --file contract.sol
if [ $? -eq 1 ]; then
    echo "Critical vulnerabilities found!"
    exit 1
fi
```

---

## ❓ Troubleshooting

### "No module named 'colorama'"
**Solution:** Install it or run without colors:
```bash
pip install colorama
# OR just ignore - it works fine without colors!
```

### "File not found"
**Solution:** Check the file path:
```bash
# Use absolute path
python detector.py --file /full/path/to/contract.sol

# Or relative path from project directory
python detector.py --file ./contracts/MyToken.sol
```

### Want AI/ML Models?
**Solution:** Full ML requires training (see TRAINING.md)
```bash
# For now, pattern-based detection works great!
# AI/ML models coming in v2.0
```

---

## 📚 More Information

- **Full Documentation:** See [README.md](README.md)
- **Architecture:** See [screenshots/README.md](screenshots/README.md)
- **Training Guide:** Coming in v2.0
- **API Usage:** Coming in v2.0

---

## 🤝 Need Help?

**Harshanandhan Reddy Gajulapalli**
- Email: harshanandhanreddy820@gmail.com
- GitHub Issues: [Report a bug](https://github.com/Harshanandhan/smart-contract-ai-detector/issues)
- Twitter: [@Nandhanreddyy](https://twitter.com/Nandhanreddyy)

---

**⚡ You're ready to detect vulnerabilities!**

Now go scan some contracts! 🚀
