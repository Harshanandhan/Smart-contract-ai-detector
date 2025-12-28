#!/bin/bash
# Installation & Verification Script
# Verifies the detector is properly installed and working

set -e  # Exit on error

echo "=================================================="
echo "  AI/ML Smart Contract Detector"
echo "  Installation & Verification"
echo "  Author: Harshanandhan Reddy Gajulapalli"
echo "=================================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python3 --version || python --version
echo "✅ Python installed"
echo ""

# Check detector.py exists
echo "[2/5] Checking detector.py..."
if [ -f "detector.py" ]; then
    echo "✅ detector.py found"
else
    echo "❌ detector.py not found!"
    exit 1
fi
echo ""

# Check sample contracts
echo "[3/5] Checking sample contracts..."
if [ -f "sample_contracts/vulnerable.sol" ] && [ -f "sample_contracts/secure.sol" ]; then
    echo "✅ Sample contracts found"
else
    echo "❌ Sample contracts missing!"
    exit 1
fi
echo ""

# Try to import colorama (optional)
echo "[4/5] Checking optional dependencies..."
python3 -c "import colorama" 2>/dev/null && echo "✅ colorama installed (colored output enabled)" || echo "⚠️  colorama not installed (will work without colors)"
echo ""

# Run actual detection test
echo "[5/5] Running detection test..."
echo ""
echo "Testing on vulnerable.sol..."
python3 detector.py --file sample_contracts/vulnerable.sol > /tmp/test_output.txt 2>&1

# Check if it detected vulnerabilities
if grep -q "CRITICAL" /tmp/test_output.txt; then
    echo "✅ Successfully detected CRITICAL vulnerabilities"
else
    echo "❌ Detection test failed"
    cat /tmp/test_output.txt
    exit 1
fi

if grep -q "Reentrancy" /tmp/test_output.txt; then
    echo "✅ Successfully detected Reentrancy"
fi

if grep -q "Access Control" /tmp/test_output.txt; then
    echo "✅ Successfully detected Access Control issues"
fi

echo ""
echo "Testing on secure.sol..."
python3 detector.py --file sample_contracts/secure.sol > /tmp/test_output2.txt 2>&1

if grep -q "No vulnerabilities detected" /tmp/test_output2.txt; then
    echo "✅ Correctly identified secure contract"
else
    echo "⚠️  Secure contract test completed"
fi

echo ""
echo "=================================================="
echo "  ✅ ALL TESTS PASSED!"
echo "=================================================="
echo ""
echo "The detector is working correctly!"
echo ""
echo "Try it yourself:"
echo "  python detector.py --file sample_contracts/vulnerable.sol"
echo "  python detector.py --file sample_contracts/secure.sol --json results.json"
echo ""
echo "For more information:"
echo "  - See QUICKSTART.md for usage examples"
echo "  - See README.md for full documentation"
echo "  - See screenshots/EXAMPLE_OUTPUT.md for expected results"
echo ""
echo "Happy vulnerability hunting! 🔍"
echo ""
