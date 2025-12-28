#!/bin/bash
# Quick test script

echo "Testing Vulnerable Contract..."
python detector.py --file sample_contracts/vulnerable.sol

echo ""
echo "Testing Secure Contract..."
python detector.py --file sample_contracts/secure.sol
