#!/bin/bash
# Integration Script for OTA Add-on Tests
# This script shows how to integrate the tests into the OTA add-on

set -e

echo "========================================================================"
echo "OTA Add-on Test Integration"
echo "========================================================================"

# Verify we're in the right directory
if [ ! -f "server.py" ]; then
    echo "ERROR: server.py not found. Run from OTA add-on directory."
    exit 1
fi

echo ""
echo "1. Checking test files..."

if [ ! -f "ota_helper.py" ]; then
    echo "   ✗ ota_helper.py not found"
    echo "   ACTION: Copy ota_helper.py from source"
    exit 1
fi
echo "   ✓ ota_helper.py found"

if [ ! -d "tests" ]; then
    echo "   ✗ tests/ directory not found"
    echo "   ACTION: Copy tests/ folder from source"
    exit 1
fi
echo "   ✓ tests/ directory found"

if [ ! -f "tests/run_all.py" ]; then
    echo "   ✗ tests/run_all.py not found"
    exit 1
fi
echo "   ✓ tests/run_all.py found"

echo ""
echo "2. Validating Python syntax..."
python3 -m py_compile server.py && echo "   ✓ server.py OK"
python3 -m py_compile ota_helper.py && echo "   ✓ ota_helper.py OK"
python3 -m py_compile tests/run_all.py && echo "   ✓ tests/run_all.py OK"

echo ""
echo "3. Checking server imports..."
python3 -c "
import ota_helper
print('   ✓ ota_helper imports successfully')
print('   ✓ create_token available:', hasattr(ota_helper, 'create_token'))
print('   ✓ validate_token available:', hasattr(ota_helper, 'validate_token'))
" || exit 1

echo ""
echo "4. Setup summary:"
echo "   - OTA Server: server.py (refactored to use ota_helper)"
echo "   - Shared Module: ota_helper.py"
echo "   - Tests: tests/run_all.py"
echo ""

echo "5. Next steps to enable tests:"
echo ""
echo "   a) Update Dockerfile:"
echo "      COPY tests /app/tests"
echo "      COPY ota_helper.py /app/"
echo ""
echo "   b) Update run.sh to execute tests:"
echo "      python3 /app/server.py &"
echo "      sleep 2"
echo "      python3 /app/tests/run_all.py"
echo ""
echo "   c) Run in container:"
echo "      docker exec <container-id> python3 /app/tests/run_all.py"
echo ""
echo "========================================================================"
echo "✓ Integration check complete!"
echo "========================================================================"
