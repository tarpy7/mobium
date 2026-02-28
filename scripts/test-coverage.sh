#!/bin/bash
# Run all tests with coverage report

echo "====================================="
echo "SecureComm Test Suite"
echo "====================================="

# Check for cargo-tarpaulin
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
fi

echo ""
echo "Running tests with coverage..."
cargo tarpaulin --workspace \
    --out Html \
    --out Stdout \
    --timeout 120 \
    --target-dir target/coverage \
    --exclude-files "*/tests/*" \
    --exclude-files "*/test_*" \
    --exclude-files "target/*" \
    2>&1 | tee test_output.log

# Extract coverage percentage
COVERAGE=$(grep -oP '\d+\.?\d*%' test_output.log | tail -1)
echo ""
echo "====================================="
echo "Coverage Report: $COVERAGE"
echo "====================================="

# Check if coverage meets threshold
if [ -n "$COVERAGE" ]; then
    COVERAGE_NUM=$(echo $COVERAGE | sed 's/%//')
    if (( $(echo "$COVERAGE_NUM >= 50" | bc -l) )); then
        echo "✅ Coverage target met (50%)"
        exit 0
    else
        echo "❌ Coverage below target (50%)"
        exit 1
    fi
fi

rm -f test_output.log