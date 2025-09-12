#!/bin/bash

# Script to analyze test failures and report which test types failed
echo "=== Test Failure Analysis ==="
echo

# Run the test and capture output
echo "Running tests and analyzing failures..."
echo

# Run make test and capture both stdout and stderr
make test 2>&1 | tee test_output.log

echo
echo "=== Failure Summary ==="
echo

# Extract and count different types of failures
echo "Response Type Mismatches:"
grep "wrong type, expected" test_output.log | sort | uniq -c | sort -nr

echo
echo "Tool-specific Failures:"
grep "wrong type, expected" test_output.log | sed 's/.*tool: \([^ ]*\)/\1/' | sort | uniq -c | sort -nr

echo
echo "Test Failures by Tool:"
grep "FAIL:" test_output.log | sed 's/.*FAIL: \([^ ]*\)/\1/' | sort | uniq -c | sort -nr

echo
echo "=== Detailed Error Analysis ==="
echo

# Show specific error patterns
echo "Expected vs Got Analysis:"
echo "Expected 1 (RESP_PACKET), Got 3 (RESP_DSTADDR):"
grep "expected 1, got 3" test_output.log | wc -l

echo "Expected 4 (RESP_PEERNAME), Got 5 (RESP_RESOLVER):"
grep "expected 4, got 5" test_output.log | wc -l

echo "Expected 3 (RESP_DSTADDR), Got 1 (RESP_PACKET):"
grep "expected 3, got 1" test_output.log | wc -l

echo
echo "=== Tools with Response Type Issues ==="
echo

# Show which tools are having response type issues
echo "Tools expecting RESP_PACKET (1) but getting RESP_DSTADDR (3):"
grep "expected 1, got 3" test_output.log | sed 's/.*tool: \([^ ]*\)/\1/' | sort | uniq -c

echo
echo "Tools expecting RESP_PEERNAME (4) but getting RESP_RESOLVER (5):"
grep "expected 4, got 5" test_output.log | sed 's/.*tool: \([^ ]*\)/\1/' | sort | uniq -c

echo
echo "=== Test Completion Status ==="
echo

# Count total tests and failures
total_tests=$(grep -c "FAIL:" test_output.log)
echo "Total test failures: $total_tests"

if [ $total_tests -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ $total_tests tests failed"
fi

echo
echo "Analysis complete. Check test_output.log for full details."
