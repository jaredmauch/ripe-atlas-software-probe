#!/usr/bin/env python3
"""
JSON Result Validation Script for RIPE Atlas Software Probe Tests

This script validates JSON test results to ensure:
1. Correct address family (af: 4 for IPv4, af: 6 for IPv6)
2. Valid IP addresses in dst_addr and src_addr fields
3. Proper JSON structure
4. Required fields are present
"""

import json
import re
import sys
import ipaddress
from typing import Dict, Any, List, Optional

def is_valid_ipv4(addr: str) -> bool:
    """Check if string is a valid IPv4 address"""
    try:
        ipaddress.IPv4Address(addr)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv6(addr: str) -> bool:
    """Check if string is a valid IPv6 address"""
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_address_family(af: int, dst_addr: str, src_addr: str) -> List[str]:
    """Validate that address family matches the actual addresses"""
    errors = []
    
    if af == 4:
        if dst_addr and not is_valid_ipv4(dst_addr):
            errors.append(f"af=4 but dst_addr='{dst_addr}' is not a valid IPv4 address")
        if src_addr and not is_valid_ipv4(src_addr):
            errors.append(f"af=4 but src_addr='{src_addr}' is not a valid IPv4 address")
    elif af == 6:
        if dst_addr and not is_valid_ipv6(dst_addr):
            errors.append(f"af=6 but dst_addr='{dst_addr}' is not a valid IPv6 address")
        if src_addr and not is_valid_ipv6(src_addr):
            errors.append(f"af=6 but src_addr='{src_addr}' is not a valid IPv6 address")
    else:
        errors.append(f"Invalid address family: af={af} (must be 4 or 6)")
    
    return errors

def validate_json_result(line: str) -> Dict[str, Any]:
    """Validate a single JSON result line"""
    errors = []
    warnings = []
    
    # Extract JSON from RESULT line
    if line.startswith("RESULT "):
        json_str = line[7:]  # Remove "RESULT " prefix
    else:
        json_str = line
    
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        return {"valid": False, "errors": [f"Invalid JSON: {e}"], "warnings": []}
    
    # Check if result field exists
    if "result" not in data:
        errors.append("Missing 'result' field")
        return {"valid": False, "errors": errors, "warnings": warnings}
    
    results = data["result"]
    
    # Handle both array and object formats
    if isinstance(results, list):
        # Array format (used by evping, evhttpget, etc.)
        result_list = results
    elif isinstance(results, dict):
        # Object format (used by evtdig, etc.)
        result_list = [results]
    else:
        errors.append("'result' field must be an array or object")
        return {"valid": False, "errors": errors, "warnings": warnings}
    
    # Validate each result in the list
    for i, result in enumerate(result_list):
        if not isinstance(result, dict):
            errors.append(f"result[{i}] must be an object")
            continue
        
        # Check required fields based on tool type
        # For evtdig: af, dst_addr, src_addr are in the main object
        # For other tools: af, dst_addr, src_addr are in the main object
        af = data.get("af")
        dst_addr = data.get("dst_addr")
        src_addr = data.get("src_addr")
        
        # Validate address family and addresses
        if af is not None and dst_addr is not None and src_addr is not None:
            af_errors = validate_address_family(af, dst_addr, src_addr)
            errors.extend([f"result[{i}]: {err}" for err in af_errors])
        else:
            # Check if fields are missing
            if af is None:
                errors.append(f"result[{i}]: missing 'af' field")
            if dst_addr is None:
                errors.append(f"result[{i}]: missing 'dst_addr' field")
            if src_addr is None:
                errors.append(f"result[{i}]: missing 'src_addr' field")
        
        # Check for empty addresses (warning, not error)
        if dst_addr == "":
            warnings.append(f"result[{i}]: dst_addr is empty")
        if src_addr == "":
            warnings.append(f"result[{i}]: src_addr is empty")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }

def main():
    """Main validation function"""
    if len(sys.argv) != 2:
        print("Usage: validate_json_results.py <test_output_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    
    total_lines = 0
    valid_lines = 0
    total_errors = 0
    total_warnings = 0
    
    print(f"Validating JSON results in {filename}...")
    print("=" * 60)
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        
        # Skip non-RESULT lines
        if not line.startswith("RESULT "):
            continue
        
        total_lines += 1
        result = validate_json_result(line)
        
        if result["valid"]:
            valid_lines += 1
            if result["warnings"]:
                print(f"Line {line_num}: VALID (with warnings)")
                for warning in result["warnings"]:
                    print(f"  WARNING: {warning}")
        else:
            print(f"Line {line_num}: INVALID")
            for error in result["errors"]:
                print(f"  ERROR: {error}")
                total_errors += 1
            for warning in result["warnings"]:
                print(f"  WARNING: {warning}")
                total_warnings += 1
    
    print("=" * 60)
    print(f"Summary:")
    print(f"  Total RESULT lines: {total_lines}")
    print(f"  Valid lines: {valid_lines}")
    print(f"  Invalid lines: {total_lines - valid_lines}")
    print(f"  Total errors: {total_errors}")
    print(f"  Total warnings: {total_warnings}")
    
    if total_errors > 0:
        print(f"\nValidation FAILED with {total_errors} errors")
        sys.exit(1)
    else:
        print(f"\nValidation PASSED")
        if total_warnings > 0:
            print(f"  (with {total_warnings} warnings)")
        sys.exit(0)

if __name__ == "__main__":
    main()
