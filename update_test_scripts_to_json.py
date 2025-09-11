#!/usr/bin/env python3
"""
Update test scripts to use JSON files instead of binary .net files.
"""

import os
import re
from pathlib import Path

def update_test_file(file_path):
    """Update a test file to use JSON instead of .net files."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace .net with .json in the file
    updated_content = content.replace('.net', '.json')
    
    # Write back the updated content
    with open(file_path, 'w') as f:
        f.write(updated_content)
    
    print(f"Updated {file_path}")

def main():
    testsuite_dir = Path("probe-busybox/testsuite")
    
    # Find all test files that reference .net files
    test_files = []
    for pattern in ["*.tests", "*.sh", "*.test"]:
        test_files.extend(testsuite_dir.glob(pattern))
    
    for test_file in test_files:
        if test_file.is_file():
            try:
                update_test_file(test_file)
            except Exception as e:
                print(f"Error updating {test_file}: {e}")

if __name__ == "__main__":
    main()
