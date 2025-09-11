#!/usr/bin/env python3
"""
Update test files to use string-based address families instead of numeric ones.
Changes:
- "af":4 -> "af":"AF_INET"
- "af":6 -> "af":"AF_INET6"
"""

import os
import re
import glob

def update_file(filepath):
    """Update a single file to use string-based address families."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Replace numeric address families with string-based ones
        original_content = content
        content = re.sub(r'"af":\s*4\b', '"af":"AF_INET"', content)
        content = re.sub(r'"af":\s*6\b', '"af":"AF_INET6"', content)
        
        # Only write if changes were made
        if content != original_content:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Updated: {filepath}")
            return True
        else:
            print(f"No changes needed: {filepath}")
            return False
            
    except Exception as e:
        print(f"Error updating {filepath}: {e}")
        return False

def main():
    """Update all test files in the testsuite directory."""
    testsuite_dir = "probe-busybox/testsuite"
    
    # Find all .out files (expected output files)
    pattern = os.path.join(testsuite_dir, "**", "*.out")
    out_files = glob.glob(pattern, recursive=True)
    
    print(f"Found {len(out_files)} .out files to process")
    
    updated_count = 0
    for filepath in out_files:
        if update_file(filepath):
            updated_count += 1
    
    print(f"\nUpdated {updated_count} files out of {len(out_files)} total files")
    
    # Also update .json files if they exist
    json_pattern = os.path.join(testsuite_dir, "**", "*.json")
    json_files = glob.glob(json_pattern, recursive=True)
    
    print(f"\nFound {len(json_files)} .json files to process")
    
    json_updated_count = 0
    for filepath in json_files:
        if update_file(filepath):
            json_updated_count += 1
    
    print(f"Updated {json_updated_count} .json files out of {len(json_files)} total files")
    print(f"\nTotal files updated: {updated_count + json_updated_count}")

if __name__ == "__main__":
    main()
