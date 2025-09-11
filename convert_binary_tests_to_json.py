#!/usr/bin/env python3
"""
Convert RIPE Atlas binary test files to JSON format for cross-platform compatibility.
"""

import os
import sys
import struct
import json
import socket
import base64
from pathlib import Path

# Response type constants
RESP_PACKET = 1
RESP_SOCKNAME = 2
RESP_DSTADDR = 3
RESP_PEERNAME = 4
RESP_READ_ERROR = 4
RESP_N_RESOLV = 4
RESP_RESOLVER = 5
RESP_LENGTH = 6
RESP_DATA = 7
RESP_CMSG = 8
RESP_TIMEOUT = 9
RESP_ADDRINFO = 10
RESP_ADDRINFO_SA = 11
RESP_TTL = 4
RESP_RCVDTTL = 5
RESP_RCVDTCLASS = 6
RESP_SENDTO = 7
RESP_PROTO = 4
RESP_TIMEOFDAY = 4

# Address family constants
AF_INET = 2
AF_INET6 = 10  # Linux value
AF_INET6_LOCAL = 28  # FreeBSD value

def parse_sockaddr(data, family):
    """Parse sockaddr structure from binary data."""
    # Handle case where family is 0 but we can infer from data length
    if family == 0 and len(data) >= 8:
        # Try to parse as IPv4 if data length suggests it
        # Check if port is in big-endian format (00 50 = 80)
        port_be = struct.unpack('>H', data[6:8])[0]
        port_le = struct.unpack('<H', data[6:8])[0]
        
        # Use the port that makes sense (80 for HTTP)
        if port_be == 80:
            port = port_be
        elif port_le == 80:
            port = port_le
        else:
            port = port_le  # Default to little-endian
            
        addr_bytes = data[8:12]  # Address starts after port
        try:
            addr_str = socket.inet_ntoa(addr_bytes)
            # Check if address is all zeros (blank/undefined)
            if addr_str == "0.0.0.0":
                return {
                    "family": "AF_INET",
                    "address": None,  # Blank/undefined address
                    "port": port
                }
            else:
                return {
                    "family": "AF_INET",
                    "address": addr_str,
                    "port": port
                }
        except:
            pass
    
    if family == AF_INET:
        # IPv4 sockaddr_in
        if len(data) < 8:
            return None
        # Skip family (2 bytes), get port (2 bytes), then address (4 bytes)
        port = struct.unpack('<H', data[2:4])[0]  # Little-endian port
        addr_bytes = data[4:8]
        addr_str = socket.inet_ntoa(addr_bytes)
        return {
            "family": "AF_INET",
            "address": addr_str,
            "port": port
        }
    elif family == AF_INET6 or family == AF_INET6_LOCAL:
        # IPv6 sockaddr_in6
        if len(data) < 24:
            return None
        # Skip family (2 bytes), get port (2 bytes), flowinfo (4 bytes), then address (16 bytes)
        port = struct.unpack('<H', data[2:4])[0]  # Little-endian port
        flowinfo = struct.unpack('<I', data[4:8])[0]  # Little-endian flowinfo
        addr_bytes = data[8:24]
        addr_str = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        
        result = {
            "family": "AF_INET6",
            "address": addr_str,
            "port": port,
            "flowinfo": flowinfo
        }
        
        # Add scope_id if available
        if len(data) >= 28:
            scope_id = struct.unpack('<I', data[24:28])[0]  # Little-endian scope_id
            result["scope_id"] = scope_id
        
        return result
    return None

def convert_binary_file(input_path, output_path):
    """Convert a binary test file to JSON format."""
    responses = []
    
    with open(input_path, 'rb') as f:
        while True:
            # Read response type
            type_data = f.read(4)
            if len(type_data) < 4:
                break
            resp_type = struct.unpack('<I', type_data)[0]
            
            # Read response size
            size_data = f.read(4)
            if len(size_data) < 4:
                break
            resp_size = struct.unpack('<I', size_data)[0]
            
            # Read response data
            if resp_size > 0:
                resp_data = f.read(resp_size)
                if len(resp_data) < resp_size:
                    break
            else:
                resp_data = b''
            
            # Convert based on response type
            response = {"type": resp_type, "size": resp_size}
            
            if resp_type in [RESP_DSTADDR, RESP_SOCKNAME, RESP_PEERNAME] and resp_size >= 6:
                # Parse sockaddr structure - family is at offset 4
                family = struct.unpack('<H', resp_data[4:6])[0]
                sockaddr_data = parse_sockaddr(resp_data[4:], family)
                if sockaddr_data:
                    response["data"] = sockaddr_data
                else:
                    response["data"] = {
                        "raw_base64": base64.b64encode(resp_data).decode('ascii'),
                        "raw_hex": resp_data.hex()
                    }
            elif resp_type == RESP_PACKET:
                # Packet data
                response["data"] = {
                    "size": resp_size,
                    "base64": base64.b64encode(resp_data).decode('ascii'),
                    "hex": resp_data.hex() if resp_size <= 100 else resp_data[:100].hex() + "..."
                }
            elif resp_type == RESP_DATA:
                # Generic data
                try:
                    text_data = resp_data.decode('utf-8', errors='ignore')
                    response["data"] = {
                        "text": text_data,
                        "size": resp_size,
                        "base64": base64.b64encode(resp_data).decode('ascii')
                    }
                except:
                    response["data"] = {
                        "base64": base64.b64encode(resp_data).decode('ascii'),
                        "hex": resp_data.hex() if resp_size <= 100 else resp_data[:100].hex() + "...",
                        "size": resp_size
                    }
            elif resp_type == RESP_TIMEOUT:
                # Timeout data
                response["data"] = {"timeout": True}
            elif resp_type == RESP_READ_ERROR:
                # Read error
                response["data"] = {"error": True}
            else:
                # Generic binary data
                response["data"] = {
                    "base64": base64.b64encode(resp_data).decode('ascii'),
                    "hex": resp_data.hex() if resp_size <= 100 else resp_data[:100].hex() + "...",
                    "size": resp_size
                }
            
            responses.append(response)
    
    # Create JSON structure
    json_data = {
        "version": "1.0",
        "source": "converted from binary",
        "original_file": os.path.basename(input_path),
        "responses": responses
    }
    
    # Write JSON file
    with open(output_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"Converted {input_path} -> {output_path} ({len(responses)} responses)")

def main():
    if len(sys.argv) != 3:
        print("Usage: convert_binary_tests_to_json.py <input_dir> <output_dir>")
        sys.exit(1)
    
    input_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not input_dir.exists():
        print(f"Input directory {input_dir} does not exist")
        sys.exit(1)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all .net files
    net_files = list(input_dir.rglob("*.net"))
    
    if not net_files:
        print(f"No .net files found in {input_dir}")
        sys.exit(1)
    
    print(f"Found {len(net_files)} .net files to convert")
    
    for net_file in net_files:
        # Create corresponding JSON file path
        rel_path = net_file.relative_to(input_dir)
        json_file = output_dir / rel_path.with_suffix('.json')
        
        # Create output directory if needed
        json_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            convert_binary_file(net_file, json_file)
        except Exception as e:
            print(f"Error converting {net_file}: {e}")

if __name__ == "__main__":
    main()
