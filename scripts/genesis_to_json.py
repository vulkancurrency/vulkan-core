#!/usr/bin/env python3
"""
Genesis Block JSON Generator

This script converts the text output from the 'create-genesis-block' command
into a properly formatted JSON structure that can be pasted into genesis_block.json.

Usage:
    1. Run: ./build/vulkan create-genesis-block > genesis_output.txt
    2. Edit genesis_output.txt and extract the block data
    3. Run: python3 scripts/genesis_to_json.py genesis_output.txt [network_name]
    4. Paste the output into genesis_block.json

Example output format to parse:
    Block Hash: abc123...
    Previous Hash: def456...
    Merkle Root: ghi789...
    Timestamp: 1234567890
    Nonce: 1000
    Bits: 545259519
    Cumulative Emission: 6103515625
    Transaction ID: xyz000...
    Output Amount: 6103515625
    Output Address: addr123...
"""

import json
import sys
import re
from typing import Dict, Any


def parse_genesis_output(text: str) -> Dict[str, Any]:
    """Parse the create-genesis-block command output"""
    
    data = {
        "version": 1,
        "previous_hash": "",
        "hash": "",
        "timestamp": 0,
        "nonce": 0,
        "bits": 0,
        "cumulative_emission": 0,
        "merkle_root": "",
        "transactions": []
    }
    
    lines = text.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        
        if not line:
            continue
            
        # Parse various field formats
        if 'Block Hash' in line or 'hash' in line.lower() and 'previous' not in line.lower():
            match = re.search(r':\s*([a-f0-9]+)', line, re.IGNORECASE)
            if match:
                data["hash"] = match.group(1)
                
        elif 'Previous Hash' in line or 'previous_hash' in line.lower():
            match = re.search(r':\s*([a-f0-9]+)', line, re.IGNORECASE)
            if match:
                data["previous_hash"] = match.group(1)
                
        elif 'Merkle Root' in line or 'merkle_root' in line.lower():
            match = re.search(r':\s*([a-f0-9]+)', line, re.IGNORECASE)
            if match:
                data["merkle_root"] = match.group(1)
                
        elif 'Timestamp' in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                data["timestamp"] = int(match.group(1))
                
        elif 'Nonce' in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                data["nonce"] = int(match.group(1))
                
        elif 'Bits' in line:
            match = re.search(r':\s*(\d+)', line)
            if match:
                data["bits"] = int(match.group(1))
                
        elif 'Cumulative' in line or 'cumulative_emission' in line.lower():
            match = re.search(r':\s*(\d+)', line)
            if match:
                data["cumulative_emission"] = int(match.group(1))
                
        elif 'Transaction' in line and 'ID' in line:
            match = re.search(r':\s*([a-f0-9]+)', line, re.IGNORECASE)
            if match:
                tx_id = match.group(1)
                if not any(t["id"] == tx_id for t in data["transactions"]):
                    data["transactions"].append({
                        "id": tx_id,
                        "outputs": []
                    })
                    
        elif 'Output' in line and 'Amount' in line:
            match = re.search(r':\s*(\d+)', line)
            if match and data["transactions"]:
                amount = int(match.group(1))
                if not any(o["amount"] == amount for o in data["transactions"][-1]["outputs"]):
                    data["transactions"][-1]["outputs"].append({
                        "amount": amount,
                        "address": ""
                    })
                    
        elif 'Output' in line and 'Address' in line:
            match = re.search(r':\s*([a-f0-9]+)', line, re.IGNORECASE)
            if match and data["transactions"] and data["transactions"][-1]["outputs"]:
                data["transactions"][-1]["outputs"][-1]["address"] = match.group(1)
    
    return data


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 genesis_to_json.py <output_file> [network_name]")
        print("\nExample:")
        print("  python3 genesis_to_json.py genesis_output.txt mainnet")
        sys.exit(1)
    
    input_file = sys.argv[1]
    network_name = sys.argv[2] if len(sys.argv) > 2 else "custom"
    
    try:
        with open(input_file, 'r') as f:
            text = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found")
        sys.exit(1)
    
    parsed_data = parse_genesis_output(text)
    
    # Create output structure
    output = {
        "comment": "Auto-generated genesis block configuration",
        network_name: parsed_data
    }
    
    # Pretty print JSON
    json_str = json.dumps(output, indent=2)
    print(json_str)
    print("\n# Copy the above JSON and paste into the appropriate network section in genesis_block.json")


if __name__ == "__main__":
    main()
