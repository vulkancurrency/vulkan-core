# Genesis Block Configuration

This directory contains tools and configuration for dynamically loading genesis blocks without hardcoding them into the compiled executable.

## Files

- **`genesis_block.json`** - The main configuration file where you paste genesis block data
- **`src/core/genesis_block_loader.c`** - C implementation that loads genesis blocks from JSON
- **`src/core/genesis_block_loader.h`** - Header file with loader function declarations
- **`scripts/genesis_to_json.py`** - Python helper script to convert terminal output to JSON format

## Quick Start

### 1. Generate a Genesis Block

```bash
./build/vulkan create-genesis-block > /tmp/genesis_output.txt
```

This outputs something like:
```
Block Hash: abc123def456...
Previous Hash: 0000000000...
Merkle Root: xyz789...
Timestamp: 1625097600
Nonce: 12345
Bits: 545259519
Cumulative Emission: 6103515625
Transaction ID: txabc123...
Output Amount: 6103515625
Output Address: address...
```

### 2. Convert to JSON Format

```bash
python3 scripts/genesis_to_json.py /tmp/genesis_output.txt mainnet
```

This outputs JSON like:
```json
{
  "comment": "Auto-generated genesis block configuration",
  "mainnet": {
    "version": 1,
    "hash": "abc123def456...",
    "previous_hash": "0000000000...",
    "merkle_root": "xyz789...",
    "timestamp": 1625097600,
    "nonce": 12345,
    "bits": 545259519,
    "cumulative_emission": 6103515625,
    "transactions": [...]
  }
}
```

### 3. Update genesis_block.json

Copy the output from step 2 and paste the network section into `genesis_block.json`:

```json
{
  "mainnet": {
    "version": 1,
    "hash": "your_hash_here",
    ...
  },
  "testnet": {
    ...
  }
}
```

### 4. Load in Your Code

Use the loader in your C code:

```c
#include "core/genesis_block_loader.h"

block_genesis_entry_t genesis_entry = {0};

if (load_genesis_block_from_file("genesis_block.json", "mainnet", &genesis_entry) == 0) {
    // Use genesis_entry
    // ...
    // Don't forget to free when done
    free_genesis_block_entry(&genesis_entry);
} else {
    // Handle error
}
```

## JSON Schema

### Structure

```json
{
  "comment": "Description",
  "mainnet": {
    "version": 1,
    "previous_hash": "hex_string_64_chars",
    "hash": "hex_string_64_chars",
    "timestamp": 1234567890,
    "nonce": 0,
    "bits": 545259519,
    "cumulative_emission": 6103515625,
    "merkle_root": "hex_string_64_chars",
    "transactions": [
      {
        "id": "hex_string_64_chars",
        "outputs": [
          {
            "amount": 6103515625,
            "address": "hex_string_or_base58"
          }
        ]
      }
    ]
  },
  "testnet": { ... }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `version` | uint32 | Block version number |
| `previous_hash` | string | Hex hash of previous block (64 hex chars for 32-byte hash) |
| `hash` | string | This block's hash (64 hex chars) |
| `timestamp` | uint32 | Unix timestamp when block was created |
| `nonce` | uint32 | Proof-of-work nonce value |
| `bits` | uint32 | Difficulty target bits |
| `cumulative_emission` | uint64 | Total coins emitted up to this block |
| `merkle_root` | string | Merkle root of transactions (64 hex chars) |
| `transactions` | array | Array of transaction entries |

## API Reference

### load_genesis_block_from_file()

Loads a genesis block configuration from JSON file.

```c
int load_genesis_block_from_file(const char *filepath, 
                                  const char *network, 
                                  block_genesis_entry_t *genesis_entry);
```

**Parameters:**
- `filepath` - Path to genesis_block.json
- `network` - Network identifier ("mainnet" or "testnet")
- `genesis_entry` - Pointer to structure to populate

**Returns:**
- `0` on success
- `-1` on failure (file not found, invalid JSON, etc.)

### free_genesis_block_entry()

Frees memory allocated by load_genesis_block_from_file().

```c
void free_genesis_block_entry(block_genesis_entry_t *genesis_entry);
```

## Integration Steps

1. **Add to CMakeLists.txt** - Include `genesis_block_loader.c` in your build
2. **Update genesis.c** - Modify to call loader instead of using hardcoded values
3. **Deploy genesis_block.json** - Include in your package/distribution
4. **Verify** - Test loading custom genesis blocks

## Example Integration

In `src/core/genesis.c`:

```c
#include "genesis_block_loader.h"

block_genesis_entry_t mainnet_genesis = {0};

// At initialization
if (load_genesis_block_from_file("genesis_block.json", "mainnet", &mainnet_genesis) != 0) {
    // Fall back to compiled defaults
    mainnet_genesis = mainnet_genesis_block_template;
}

// Later use mainnet_genesis instead of mainnet_genesis_block_template
```

## Troubleshooting

### File not found error
- Make sure `genesis_block.json` is in the correct path when running
- Use absolute paths if relative paths don't work

### Invalid JSON
- Validate JSON syntax: `jq . genesis_block.json`
- Check hex string lengths (should be 64 chars for 32-byte hashes)

### Hash mismatch
- Ensure the hash values are correctly copied from terminal output
- Verify no characters were truncated or corrupted during copy/paste

## Notes

- The Python script attempts to parse common output formats but may need adjustment based on your actual output format
- Always validate genesis block hashes and values before deploying
- Keep genesis_block.json with your other configuration files
- Multiple networks can be configured in a single JSON file
