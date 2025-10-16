# User Guide

This guide provides detailed instructions for using the JA3 Session Extractor.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Command Line Options](#command-line-options)
4. [Examples](#examples)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Installation

### Prerequisites

- Python 3.8 or higher
- Virtual environment (recommended)
- PCAP/PCAPng files to analyze

### Step-by-Step Installation

1. **Clone or download the project**
   ```bash
   git clone https://github.com/shashinma/rules.git
   cd rules
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Linux/macOS
   # or
   venv\Scripts\activate     # On Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation**
   ```bash
   python3 session_ja3_extractor.py --help
   ```

## Basic Usage

### Simple Analysis

```bash
# Basic session analysis
python3 session_ja3_extractor.py capture.pcap

# JSON output
python3 session_ja3_extractor.py capture.pcap -j
```

### Rule Generation

```bash
# Generate hash-based rules
python3 session_ja3_extractor.py capture.pcap -H

# Generate HEX-based rules
python3 session_ja3_extractor.py capture.pcap -X

# Generate both types
python3 session_ja3_extractor.py capture.pcap -H -X
```

### Session Management

```bash
# List all sessions
python3 session_ja3_extractor.py capture.pcap -l

# Filter specific session
python3 session_ja3_extractor.py capture.pcap -f 1

# Rules only (skip analysis)
python3 session_ja3_extractor.py capture.pcap -r -H
```

## Command Line Options

### Positional Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `pcap` | PCAP file to process | `capture.pcap` |

### Optional Arguments

| Short | Long | Description | Example |
|-------|------|-------------|---------|
| `-h` | `--help` | Show help message | `--help` |
| `-p` | `--ssl-port-only` | Search only port 443 | `-p` |
| `-j` | `--json` | JSON output format | `-j` |
| `-H` | `--hash-rules` | Generate hash-based rules | `-H` |
| `-X` | `--hex-rules` | Generate HEX-based rules | `-X` |
| `-r` | `--rules-only` | Show only rules | `-r` |
| `-e` | `--export-rules` | Export rules to file | `-e rules.rules` |
| `-f` | `--filter-session` | Filter by session number | `-f 1` |
| `-l` | `--list-sessions` | Show sessions list | `-l` |
| `-t` | `--tool-name` | Tool name for rules | `-t "MyTool"` |

## Examples

### Example 1: Basic Analysis

```bash
python3 session_ja3_extractor.py network_capture.pcap
```

### Example 2: Using API Examples

The project includes comprehensive examples in the `examples/` directory:

```bash
# Quick API test
python3 examples/quick_api_test.py

# Simple usage example
python3 examples/simple_api_example.py

# Working example with real PCAP files
python3 examples/working_api_example.py

# Comprehensive examples
python3 examples/api_examples.py
```

For detailed API usage examples, see [Examples Documentation](../examples/README.md).

### Example 3: Basic Analysis - Session List (Command Line)

```bash
python3 session_ja3_extractor.py network_capture.pcap -l
```

**Output:**
```
==========================================
                    Sessions List                    
==========================================
Total sessions: 3

#  1 192.168.1.100:45678 → 10.0.0.1:443
      Client: 192.168.1.100:45678
      Server: 10.0.0.1:443
      JA3: ✓ JA3S: ✓

#  2 192.168.1.101:45679 → 10.0.0.2:443
      Client: 192.168.1.101:45679
      Server: 10.0.0.2:443
      JA3: ✓ JA3S: ✓
```

### Example 2: Rule Generation

```bash
python3 session_ja3_extractor.py capture.pcap -H -e suricata_rules.rules
```

**Output:**
```
Generated 5 hash-based Suricata rules
Rules exported to: suricata_rules.rules
```

### Example 3: Session Filtering

```bash
python3 session_ja3_extractor.py capture.pcap -f 2 -H
```

**Output:**
```
Session 2: 192.168.1.101:45679 → 10.0.0.2:443
JA3: abc123def456...
JA3S: def456abc123...

Generated rules for session 2:
alert tls any any -> any any (msg:"JA3 Hash Detection"; content:"abc123def456..."; sid:2000001; rev:1;)
```

### Example 4: JSON Output

```bash
python3 session_ja3_extractor.py capture.pcap -j
```

**Output:**
```json
{
  "sessions": [
    {
      "key": "192.168.1.100:45678-10.0.0.1:443",
      "client_ip": "192.168.1.100",
      "client_port": 45678,
      "server_ip": "10.0.0.1",
      "server_port": 443,
      "has_ja3": true,
      "has_ja3s": true,
      "ja3": "abc123def456...",
      "ja3s": "def456abc123..."
    }
  ]
}
```

## Troubleshooting

### Common Issues

#### 1. Module Not Found Error

**Error:**
```
ModuleNotFoundError: No module named 'dpkt'
```

**Solution:**
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install dpkt packaging
```

#### 2. Permission Denied

**Error:**
```
PermissionError: No read permission for file: capture.pcap
```

**Solution:**
```bash
# Check file permissions
ls -la capture.pcap

# Fix permissions if needed
chmod 644 capture.pcap
```

#### 3. Invalid File Format

**Error:**
```
Exception: File is not PCAP or PCAPng
```

**Solution:**
- Ensure file is a valid PCAP or PCAPng file
- Check file extension (.pcap or .pcapng)
- Verify file is not corrupted

#### 4. Session Not Found

**Error:**
```
ValueError: Session number 5 not found
```

**Solution:**
```bash
# List available sessions first
python3 session_ja3_extractor.py capture.pcap -l

# Use correct session number
python3 session_ja3_extractor.py capture.pcap -f 1
```

### Performance Issues

#### Large PCAP Files

For large PCAP files (>1GB):

```bash
# Use rules-only mode to skip analysis
python3 session_ja3_extractor.py large_capture.pcap -r -H

# Filter specific sessions
python3 session_ja3_extractor.py large_capture.pcap -f 1 -H
```

#### Memory Usage

- Use virtual environment to isolate dependencies
- Close other applications when processing large files
- Consider splitting large PCAP files

## Best Practices

### 1. File Organization

```
project/
├── captures/           # PCAP files
├── rules/             # Generated rules
├── output/            # Analysis results
└── logs/              # Log files
```

### 2. Rule Management

```bash
# Generate rules with custom tool name
python3 session_ja3_extractor.py capture.pcap -H -t "SecurityTeam" -e rules.rules

# Generate both types for comprehensive coverage
python3 session_ja3_extractor.py capture.pcap -H -X -e all_rules.rules
```

### 3. Session Analysis

```bash
# Always list sessions first
python3 session_ja3_extractor.py capture.pcap -l

# Analyze specific interesting sessions
python3 session_ja3_extractor.py capture.pcap -f 1 -f 3 -f 5
```

### 4. Automation

```bash
#!/bin/bash
# Process multiple PCAP files
for file in captures/*.pcap; do
    echo "Processing $file..."
    python3 session_ja3_extractor.py "$file" -H -e "rules/$(basename "$file" .pcap).rules"
done
```

### 5. Integration with Suricata

1. **Copy rules to Suricata directory:**
   ```bash
   sudo cp generated_rules.rules /etc/suricata/rules/
   ```

2. **Update Suricata configuration:**
   ```yaml
   # suricata.yaml
   rule-files:
     - generated_rules.rules
   ```

3. **Reload Suricata:**
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml
   sudo systemctl reload suricata
   ```

## Advanced Usage

### Custom Tool Names

```bash
# Use descriptive tool names
python3 session_ja3_extractor.py capture.pcap -H -t "MalwareAnalysis" -e malware_rules.rules
python3 session_ja3_extractor.py capture.pcap -X -t "ThreatHunting" -e threat_rules.rules
```

### Batch Processing

```bash
# Process multiple files with different settings
python3 session_ja3_extractor.py malware.pcap -H -t "Malware" -e malware.rules
python3 session_ja3_extractor.py normal.pcap -H -t "Baseline" -e baseline.rules
python3 session_ja3_extractor.py suspicious.pcap -H -X -t "Suspicious" -e suspicious.rules
```

### Integration Scripts

```python
#!/usr/bin/env python3
"""Integration script for automated rule generation."""

import subprocess
import os
import sys

def generate_rules(pcap_file, rule_type="hash"):
    """Generate rules for a PCAP file."""
    cmd = [
        "python3", "session_ja3_extractor.py", pcap_file,
        "-H" if rule_type == "hash" else "-X",
        "-e", f"{os.path.basename(pcap_file)}.rules"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_rules.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    if generate_rules(pcap_file):
        print(f"Rules generated successfully for {pcap_file}")
    else:
        print(f"Failed to generate rules for {pcap_file}")
        sys.exit(1)
```
