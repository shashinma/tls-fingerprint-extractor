# Frequently Asked Questions (FAQ)

This document answers common questions about the JA3 Session Extractor.

## General Questions

### What is JA3 Session Extractor?

JA3 Session Extractor is a Python tool that analyzes PCAP/PCAPng files to extract JA3 and JA3S TLS fingerprints. It groups TLS handshakes by sessions and can generate Suricata IDS rules based on the extracted fingerprints.

### What are JA3 and JA3S?

- **JA3**: A method for creating TLS client fingerprints by hashing values from Client Hello messages
- **JA3S**: A similar method for Server Hello messages

These fingerprints help identify specific TLS implementations and can be used for threat detection and network analysis.

### What file formats are supported?

The tool supports:
- PCAP files (.pcap)
- PCAPng files (.pcapng)

## Installation Questions

### Why do I need a virtual environment?

Virtual environments are required because:
- macOS uses externally-managed environment for Python
- System Python is protected from package installation
- Required dependencies (`dpkt`, `packaging`) are missing in system Python

### How do I install dependencies?

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Can I install without virtual environment?

Yes, but not recommended:
```bash
pip install --break-system-packages dpkt packaging
```

## Usage Questions

### How do I run the tool?

```bash
# Basic usage
python3 session_ja3_extractor.py capture.pcap

# With virtual environment
source venv/bin/activate
python3 session_ja3_extractor.py capture.pcap
```

### What command line options are available?

| Short | Long | Description |
|-------|------|-------------|
| `-h` | `--help` | Show help message |
| `-p` | `--ssl-port-only` | Search only port 443 |
| `-j` | `--json` | JSON output format |
| `-H` | `--hash-rules` | Generate hash-based rules |
| `-X` | `--hex-rules` | Generate HEX-based rules |
| `-r` | `--rules-only` | Show only rules |
| `-e` | `--export-rules` | Export rules to file |
| `-f` | `--filter-session` | Filter by session number |
| `-l` | `--list-sessions` | Show sessions list |
| `-t` | `--tool-name` | Tool name for rules |

### How do I generate Suricata rules?

```bash
# Hash-based rules
python3 session_ja3_extractor.py capture.pcap -H

# HEX-based rules
python3 session_ja3_extractor.py capture.pcap -X

# Both types
python3 session_ja3_extractor.py capture.pcap -H -X

# Export to file
python3 session_ja3_extractor.py capture.pcap -H -e rules.rules
```

### How do I filter sessions?

```bash
# List all sessions first
python3 session_ja3_extractor.py capture.pcap -l

# Filter specific session
python3 session_ja3_extractor.py capture.pcap -f 1
```

## Technical Questions

### What Python version is required?

Python 3.8 or higher is required.

### What dependencies are needed?

- `dpkt>=1.9.8` - For PCAP file parsing
- `packaging>=25.0` - For version handling

### How does session grouping work?

Sessions are grouped by:
- Client IP and port
- Server IP and port
- TLS handshake sequence

Each unique combination creates a separate session.

### What is the difference between hash-based and HEX-based rules?

- **Hash-based**: Uses MD5 hash of JA3/JA3S fingerprint
- **HEX-based**: Uses hexadecimal representation of the fingerprint

Both can be used in Suricata, but HEX-based rules are more specific.

## Troubleshooting Questions

### "ModuleNotFoundError: No module named 'dpkt'"

**Solution:**
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install dpkt packaging
```

### "PermissionError: No read permission for file"

**Solution:**
```bash
# Check file permissions
ls -la capture.pcap

# Fix permissions
chmod 644 capture.pcap
```

### "Exception: File is not PCAP or PCAPng"

**Possible causes:**
- File is corrupted
- Wrong file format
- File is empty

**Solution:**
- Verify file integrity
- Check file extension
- Ensure file contains network traffic

### "ValueError: Session number X not found"

**Solution:**
```bash
# List available sessions
python3 session_ja3_extractor.py capture.pcap -l

# Use correct session number
python3 session_ja3_extractor.py capture.pcap -f 1
```

### No sessions found in PCAP file

**Possible causes:**
- No TLS traffic in file
- All traffic on non-443 ports (use `-p` flag)
- Incomplete TLS handshakes

**Solution:**
```bash
# Search all ports
python3 session_ja3_extractor.py capture.pcap

# Search only port 443
python3 session_ja3_extractor.py capture.pcap -p
```

## Performance Questions

### How to handle large PCAP files?

For files >1GB:
```bash
# Use rules-only mode
python3 session_ja3_extractor.py large.pcap -r -H

# Filter specific sessions
python3 session_ja3_extractor.py large.pcap -f 1 -H
```

### Memory usage optimization

- Use virtual environment
- Close other applications
- Consider splitting large files
- Use `--rules-only` for rule generation

### Processing time

Processing time depends on:
- File size
- Number of TLS sessions
- System resources

Typical performance:
- Small files (<100MB): seconds
- Medium files (100MB-1GB): minutes
- Large files (>1GB): 10+ minutes

## Integration Questions

### How to integrate with Suricata?

1. **Generate rules:**
   ```bash
   python3 session_ja3_extractor.py capture.pcap -H -e rules.rules
   ```

2. **Copy to Suricata:**
   ```bash
   sudo cp rules.rules /etc/suricata/rules/
   ```

3. **Update configuration:**
   ```yaml
   # suricata.yaml
   rule-files:
     - rules.rules
   ```

4. **Reload Suricata:**
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml
   sudo systemctl reload suricata
   ```

### How to automate rule generation?

Create a script:
```bash
#!/bin/bash
for file in captures/*.pcap; do
    echo "Processing $file..."
    python3 session_ja3_extractor.py "$file" -H -e "rules/$(basename "$file" .pcap).rules"
done
```

### How to integrate with SIEM?

Export rules and import into your SIEM:
1. Generate rules with custom tool names
2. Use SIEM's rule import functionality
3. Configure alerts and dashboards

## Output Questions

### What does the session list show?

The session list displays:
- Session number
- Client and server IP:port
- JA3/JA3S availability (✓/✗)
- Color-coded information

### What does JSON output contain?

JSON output includes:
- Session keys
- IP addresses and ports
- JA3/JA3S hashes
- Timestamps
- Extension data

### How are Suricata rules formatted?

Rules follow Suricata format:
```
alert tls any any -> any any (msg:"JA3 Hash Detection"; content:"hash_value"; sid:2000001; rev:1;)
```

## Development Questions

### How to contribute to the project?

1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

See `CONTRIBUTING.md` for details.

### How to extend functionality?

The project is modular:
- Add new rule generators in `rules/`
- Add new output formats in `output/`
- Add new CLI options in `cli/`

See `DEVELOPER_GUIDE.md` for details.

### How to run tests?

```bash
# Install test dependencies
pip install pytest

# Run all tests
python -m pytest tests/

# Run quick API test
python3 tests/quick_api_test.py

# Run specific test file
python -m pytest tests/test_ja3_extractor.py
```

## License Questions

### What license is used?

BSD 3-Clause License - allows commercial use, modification, and distribution.

### Can I use this in commercial products?

Yes, the BSD license allows commercial use.

### Do I need to credit the original author?

Yes, you must retain the copyright notice in the source code.

## Support Questions

### Where to get help?

- Check this FAQ
- Read the documentation
- Open an issue on GitHub
- Check existing issues

### How to report bugs?

1. Check if issue already exists
2. Provide detailed description
3. Include error messages
4. Provide sample PCAP file if possible

### How to request features?

1. Check if feature already exists
2. Describe use case
3. Explain why it would be valuable
4. Consider implementation complexity
