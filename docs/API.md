# API Reference

This document provides detailed API reference for all classes and methods in the JA3 Session Extractor.

## Core Classes

### JA3SessionAnalyzer

Main application class that coordinates all components.

```python
from src.ja3_extractor import JA3SessionAnalyzer

analyzer = JA3SessionAnalyzer()
analyzer.run()
```

#### Methods

- `run()` - Main entry point for the application
- `_output_json()` - Output results in JSON format
- `_output_session_analysis()` - Output detailed session analysis
- `_generate_suricata_rules()` - Generate Suricata rules

### JA3Extractor

Core class for extracting JA3 and JA3S hashes from PCAP files.

```python
from src.ja3_extractor.core import JA3Extractor

extractor = JA3Extractor()
sessions = extractor.process_pcap(packets)
```

#### Methods

- `process_pcap(packets)` - Process PCAP packets and extract hashes
- `process_client_hello(packet, session)` - Process Client Hello messages
- `process_server_hello(packet, session)` - Process Server Hello messages
- `process_client_extensions(extensions)` - Process client extensions
- `process_server_extensions(extensions)` - Process server extensions

### SessionManager

Manages TLS session data and state.

```python
from src.ja3_extractor.core import SessionManager

manager = SessionManager()
session = manager.get_session(session_key)
```

#### Methods

- `get_session(session_key)` - Get session data by key
- `update_session(session_key, data)` - Update session data
- `get_all_sessions()` - Get all sessions
- `get_complete_sessions()` - Get only complete sessions
- `get_sessions_sorted_by_time()` - Get sessions sorted by time
- `clear()` - Clear all sessions
- `__len__()` - Get number of sessions
- `__iter__()` - Iterate over sessions

### SuricataRuleGenerator

Generates Suricata IDS rules from JA3/JA3S hashes.

```python
from src.ja3_extractor.rules import SuricataRuleGenerator

generator = SuricataRuleGenerator()
rules = generator.generate_hash_based_rules(sessions)
```

#### Methods

- `generate_hash_based_rules(sessions)` - Generate hash-based rules
- `generate_hex_based_rules(sessions)` - Generate HEX-based rules
- `convert_ja3_to_hex_patterns(ja3_hash)` - Convert JA3 to HEX patterns
- `convert_ja3s_to_hex_patterns(ja3s_hash)` - Convert JA3S to HEX patterns
- `highlight_suricata_syntax(rule)` - Highlight rule syntax
- `_extract_rule_content(rule_text)` - Extract rule content for duplicates
- `_remove_duplicate_rules(rules)` - Remove duplicate rules

### OutputFormatter

Formats and displays analysis results.

```python
from src.ja3_extractor.output import OutputFormatter

formatter = OutputFormatter()
output = formatter.format_session_analysis(sessions)
```

#### Methods

- `format_json_output(sessions)` - Format JSON output
- `format_session_analysis(sessions)` - Format session analysis
- `format_sessions_list(sessions_list)` - Format sessions list
- `format_suricata_rules(rules)` - Format Suricata rules
- `_format_single_session(session)` - Format single session
- `_format_client_hello(session)` - Format Client Hello
- `_format_server_hello(session)` - Format Server Hello
- `_colorize_session_key(session_key)` - Colorize session key

### ArgumentParser

Handles command line argument parsing and validation.

```python
from src.ja3_extractor.cli import ArgumentParser

parser = ArgumentParser()
args = parser.parse_args()
```

#### Methods

- `parse_args()` - Parse command line arguments
- `validate_pcap_file(pcap_path)` - Validate PCAP file
- `load_pcap_file(pcap_path)` - Load and read PCAP file
- `_create_parser()` - Create argument parser

## Utility Classes

### Colors

Manages terminal color codes for formatted output.

```python
from src.ja3_extractor.utils.colors import Colors

print(f"{Colors.BOLD}{Colors.RED}Error message{Colors.END}")
```

#### Constants

- `HEADER` - Header color
- `BLUE`, `CYAN`, `GREEN`, `YELLOW`, `ORANGE`, `RED` - Basic colors
- `LIGHT_GRAY`, `BOLD` - Text formatting
- `SURICATA_KEYWORD`, `SURICATA_STRING` - Suricata syntax colors

#### Methods

- `disable_colors()` - Disable all colors

### Utils

Utility functions for JA3/JA3S processing.

```python
from src.ja3_extractor.utils.utils import convert_ip, create_session_key

ip_str = convert_ip(ip_bytes)
session_key = create_session_key(client_ip, client_port, server_ip, server_port)
```

#### Functions

- `convert_ip(ip_bytes)` - Convert IP bytes to string
- `parse_variable_array(data)` - Parse variable length array
- `ntoh(data)` - Convert network byte order
- `convert_to_ja3_segment(data)` - Convert to JA3 segment
- `create_session_key(client_ip, client_port, server_ip, server_port)` - Create session key
- `create_default_session()` - Create default session structure

## Data Structures

### Session Structure

```python
session = {
    'key': 'client_ip:port-server_ip:port',
    'client_ip': '192.168.1.1',
    'client_port': 12345,
    'server_ip': '10.0.0.1',
    'server_port': 443,
    'has_ja3': True,
    'has_ja3s': True,
    'ja3': 'abc123...',
    'ja3s': 'def456...',
    'client_hello_time': timestamp,
    'server_hello_time': timestamp,
    'extensions': {...}
}
```

### Rule Structure

```python
rule = {
    'sid': 2000001,
    'rule_type': 'hash-based',  # or 'hex-based'
    'ja3_hash': 'abc123...',
    'ja3s_hash': 'def456...',
    'content': 'content:"abc123..."',
    'msg': 'JA3 Hash Detection',
    'tool_name': 'ja3-extractor'
}
```

## Error Handling

### Custom Exceptions

```python
# File not found
raise FileNotFoundError("PCAP file not found: {}".format(pcap_path))

# Permission denied
raise PermissionError("No read permission for file: {}".format(pcap_path))

# Invalid file format
raise Exception("File is not PCAP or PCAPng: %s, %s" % (e_pcap, e_pcapng))

# Session not found
raise ValueError("Session number {} not found".format(session_number))
```

## Configuration

### Environment Variables

- `PYTHONPYCACHEPREFIX` - Custom pycache directory
- `TERM` - Terminal type for color support

### Configuration Files

- `pyproject.toml` - Project configuration
- `setup.cfg` - Additional configuration
- `.pythonrc` - Python startup configuration
- `.gitignore` - Git ignore rules
