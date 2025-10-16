# JA3 Session Extractor - Refactored Version

This project is a refactored version of the original script for extracting JA3 and JA3S hashes from PCAP files, divided into classes according to PEP standards.

## Description

JA3 is a method for creating TLS client fingerprints by hashing values from Client Hello messages. JA3S is a similar method for Server Hello messages. This tool analyzes PCAP files and extracts these fingerprints with grouping by TLS sessions.

## Features

- [x] JA3 and JA3S hash extraction from PCAP/PCAPng files
- [x] Grouping by TLS sessions
- [x] Hash-based Suricata rules generation
- [x] HEX-based Suricata rules generation
- [x] Rules export to file with metadata
- [x] Filtering by specific session
- [x] List of all sessions with keys
- [x] JSON output format
- [x] Colored output with syntax highlighting
- [x] Support for all ports or port 443 only
- [x] Show only complete sessions (with JA3 and JA3S)
- [x] Enhanced colored session list with IP and port highlighting
- [x] Custom tool name for Suricata rules
- [x] Automatic duplicate rule removal
- [x] Generation date in exported rules
- [x] Custom pycache directory management
- [x] Modular architecture with PEP compliance
- [x] Object-oriented design with SOLID principles
- [x] Comprehensive error handling and documentation

## Installation

### ⚠️ Important: Virtual environment is required!

The script **DOES NOT WORK** without a virtual environment for the following reasons:
- macOS uses externally-managed environment for Python
- System Python is protected from package installation
- Required dependencies (`dpkt`, `packaging`) are missing in system Python

### Creating virtual environment (required)
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate     # On Windows
```

### Installing dependencies
```bash
pip install -r requirements.txt
```

### Installing as package (optional)
```bash
# Development installation
pip install -e .

# Or regular installation
pip install .
```

### Alternative ways to run

#### 1. Bash script (automatically creates venv)
```bash
./run_ja3_extractor.sh file.pcap -H
```

#### 2. Python wrapper script
```bash
python3 ja3_extractor.py file.pcap -H
```

#### 3. Direct execution
```bash
python3 session_ja3_extractor.py file.pcap -H
```

#### 4. Force installation in system Python (not recommended)
```bash
pip install --break-system-packages dpkt packaging
```

## Usage

### Basic commands

```bash
# Session analysis
python session_ja3_extractor.py file.pcap

# JSON output
python session_ja3_extractor.py file.pcap --json

# Generate hash-based Suricata rules
python session_ja3_extractor.py file.pcap -H

# Generate HEX-based Suricata rules
python session_ja3_extractor.py file.pcap -X

# Rules only (skip session analysis)
python ja3_extractor.py file.pcap -r -H

# Search only on port 443
python ja3_extractor.py file.pcap -p

# Show list of all sessions
python ja3_extractor.py file.pcap -l

# Filter by specific session number
python ja3_extractor.py file.pcap -f 1

# Export rules to file
python ja3_extractor.py file.pcap -H -e rules.rules

# Export both rule types
python ja3_extractor.py file.pcap -H -X -e rules.rules

# Specify tool name in rules
python ja3_extractor.py file.pcap -H -t "My Security Tool"
```

### Command line parameters

| Parameter | Description |
|-----------|-------------|
| `pcap` | PCAP file to process (required) |
| `-p, --ssl-port-only` | Search only on port 443 |
| `-j, --json` | Output results in JSON format |
| `-H, --hash-rules` | Generate hash-based Suricata rules |
| `-X, --hex-rules` | Generate HEX-based Suricata rules |
| `-r, --rules-only` | Show only rules (skip analysis) |
| `-e, --export-rules FILE` | Export rules to file |
| `-f, --filter-session NUMBER` | Filter by session number |
| `-l, --list-sessions` | Show list of all sessions with keys |
| `-t, --tool-name NAME` | Tool name for display in rules |

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Documentation Index](docs/index.md)** - Overview of all documentation
- **[User Guide](docs/USER_GUIDE.md)** - Complete user guide with examples
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Guide for developers and contributors
- **[API Reference](docs/API.md)** - Complete API reference
- **[API Examples](examples/README.md)** - Practical API usage examples
- **[FAQ](docs/FAQ.md)** - Frequently asked questions

## Architecture

The project is divided into the following modules:

### Main classes

- **`JA3SessionAnalyzer`** - Main application class that coordinates all components
- **`JA3Extractor`** - Class for extracting JA3 and JA3S hashes from PCAP files
- **`SessionManager`** - Class for managing TLS sessions
- **`SuricataRuleGenerator`** - Class for generating Suricata rules
- **`OutputFormatter`** - Class for formatting output results
- **`ArgumentParser`** - Class for processing command line arguments
- **`Colors`** - Class for managing terminal color codes

### Utility modules

- **`utils.py`** - Utility functions for working with JA3 and JA3S
- **`__init__.py`** - Package initialization

## File structure

```
rules/
├── src/                           # Source code package
│   └── ja3_extractor/            # Main package
│       ├── __init__.py           # Package initialization
│       ├── ja3_session_analyzer.py # Main application class
│       ├── core/                 # Core components
│       │   ├── __init__.py
│       │   ├── ja3_extractor.py  # JA3/JA3S extraction
│       │   └── session_manager.py # Session management
│       ├── rules/               # Rule generation
│       │   ├── __init__.py
│       │   └── suricata_rule_generator.py
│       ├── output/              # Output formatting
│       │   ├── __init__.py
│       │   └── output_formatter.py
│       ├── cli/                 # Command line interface
│       │   ├── __init__.py
│       │   └── argument_parser.py
│       └── utils/               # Utility functions
│           ├── __init__.py
│           ├── utils.py
│           └── colors.py
├── docs/                        # Documentation
│   ├── index.md                # Documentation index
│   ├── USER_GUIDE.md           # User guide
│   ├── DEVELOPER_GUIDE.md      # Developer guide
│   ├── API.md                  # API reference
│   ├── API_EXAMPLES.md         # API usage examples
│   └── FAQ.md                  # Frequently asked questions
├── examples/                   # Usage examples
│   ├── __init__.py
│   ├── README.md               # Examples documentation
│   ├── quick_api_test.py       # Quick API test
│   ├── simple_api_example.py   # Simple usage example
│   ├── working_api_example.py  # Working example with real files
│   ├── api_examples.py         # Comprehensive examples
│   └── example_usage.py        # Basic usage example
├── tests/                      # Test files
│   ├── __init__.py
│   ├── README.md               # Tests documentation
│   ├── quick_api_test.py       # Quick API test
│   └── test_ja3_extractor.py   # Unit tests
├── ja3_extractor.py             # Main script
├── ja3_extractor.sh             # Bash wrapper script
├── session_ja3_extractor.py     # Legacy script (compatibility)
├── run_ja3_extractor.sh         # Auto venv script
├── requirements.txt             # Dependencies
├── setup.py                     # Package installation
├── pyproject.toml              # Modern configuration
├── setup.cfg                   # Additional configuration
├── .pythonrc                   # Python startup configuration
├── .gitignore                  # Git ignore rules
├── README.md                    # Documentation
├── ARCHITECTURE.md              # Architecture
└── base/                        # Original modules
    ├── ja3.py
    └── ja3s.py
```

## Examples

### As module
```python
from ja3_session_analyzer import JA3SessionAnalyzer

analyzer = JA3SessionAnalyzer()
# Configure and run analysis
```

### Using individual components
```python
from ja3_extractor.core import JA3Extractor, SessionManager
from ja3_extractor.rules import SuricataRuleGenerator
from ja3_extractor.output import OutputFormatter

extractor = JA3Extractor()
sessions = extractor.process_pcap(packets)
```

### Running tests
```bash
python -m unittest tests.test_ja3_extractor
```

### Running examples
```bash
python examples/example_usage.py
```

## Refactoring principles

### 1. Single Responsibility Principle
Each class is responsible for one specific task:
- `JA3Extractor` - only hash extraction
- `SessionManager` - only session management
- `SuricataRuleGenerator` - only rule generation
- `OutputFormatter` - only output formatting

### 2. Encapsulation
All data and methods are encapsulated in appropriate classes with clear interfaces.

### 3. PEP standards compliance
- PEP 8 - code style
- PEP 257 - documentation
- PEP 484 - type hints (where applicable)

### 4. Modularity
Code is divided into logical modules, each of which can be used independently.

## Advantages of new architecture

1. **Readability** - code is easier to read and understand
2. **Testability** - each class can be tested independently
3. **Extensibility** - easy to add new features
4. **Reusability** - components can be used in other projects
5. **Maintainability** - easier to fix bugs and add features

## Key Features

### Enhanced colored output
- IP addresses highlighted in yellow/orange
- Ports highlighted in red
- Session keys with directional arrows (→)
- Bold formatting for IPs and ports in session headers

### Improved rule generation
- Custom tool names for Suricata rules
- Automatic duplicate rule removal
- Generation date in exported rules
- Support for both hash-based and HEX-based rules simultaneously

### Better session management
- Session filtering by number (starting from 1)
- Enhanced session list display
- Complete sessions only (no incomplete sessions)

### Python bytecode management
- Custom `__pycache__` directory within project
- No external dependencies for pycache configuration
- Clean project structure

## Compatibility

The new version is fully compatible with the original command line interface and supports all existing options.

## Versioning

- **v1.0.0** - Complete refactored version with modular architecture, English translation, and enhanced features

## License

BSD 3-Clause License

## Authors

Copyright (c) 2025, Mikhail Shashin
