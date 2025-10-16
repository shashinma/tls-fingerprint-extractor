# Examples Directory

This directory contains practical examples of how to use the JA3 Session Extractor API.

## 📁 Files

### Python Examples
- **`working_api_example.py`** - Complete working example with real PCAP files
- **`simple_api_example.py`** - Minimal example for quick testing  
- **`api_examples.py`** - Comprehensive examples with various use cases
- **`example_usage.py`** - Basic usage example

### Documentation
- **`API_EXAMPLES_README.md`** - English documentation for API examples
- **`API_EXAMPLES_RU.md`** - Russian documentation for API examples

## 🚀 Quick Start

### Prerequisites
```bash
# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install dpkt packaging
```

### Running Examples

#### From project root:
```bash
# Quick test
python3 tests/quick_api_test.py

# Working example
python3 examples/working_api_example.py

# Simple example
python3 examples/simple_api_example.py

# Comprehensive examples
python3 examples/api_examples.py
```

#### From examples directory:
```bash
cd examples
source ../venv/bin/activate

# Working example
python3 working_api_example.py

# Simple example  
python3 simple_api_example.py

# Comprehensive examples
python3 api_examples.py
```

## 📊 Example Output

The examples will:
- Load and analyze PCAP files from the project root
- Extract JA3/JA3S fingerprints
- Display session information with colored output
- Generate Suricata rules (hash-based and HEX-based)
- Export rules to timestamped files
- Show comprehensive analysis results

## 🔧 Key Features Demonstrated

1. **Basic API Usage** - Loading PCAP files and extracting sessions
2. **Rule Generation** - Creating Suricata rules from JA3/JA3S data
3. **Session Filtering** - Filtering by IP, port, or JA3 hash
4. **JSON Export** - Exporting results in structured format
5. **Error Handling** - Robust error handling patterns
6. **Custom Tool Names** - Generating rules with custom identifiers
7. **Batch Processing** - Processing multiple PCAP files
8. **External Integration** - Integration patterns for SIEM systems

## 📝 Generated Files

Examples create timestamped files:
- `hash_rules_YYYYMMDD_HHMMSS.rules` - Hash-based Suricata rules
- `hex_rules_YYYYMMDD_HHMMSS.rules` - HEX-based Suricata rules  
- `analysis_YYYYMMDD_HHMMSS.json` - JSON analysis results

## 🔍 Troubleshooting

### Common Issues
1. **ModuleNotFoundError**: Install dependencies with `pip install dpkt packaging`
2. **FileNotFoundError**: Ensure PCAP files exist in project root
3. **No sessions found**: Verify PCAP contains TLS traffic
4. **Permission denied**: Check file permissions

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📚 Related Documentation

- [API Reference](../docs/API.md) - Complete API documentation
- [User Guide](../docs/USER_GUIDE.md) - Comprehensive user guide
- [Developer Guide](../docs/DEVELOPER_GUIDE.md) - Development practices
- [FAQ](../docs/FAQ.md) - Frequently asked questions

## 🎯 Use Cases

These examples are designed for:
- **Developers** integrating JA3 Session Extractor into their applications
- **Security Analysts** analyzing network traffic for threat detection
- **Researchers** studying TLS fingerprinting techniques
- **System Administrators** implementing network monitoring solutions
