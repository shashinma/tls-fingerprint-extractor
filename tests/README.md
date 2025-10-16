# Tests Directory

This directory contains test files for the JA3 Session Extractor project.

## 📁 Files

### Test Files
- **`quick_api_test.py`** - Quick API functionality test
- **`test_ja3_extractor.py`** - Comprehensive unit tests for JA3 extractor

## 🚀 Running Tests

### Prerequisites
```bash
# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install dpkt packaging
```

### Running Tests

#### From project root:
```bash
# Quick API test
python3 tests/quick_api_test.py

# Unit tests
python3 tests/test_ja3_extractor.py
```

#### From tests directory:
```bash
cd tests
source ../venv/bin/activate

# Quick API test
python3 quick_api_test.py

# Unit tests
python3 test_ja3_extractor.py
```

## 📊 Test Output

### Quick API Test
The quick test will:
- Import JA3 Session Extractor components
- Initialize analyzer and parser
- Find PCAP files in project root
- Load and process packets
- Extract JA3/JA3S fingerprints
- Generate Suricata rules
- Display sample results

Sample output:
```
JA3 Session Extractor - Quick API Test
==================================================
✅ Successfully imported JA3 Session Extractor
✅ Successfully initialized components
✅ Found 3 PCAP files:
   📄 lig-win-vestadon.ru-all.pcapng
   📄 lig-win-vestadon.ru-all-websocket.pcapng
   📄 capture (2).pcap

🔍 Testing with: ../lig-win-vestadon.ru-all.pcapng
✅ Loaded 17305 packets
✅ Found 238 total sessions
✅ Found 43 complete sessions

📊 Sample session:
   Client: 172.27.55.129:59941
   Server: 46.19.66.166:443

🛡️ Generated 15 hash-based rules
📝 Sample rule:
   alert tls any any -> any any (msg:"JA3 Client Fingerprint Match - JA3 Extractor"...

🎉 API test completed successfully!
```

### Unit Tests
The unit tests will:
- Test individual components
- Verify functionality
- Check error handling
- Validate output formats

## 🔧 Test Features

### Quick API Test Features
- **Import Testing** - Verifies all modules can be imported
- **Initialization Testing** - Tests component initialization
- **File Discovery** - Finds PCAP files in project root
- **Processing Testing** - Tests packet processing and session extraction
- **Rule Generation** - Tests Suricata rule generation
- **Error Handling** - Tests error handling scenarios

### Unit Test Features
- **Component Testing** - Tests individual classes and methods
- **Data Validation** - Validates data structures and formats
- **Edge Cases** - Tests edge cases and error conditions
- **Integration Testing** - Tests component integration

## 🔍 Troubleshooting

### Common Issues
1. **ModuleNotFoundError**: Install dependencies with `pip install dpkt packaging`
2. **FileNotFoundError**: Ensure PCAP files exist in project root
3. **Import errors**: Verify you're running from correct directory
4. **Permission denied**: Check file permissions

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📚 Related Documentation

- [API Reference](../docs/API.md) - Complete API documentation
- [Developer Guide](../docs/DEVELOPER_GUIDE.md) - Development practices
- [API Examples](../examples/API_EXAMPLES_README.md) - Practical usage examples
- [FAQ](../docs/FAQ.md) - Frequently asked questions

## 🎯 Test Coverage

Tests cover:
- **Core Functionality** - Basic JA3/JA3S extraction
- **Session Management** - Session tracking and management
- **Rule Generation** - Suricata rule creation
- **Output Formatting** - Output formatting and display
- **Error Handling** - Error scenarios and recovery
- **File Operations** - PCAP file loading and processing
- **CLI Interface** - Command line argument processing

## 🚀 Continuous Integration

These tests are designed to be run in CI/CD pipelines:
- Fast execution time
- Clear pass/fail indicators
- Comprehensive error reporting
- Minimal external dependencies
