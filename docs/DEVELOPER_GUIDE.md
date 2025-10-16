# Developer Guide

This guide provides information for developers who want to contribute to or extend the JA3 Session Extractor.

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [Code Standards](#code-standards)
4. [Testing](#testing)
5. [Extending the Project](#extending-the-project)
6. [Debugging](#debugging)
7. [Performance Optimization](#performance-optimization)

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment
- Code editor (VS Code, PyCharm, etc.)

### Development Environment

1. **Clone the repository**
   ```bash
   git clone https://github.com/shashinma/rules.git
   cd rules
   ```

2. **Create development virtual environment**
   ```bash
   python3 -m venv dev-env
   source dev-env/bin/activate  # On Linux/macOS
   # or
   dev-env\Scripts\activate     # On Windows
   ```

3. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e .  # Install in development mode
   ```

4. **Install development tools**
   ```bash
   pip install pytest black flake8 mypy
   ```

## Project Structure

```
rules/
├── src/                           # Source code
│   └── ja3_extractor/            # Main package
│       ├── __init__.py           # Package initialization
│       ├── ja3_session_analyzer.py # Main application class
│       ├── core/                 # Core functionality
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
│   └── FAQ.md                  # FAQ
├── examples/                   # Usage examples
│   ├── README.md               # Examples documentation
│   ├── quick_api_test.py       # Quick API test
│   ├── simple_api_example.py   # Simple usage example
│   ├── working_api_example.py  # Working example with real files
│   ├── api_examples.py         # Comprehensive examples
│   └── example_usage.py        # Basic usage example
├── tests/                      # Test files
│   ├── README.md               # Tests documentation
│   ├── quick_api_test.py       # Quick API test
│   └── test_ja3_extractor.py   # Unit tests
├── session_ja3_extractor.py     # Main entry point
├── requirements.txt             # Dependencies
├── pyproject.toml              # Project configuration
└── README.md                    # Project documentation
```

## Code Standards

### PEP Compliance

The project follows Python PEP standards:

- **PEP 8** - Code style
- **PEP 257** - Docstring conventions
- **PEP 484** - Type hints

### Code Style

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Module docstring describing the purpose."""

import os
import sys
from typing import Dict, List, Optional


class ExampleClass:
    """Class docstring describing the class purpose."""
    
    def __init__(self, param: str) -> None:
        """Initialize the class.
        
        Args:
            param: Description of the parameter
        """
        self.param = param
    
    def example_method(self, data: List[str]) -> Optional[Dict[str, str]]:
        """Example method with type hints.
        
        Args:
            data: List of strings to process
            
        Returns:
            Dictionary with processed data or None if error
            
        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Data cannot be empty")
        
        return {"processed": "data"}
```

### Docstring Format

Use Google-style docstrings:

```python
def process_pcap(self, packets: List[bytes]) -> Dict[str, Any]:
    """Process PCAP packets and extract JA3/JA3S hashes.
    
    This method analyzes TLS handshake packets to extract JA3 and JA3S
    fingerprints, grouping them by TLS sessions.
    
    Args:
        packets: List of raw packet data from PCAP file
        
    Returns:
        Dictionary containing session data with JA3/JA3S hashes
        
    Raises:
        ValueError: If packets list is empty
        Exception: If packet parsing fails
        
    Example:
        >>> extractor = JA3Extractor()
        >>> sessions = extractor.process_pcap(packets)
        >>> print(f"Found {len(sessions)} sessions")
    """
    pass
```

## Testing

### Test Structure

```
tests/
├── __init__.py
├── README.md               # Test documentation
├── quick_api_test.py       # Quick API functionality test
└── test_ja3_extractor.py  # Comprehensive unit tests
```

### Examples Structure

```
examples/
├── __init__.py
├── README.md               # Examples documentation
├── quick_api_test.py       # Quick API test
├── simple_api_example.py   # Simple usage example
├── working_api_example.py  # Working example with real files
├── api_examples.py         # Comprehensive examples
└── example_usage.py        # Basic usage example
```

### Writing Tests

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for JA3 extractor functionality."""

import unittest
from unittest.mock import Mock, patch
from src.ja3_extractor.core import JA3Extractor


class TestJA3Extractor(unittest.TestCase):
    """Test cases for JA3Extractor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.extractor = JA3Extractor()
    
    def test_process_pcap_empty_packets(self):
        """Test processing empty packet list."""
        with self.assertRaises(ValueError):
            self.extractor.process_pcap([])
    
    def test_process_pcap_valid_packets(self):
        """Test processing valid packets."""
        # Mock packet data
        mock_packets = [Mock(), Mock()]
        
        with patch.object(self.extractor, '_parse_packet') as mock_parse:
            mock_parse.return_value = {'ja3': 'test_hash'}
            result = self.extractor.process_pcap(mock_packets)
            
            self.assertIsInstance(result, dict)
            self.assertEqual(len(mock_parse.call_args_list), 2)
    
    def tearDown(self):
        """Clean up after tests."""
        pass


if __name__ == '__main__':
    unittest.main()
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_ja3_extractor.py

# Run quick API test
python3 tests/quick_api_test.py

# Run with coverage
python -m pytest --cov=src tests/

# Run with verbose output
python -m pytest -v tests/
```

## Extending the Project

### Adding New Rule Types

1. **Create new rule generator**
   ```python
   # src/ja3_extractor/rules/custom_rule_generator.py
   
   class CustomRuleGenerator:
       """Custom rule generator for different IDS systems."""
       
       def generate_custom_rules(self, sessions):
           """Generate custom format rules."""
           rules = []
           for session in sessions:
               if session['has_ja3']:
                   rule = self._create_custom_rule(session)
                   rules.append(rule)
           return rules
   ```

2. **Add CLI option**
   ```python
   # src/ja3_extractor/cli/argument_parser.py
   
   parser.add_argument("-c", "--custom-rules", 
                      action="store_true", 
                      help="Generate custom format rules")
   ```

3. **Integrate with main analyzer**
   ```python
   # src/ja3_extractor/ja3_session_analyzer.py
   
   def _generate_custom_rules(self, sessions):
       """Generate custom format rules."""
       generator = CustomRuleGenerator()
       return generator.generate_custom_rules(sessions)
   ```

### Adding New Output Formats

1. **Create new formatter**
   ```python
   # src/ja3_extractor/output/custom_formatter.py
   
   class CustomFormatter:
       """Custom output formatter."""
       
       def format_custom_output(self, sessions):
           """Format sessions in custom format."""
           output = []
           for session in sessions:
               formatted = self._format_session(session)
               output.append(formatted)
           return '\n'.join(output)
   ```

2. **Add CLI option**
   ```python
   parser.add_argument("--custom-format", 
                      action="store_true",
                      help="Output in custom format")
   ```

### Adding New Session Filters

1. **Extend SessionManager**
   ```python
   # src/ja3_extractor/core/session_manager.py
   
   def get_sessions_by_ip(self, ip_address):
       """Get sessions filtered by IP address."""
       filtered = {}
       for key, session in self.sessions.items():
           if (session['client_ip'] == ip_address or 
               session['server_ip'] == ip_address):
               filtered[key] = session
       return filtered
   ```

2. **Add CLI option**
   ```python
   parser.add_argument("--filter-ip", 
                      type=str,
                      help="Filter sessions by IP address")
   ```

## Debugging

### Debug Mode

Add debug logging to classes:

```python
import logging

class JA3Extractor:
    """JA3 extractor with debug support."""
    
    def __init__(self, debug=False):
        """Initialize with optional debug mode."""
        self.debug = debug
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            self.logger = logging.getLogger(__name__)
    
    def process_pcap(self, packets):
        """Process packets with debug logging."""
        if self.debug:
            self.logger.debug(f"Processing {len(packets)} packets")
        
        # Processing logic...
        
        if self.debug:
            self.logger.debug(f"Found {len(sessions)} sessions")
```

### Debugging Tools

1. **Python Debugger (pdb)**
   ```python
   import pdb
   
   def problematic_function():
       pdb.set_trace()  # Breakpoint
       # Code to debug
   ```

2. **Logging**
   ```python
   import logging
   
   logging.basicConfig(
       level=logging.DEBUG,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   
   logger = logging.getLogger(__name__)
   logger.debug("Debug message")
   ```

3. **Profiling**
   ```python
   import cProfile
   
   def profile_function():
       # Function to profile
       pass
   
   cProfile.run('profile_function()')
   ```

## Performance Optimization

### Memory Optimization

1. **Generator Functions**
   ```python
   def process_packets_generator(packets):
       """Process packets one at a time to save memory."""
       for packet in packets:
           yield process_single_packet(packet)
   ```

2. **Lazy Loading**
   ```python
   class LazySessionManager:
       """Session manager with lazy loading."""
       
       def __init__(self):
           self._sessions = None
       
       @property
       def sessions(self):
           if self._sessions is None:
               self._sessions = self._load_sessions()
           return self._sessions
   ```

### CPU Optimization

1. **Multiprocessing**
   ```python
   from multiprocessing import Pool
   
   def process_pcap_parallel(pcap_files):
       """Process multiple PCAP files in parallel."""
       with Pool() as pool:
           results = pool.map(process_single_pcap, pcap_files)
       return results
   ```

2. **Caching**
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=128)
   def expensive_calculation(data):
       """Cache expensive calculations."""
       # Expensive computation
       return result
   ```

### Profiling and Monitoring

1. **Memory Profiling**
   ```bash
   pip install memory-profiler
   python -m memory_profiler script.py
   ```

2. **Time Profiling**
   ```bash
   pip install line-profiler
   python -m line_profiler script.py
   ```

3. **System Monitoring**
   ```python
   import psutil
   
   def monitor_resources():
       """Monitor system resources."""
       cpu_percent = psutil.cpu_percent()
       memory_percent = psutil.virtual_memory().percent
       print(f"CPU: {cpu_percent}%, Memory: {memory_percent}%")
   ```

## Contributing Guidelines

### Code Review Process

1. **Create feature branch**
   ```bash
   git checkout -b feature/new-feature
   ```

2. **Make changes and test**
   ```bash
   python -m pytest tests/
   python -m flake8 src/
   python -m black src/
   ```

3. **Commit changes**
   ```bash
   git add .
   git commit -m "Add new feature: brief description"
   ```

4. **Push and create PR**
   ```bash
   git push origin feature/new-feature
   ```

### Code Quality Checks

```bash
# Format code
python -m black src/ tests/

# Check style
python -m flake8 src/ tests/

# Type checking
python -m mypy src/

# Run tests
python -m pytest tests/ -v

# Coverage report
python -m pytest --cov=src tests/ --cov-report=html
```

### Documentation Updates

When adding new features:

1. Update API documentation in `docs/API.md`
2. Update user guide in `docs/USER_GUIDE.md`
3. Update README.md if needed
4. Add examples in `examples/` directory
5. Update test documentation in `tests/README.md`
5. Update CHANGELOG.md

### Release Process

1. **Update version numbers**
   - `pyproject.toml`
   - `src/ja3_extractor/__init__.py`
   - `session_ja3_extractor.py`

2. **Update documentation**
   - CHANGELOG.md
   - README.md

3. **Create release**
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

4. **Build package**
   ```bash
   python -m build
   ```
