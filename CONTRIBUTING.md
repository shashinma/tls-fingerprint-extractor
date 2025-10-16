# Contributing to JA3 Session Extractor

Thank you for your interest in contributing to JA3 Session Extractor! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows a code of conduct that ensures a welcoming environment for all contributors. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/rules.git
   cd rules
   ```

3. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Linux/macOS
   # or
   venv\Scripts\activate     # On Windows
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## Development Guidelines

### Code Style

This project follows PEP 8 style guidelines. Please ensure your code adheres to these standards:

- Use 4 spaces for indentation
- Maximum line length of 79 characters
- Use meaningful variable and function names
- Add docstrings for all public functions and classes
- Follow PEP 257 for docstring conventions

### Type Hints

Where applicable, use type hints following PEP 484:

```python
def process_pcap(self, packets: List[bytes]) -> Dict[str, Any]:
    """Process PCAP packets and extract JA3/JA3S hashes."""
    pass
```

### Documentation

- All public functions and classes must have docstrings
- Use English for all documentation
- Follow the existing documentation style
- Update README.md and ARCHITECTURE.md when adding new features

### Testing

- Write tests for new functionality
- Ensure all existing tests pass
- Use descriptive test names
- Test both success and failure cases

## Submitting Changes

### Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the guidelines above

3. Test your changes:
   ```bash
   python -m unittest tests/
   ```

4. Update documentation if necessary

5. Commit your changes with descriptive messages:
   ```bash
   git commit -m "Add feature: brief description"
   ```

6. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

7. Create a Pull Request on GitHub

### Commit Message Format

Use clear, descriptive commit messages:

- Use imperative mood ("Add feature" not "Added feature")
- Keep the first line under 50 characters
- Add more details in the body if necessary
- Reference issues when applicable

Examples:
```
Add support for custom tool names in Suricata rules

- Add --tool-name CLI argument
- Update SuricataRuleGenerator to use custom names
- Add default naming based on rule type
- Update documentation

Fixes #123
```

## Areas for Contribution

### Bug Reports

When reporting bugs, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs

### Feature Requests

For feature requests, please:

- Describe the use case
- Explain why it would be valuable
- Consider implementation complexity
- Check if similar functionality exists

### Code Contributions

Areas that could benefit from contributions:

- Additional output formats
- New rule types for different IDS systems
- Performance optimizations
- Additional test coverage
- Documentation improvements
- Error handling enhancements

## Architecture Overview

This project uses a modular architecture with the following main components:

- **JA3SessionAnalyzer**: Main application controller
- **JA3Extractor**: Core logic for hash extraction
- **SessionManager**: Data management for TLS sessions
- **SuricataRuleGenerator**: Rule generation for Suricata
- **OutputFormatter**: Output formatting and display
- **ArgumentParser**: CLI interface
- **Colors**: Terminal color management
- **Utils**: Utility functions

When contributing, please maintain this separation of concerns and follow the existing patterns.

## Release Process

Releases are managed by maintainers and follow semantic versioning:

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Questions and Support

If you have questions about contributing:

- Open an issue for discussion
- Check existing issues and pull requests
- Review the documentation
- Contact maintainers if needed

## License

By contributing to this project, you agree that your contributions will be licensed under the same BSD 3-Clause License that covers the project.

## Recognition

Contributors will be recognized in:

- CHANGELOG.md
- README.md (if significant contribution)
- Release notes

Thank you for contributing to JA3 Session Extractor!

---

**Copyright (c) 2025, Mikhail Shashin**
