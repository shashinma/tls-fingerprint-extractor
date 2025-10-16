#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""JA3 and JA3S hash extraction from PCAP files with session grouping.

This module provides a refactored version of the original script,
divided into classes according to PEP standards.
"""

import os
import sys

# Set custom pycache directory before importing modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYCACHE_DIR = os.path.join(SCRIPT_DIR, '__pycache__')
os.makedirs(PYCACHE_DIR, exist_ok=True)
sys.pycache_prefix = PYCACHE_DIR

from src.ja3_extractor import JA3SessionAnalyzer

__author__ = "Mikhail Shashin"
__copyright__ = "Copyright (c) 2025, Mikhail Shashin"
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"


def main():
    """Main function to run the application."""
    analyzer = JA3SessionAnalyzer()
    analyzer.run()


if __name__ == "__main__":
    main()
