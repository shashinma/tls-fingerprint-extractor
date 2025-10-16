#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JA3 Extractor - Simple wrapper script.

This is a simple wrapper that imports and runs the main JA3 extractor.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main module
if __name__ == "__main__":
    from session_ja3_extractor import main
    main()