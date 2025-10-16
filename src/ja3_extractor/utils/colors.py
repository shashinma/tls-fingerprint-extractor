#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Terminal color codes management class."""


class Colors:
    """Terminal color codes management class."""
    
    # Basic colors
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'  # Orange color
    GRAY = '\033[90m'
    LIGHT_GRAY = '\033[37m'
    WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Colors for Suricata syntax
    SURICATA_KEYWORD = '\033[95m'  # Purple for keywords
    SURICATA_STRING = '\033[93m'   # Yellow for strings
    SURICATA_NUMBER = '\033[96m'   # Cyan for numbers
    SURICATA_OPERATOR = '\033[91m' # Red for operators
    
    @classmethod
    def disable_colors(cls):
        """Disable all colors (for cases when terminal doesn't support colors)."""
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.ORANGE = ''
        cls.GRAY = ''
        cls.LIGHT_GRAY = ''
        cls.WHITE = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
        cls.END = ''
        cls.SURICATA_KEYWORD = ''
        cls.SURICATA_STRING = ''
        cls.SURICATA_NUMBER = ''
        cls.SURICATA_OPERATOR = ''
