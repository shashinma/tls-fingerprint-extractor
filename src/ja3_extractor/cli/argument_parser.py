#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Command line argument parser class."""

import argparse
import os
import dpkt
from ..utils.colors import Colors


class ColoredHelpFormatter(argparse.HelpFormatter):
    """Custom help formatter with colored output."""
    
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=80)
    
    def _format_action_invocation(self, action):
        """Format action invocation with colors."""
        if not action.option_strings:
            # Positional argument
            return f"{Colors.BOLD}{Colors.CYAN}{action.dest}{Colors.END}"
        
        # Optional arguments
        parts = []
        for option_string in action.option_strings:
            if option_string.startswith('--'):
                # Long option
                parts.append(f"{Colors.BOLD}{Colors.GREEN}{option_string}{Colors.END}")
            else:
                # Short option
                parts.append(f"{Colors.BOLD}{Colors.YELLOW}{option_string}{Colors.END}")
        
        return ', '.join(parts)
    
    def _format_text(self, text):
        """Format help text with colors."""
        if text is None:
            return ''
        
        # Colorize metavar
        if '{' in text and '}' in text:
            # Replace metavar placeholders with colored versions
            import re
            text = re.sub(r'\{([^}]+)\}', r'{}\1{}'.format(Colors.BOLD + Colors.RED, Colors.END), text)
        
        return text
    
    def _format_usage(self, usage, actions, groups, prefix):
        """Format usage line with colors."""
        if prefix is None:
            prefix = f"{Colors.BOLD}{Colors.BLUE}usage:{Colors.END} "
        
        return super()._format_usage(usage, actions, groups, prefix)
    
    def _format_action(self, action):
        """Format individual action with colors."""
        # Format the action header
        action_header = self._format_action_invocation(action)
        
        # Format the help text
        help_text = self._format_text(action.help) if action.help else ''
        
        # Format metavar if present
        if action.metavar:
            metavar = f"{Colors.BOLD}{Colors.RED}{action.metavar}{Colors.END}"
            action_header += f" {metavar}"
        
        # Combine header and help
        if help_text:
            return f"{action_header}\n{Colors.LIGHT_GRAY}{help_text}{Colors.END}\n"
        else:
            return f"{action_header}\n"
    
    def _format_action_group(self, action_group):
        """Format action group with colors."""
        if not action_group._group_actions:
            return ''
        
        # Format group title
        title = action_group.title
        if title:
            title = f"{Colors.BOLD}{Colors.HEADER}{title}:{Colors.END}"
        
        # Format actions
        action_texts = []
        for action in action_group._group_actions:
            action_text = self._format_action(action)
            if action_text:
                action_texts.append(action_text)
        
        if action_texts:
            return f"{title}\n" + "\n".join(action_texts) + "\n"
        return ""


class ArgumentParser:
    """Command line argument parser class."""
    
    def __init__(self):
        """Initialize argument parser."""
        self.parser = self._create_parser()
    
    def _create_parser(self):
        """Create command line argument parser."""
        desc = f"{Colors.BOLD}{Colors.CYAN}Script for extracting JA3 and JA3S fingerprints from PCAP files with session grouping{Colors.END}"
        parser = argparse.ArgumentParser(
            description=desc,
            formatter_class=ColoredHelpFormatter,
            add_help=False  # We'll add custom help
        )
        
        # Add custom help
        parser.add_argument(
            "-h", "--help", 
            action="help", 
            help=f"{Colors.BOLD}{Colors.GREEN}Show this help message and exit{Colors.END}"
        )
        
        parser.add_argument("pcap", help="PCAP file to process")
        
        help_text = "Search for client handshakes only on port 443 (by default searches on all ports)"
        parser.add_argument("-p", "--ssl_port_only", required=False,
                           action="store_true", default=False,
                           help=help_text)
        
        help_text = "Output results in JSON format"
        parser.add_argument("-j", "--json", required=False, action="store_true",
                           default=False, help=help_text)
        
        help_text = "Generate hash-based Suricata rules"
        parser.add_argument("-H", "--hash-rules", required=False, action="store_true",
                           default=False, help=help_text)
        
        help_text = "Generate HEX-based Suricata rules"
        parser.add_argument("-X", "--hex-rules", required=False, action="store_true",
                           default=False, help=help_text)
        
        help_text = "Show only rules (skip session analysis)"
        parser.add_argument("-r", "--rules-only", required=False, action="store_true",
                           default=False, help=help_text)
        
        help_text = "Export rules to file"
        parser.add_argument("-e", "--export-rules", required=False, type=str,
                           metavar="FILE", help=help_text)
        
        help_text = "Filter by session number (starts from 1)"
        parser.add_argument("-f", "--filter-session", required=False, type=int,
                           metavar="SESSION_NUMBER", help=help_text)
        
        help_text = "Show list of all sessions with their keys"
        parser.add_argument("-l", "--list-sessions", required=False, action="store_true",
                           default=False, help=help_text)
        
        help_text = "Tool name for display in Suricata rules (default: ja3-hash-rule or ja3-hex-rule)"
        parser.add_argument("-t", "--tool-name", required=False, type=str,
                           metavar="NAME", help=help_text)
        
        return parser
    
    def parse_args(self):
        """Parse command line arguments."""
        return self.parser.parse_args()
    
    def validate_pcap_file(self, pcap_path):
        """Validate PCAP file."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError("PCAP file not found: {}".format(pcap_path))
        
        if not os.access(pcap_path, os.R_OK):
            raise PermissionError("No read permission for file: {}".format(pcap_path))
        
        return True
    
    def load_pcap_file(self, pcap_path):
        """Load PCAP file."""
        try:
            with open(pcap_path, 'rb') as fp:
                try:
                    capture = dpkt.pcap.Reader(fp)
                    # Read all data into memory so file can be closed
                    packets = list(capture)
                    return packets
                except ValueError as e_pcap:
                    try:
                        fp.seek(0, os.SEEK_SET)
                        capture = dpkt.pcapng.Reader(fp)
                        packets = list(capture)
                        return packets
                    except ValueError as e_pcapng:
                        raise Exception(
                            "File is not PCAP or PCAPng: %s, %s" %
                            (e_pcap, e_pcapng))
        except Exception as e:
            raise Exception("Error reading file: %s" % str(e))
