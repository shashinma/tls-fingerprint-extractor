#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Main application class for JA3 and JA3S hash extraction."""

from .core.ja3_extractor import JA3Extractor
from .rules.suricata_rule_generator import SuricataRuleGenerator
from .output.output_formatter import OutputFormatter
from .cli.argument_parser import ArgumentParser
from .utils.colors import Colors


class JA3SessionAnalyzer:
    """Main application class for JA3 session analysis."""
    
    def __init__(self):
        """Initialize session analyzer."""
        self.ja3_extractor = JA3Extractor()
        self.rule_generator = SuricataRuleGenerator()
        self.output_formatter = OutputFormatter()
        self.argument_parser = ArgumentParser()
    
    def run(self):
        """Run main application logic."""
        args = self.argument_parser.parse_args()
        
        # Validate and load PCAP file
        self.argument_parser.validate_pcap_file(args.pcap)
        capture = self.argument_parser.load_pcap_file(args.pcap)
        
        # Process PCAP file
        sessions = self.ja3_extractor.process_pcap(capture, 
                                                 ssl_port_only=args.ssl_port_only)
        
        # Filter sessions - show only complete sessions
        sessions = {k: v for k, v in sessions.items() 
                   if v['ja3'] and v['ja3s']}
        
        # Additional filtering by specific session
        if args.filter_session:
            sessions_list = self.ja3_extractor.session_manager.get_sessions_list()
            if args.filter_session < 1 or args.filter_session > len(sessions_list):
                print(f"Session number {args.filter_session} not found.")
                print(f"Available sessions: 1-{len(sessions_list)}")
                print("Use --list-sessions to view available sessions.")
                return
            
            # Get session by number (index starts from 0)
            selected_session = sessions_list[args.filter_session - 1]
            sessions = self.ja3_extractor.session_manager.get_session_by_key(selected_session['key'])
        
        # Show sessions list
        if args.list_sessions:
            self._show_sessions_list()
            return
        
        # Output results
        if args.json:
            self._output_json(sessions)
        elif not args.rules_only:
            self._output_session_analysis(sessions)
        
        # Generate Suricata rules
        if args.hash_rules or args.hex_rules:
            self._generate_suricata_rules(sessions, args)
        
        # Export rules to file
        if args.export_rules:
            self._export_rules_to_file(sessions, args)
    
    def _output_json(self, sessions):
        """Output results in JSON format."""
        output = self.output_formatter.format_json_output(sessions)
        print(output)
    
    def _output_session_analysis(self, sessions):
        """Output detailed session analysis."""
        output = self.output_formatter.format_session_analysis(sessions)
        print(output)
    
    def _generate_suricata_rules(self, sessions, args):
        """Generate Suricata rules."""
        tool_name = getattr(args, 'tool_name', None)
        
        if args.hash_rules:
            default_name = "ja3-hash-rule" if tool_name is None else tool_name
            self._generate_hash_rules(sessions, default_name)
        
        if args.hex_rules:
            default_name = "ja3-hex-rule" if tool_name is None else tool_name
            self._generate_hex_rules(sessions, default_name)
    
    def _generate_hash_rules(self, sessions, tool_name="JA3 Extractor"):
        """Generate hash-based rules."""
        rules = self.rule_generator.generate_hash_based_rules(sessions, tool_name)
        
        print("\n" + Colors.CYAN + "=" * 60 + Colors.END)
        print(Colors.BOLD + Colors.HEADER + 
              "              Generated Hash-Based Suricata Rules              " + 
              Colors.END)
        print(Colors.CYAN + "=" * 60 + Colors.END)
        
        # Отображаем все правила подряд
        for i, rule in enumerate(rules):
            highlighted_rule = self.rule_generator.highlight_suricata_syntax(rule)
            print(highlighted_rule)
            print()  # Empty line between rules
        
        print(Colors.CYAN + "-" * 60 + Colors.END)
        print("Generated {} unique hash-based Suricata rules from {} sessions".format(
            len(rules), len(sessions)))
        print("")
    
    def _generate_hex_rules(self, sessions, tool_name="JA3 Extractor"):
        """Generate HEX-based rules."""
        rules = self.rule_generator.generate_hex_based_rules(sessions, tool_name)
        
        print("\n" + Colors.CYAN + "=" * 60 + Colors.END)
        print(Colors.BOLD + Colors.HEADER + 
              "              Generated HEX-Based Suricata Rules              " + 
              Colors.END)
        print(Colors.CYAN + "=" * 60 + Colors.END)
        
        # Отображаем все правила подряд
        for i, rule in enumerate(rules):
            highlighted_rule = self.rule_generator.highlight_suricata_syntax(rule)
            print(highlighted_rule)
            print()  # Empty line between rules
        
        print(Colors.CYAN + "-" * 60 + Colors.END)
        print("Generated {} unique HEX-based Suricata rules from {} sessions".format(
            len(rules), len(sessions)))
        print("")
    
    def _show_sessions_list(self):
        """Show list of all sessions."""
        sessions_list = self.ja3_extractor.session_manager.get_sessions_list()
        output = self.output_formatter.format_sessions_list(sessions_list)
        print(output)
    
    def _export_rules_to_file(self, sessions, args):
        """Export rules to file."""
        if not sessions:
            print("No sessions to export rules.")
            return
        
        filename = args.export_rules
        tool_name = getattr(args, 'tool_name', None)
        
        # Determine rule type for export
        if args.hash_rules and args.hex_rules:
            # Export both types
            hash_filename = filename.replace('.rules', '_hash.rules')
            hex_filename = filename.replace('.rules', '_hex.rules')
            
            # Hash-based rules
            hash_tool_name = "ja3-hash-rule" if tool_name is None else tool_name
            hash_rules = self.rule_generator.generate_hash_based_rules(sessions, hash_tool_name)
            success, message = self.rule_generator.export_rules_with_metadata(
                sessions, hash_filename, "hash", hash_tool_name)
            print(f"Hash rules: {message}")
            
            # HEX-based rules
            hex_tool_name = "ja3-hex-rule" if tool_name is None else tool_name
            hex_rules = self.rule_generator.generate_hex_based_rules(sessions, hex_tool_name)
            success, message = self.rule_generator.export_rules_with_metadata(
                sessions, hex_filename, "hex", hex_tool_name)
            print(f"Hex rules: {message}")
            
        elif args.hash_rules:
            # Only hash-based rules
            hash_tool_name = "ja3-hash-rule" if tool_name is None else tool_name
            hash_rules = self.rule_generator.generate_hash_based_rules(sessions, hash_tool_name)
            success, message = self.rule_generator.export_rules_with_metadata(
                sessions, filename, "hash", hash_tool_name)
            print(message)
            
        elif args.hex_rules:
            # Only HEX-based rules
            hex_tool_name = "ja3-hex-rule" if tool_name is None else tool_name
            hex_rules = self.rule_generator.generate_hex_based_rules(sessions, hex_tool_name)
            success, message = self.rule_generator.export_rules_with_metadata(
                sessions, filename, "hex", hex_tool_name)
            print(message)
            
        else:
            # By default export hash-based rules
            hash_tool_name = "ja3-hash-rule" if tool_name is None else tool_name
            hash_rules = self.rule_generator.generate_hash_based_rules(sessions, hash_tool_name)
            success, message = self.rule_generator.export_rules_with_metadata(
                sessions, filename, "hash", hash_tool_name)
            print(message)


def main():
    """Main function to run the application."""
    analyzer = JA3SessionAnalyzer()
    analyzer.run()


if __name__ == "__main__":
    main()
