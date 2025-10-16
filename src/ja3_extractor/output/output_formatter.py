#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Output formatter class for analysis results."""

import json
from ..utils.colors import Colors


class OutputFormatter:
    """Output formatter class for analysis results."""
    
    def __init__(self):
        """Initialize output formatter."""
        self.colors = Colors()
    
    def format_json_output(self, sessions):
        """Format output in JSON format."""
        return json.dumps(sessions, indent=4, sort_keys=True, ensure_ascii=False)
    
    def format_session_analysis(self, sessions):
        """Format detailed session analysis."""
        output = []
        output.append("\n" + Colors.CYAN + "=" * 60 + Colors.END)
        output.append(Colors.BOLD + Colors.HEADER + 
                     "                   TLS Sessions Analysis                    " + 
                     Colors.END)
        output.append(Colors.CYAN + "=" * 60 + Colors.END)
        
        session_count = 0
        # Sort sessions by first packet timestamp
        sorted_sessions = sorted(sessions.items(), 
                               key=lambda x: x[1]['first_timestamp'] or 0)
        
        for session_key, session_data in sorted_sessions:
            if session_data['ja3'] or session_data['ja3s']:
                session_count += 1
                output.append(self._format_single_session(session_count, session_data))
        
        return '\n'.join(output)
    
    def _format_single_session(self, session_count, session_data):
        """Format single session."""
        output = []
        output.append("\n" + Colors.BOLD + Colors.BLUE + 
                     "▶ TLS Session {}".format(session_count) + Colors.END)
        
        # Client Hello (JA3)
        if session_data['ja3']:
            output.append(self._format_client_hello(session_data))
        
        # Server Hello (JA3S)
        if session_data['ja3s']:
            output.append(self._format_server_hello(session_data))
        
        output.append("")
        return '\n'.join(output)
    
    def _format_client_hello(self, session_data):
        """Format Client Hello information."""
        output = []
        output.append("  " + Colors.GREEN + "• ClientHello (JA3)" + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Frame" + Colors.END + 
                     "               : " + Colors.WHITE + 
                     "{}".format(session_data['client_hello_frame']) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Direction" + Colors.END + 
                     "           : " + Colors.WHITE + "{} → {}".format(
                         f"{Colors.YELLOW}{session_data['client_ip']}{Colors.END}",
                         f"{Colors.ORANGE}{session_data['server_ip']}{Colors.END}") + Colors.END)
        
        # Parse JA3 components
        ja3_parts = session_data['ja3'].split(',')
        version = ja3_parts[0] if len(ja3_parts) > 0 else ""
        cipher_suites = ja3_parts[1] if len(ja3_parts) > 1 else ""
        extensions = ja3_parts[2] if len(ja3_parts) > 2 else ""
        supported_groups = ja3_parts[3] if len(ja3_parts) > 3 else ""
        ec_point_formats = ja3_parts[4] if len(ja3_parts) > 4 else ""
        
        output.append("    " + Colors.LIGHT_GRAY + "Version" + Colors.END + 
                     "             : " + Colors.WHITE + "{}".format(version) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Cipher Suites" + Colors.END + 
                     "       : " + Colors.WHITE + "{}".format(cipher_suites) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Extensions" + Colors.END + 
                     "          : " + Colors.WHITE + "{}".format(extensions) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Supported Groups" + Colors.END + 
                     "    : " + Colors.WHITE + "{}".format(supported_groups) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "EC Point Formats" + Colors.END + 
                     "    : " + Colors.WHITE + "{}".format(ec_point_formats) + Colors.END)
        
        # Hex Values
        hex_values = self._convert_to_hex_values(ja3_parts)
        output.append("    " + Colors.YELLOW + "Hex Values" + Colors.END + 
                     "          : " + Colors.WHITE + "{}".format(hex_values) + Colors.END)
        output.append("    " + Colors.RED + "JA3 Fullstring" + Colors.END + 
                     "      : " + Colors.WHITE + "{}".format(session_data['ja3']) + Colors.END)
        output.append("    " + Colors.RED + "JA3 MD5" + Colors.END + 
                     "             : " + Colors.CYAN + "{}".format(session_data['ja3_digest']) + Colors.END)
        
        return '\n'.join(output)
    
    def _format_server_hello(self, session_data):
        """Форматирует информацию о Server Hello."""
        output = []
        output.append("\n  " + Colors.GREEN + "• ServerHello (JA3S)" + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Frame" + Colors.END + 
                     "               : " + Colors.WHITE + 
                     "{}".format(session_data['server_hello_frame']) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Direction" + Colors.END + 
                     "           : " + Colors.WHITE + "{} → {}".format(
                         f"{Colors.ORANGE}{session_data['server_ip']}{Colors.END}",
                         f"{Colors.YELLOW}{session_data['client_ip']}{Colors.END}") + Colors.END)
        
        # Parse JA3S components
        ja3s_parts = session_data['ja3s'].split(',')
        version = ja3s_parts[0] if len(ja3s_parts) > 0 else ""
        selected_cipher = ja3s_parts[1] if len(ja3s_parts) > 1 else ""
        extensions = ja3s_parts[2] if len(ja3s_parts) > 2 else ""
        
        output.append("    " + Colors.LIGHT_GRAY + "Version" + Colors.END + 
                     "             : " + Colors.WHITE + "{}".format(version) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Selected Cipher" + Colors.END + 
                     "     : " + Colors.WHITE + "{}".format(selected_cipher) + Colors.END)
        output.append("    " + Colors.LIGHT_GRAY + "Extensions" + Colors.END + 
                     "          : " + Colors.WHITE + "{}".format(extensions) + Colors.END)
        
        # Hex Values
        hex_values = self._convert_to_hex_values(ja3s_parts)
        output.append("    " + Colors.YELLOW + "Hex Values" + Colors.END + 
                     "          : " + Colors.WHITE + "{}".format(hex_values) + Colors.END)
        output.append("    " + Colors.RED + "JA3s Fullstring" + Colors.END + 
                     "     : " + Colors.WHITE + "{}".format(session_data['ja3s']) + Colors.END)
        output.append("    " + Colors.RED + "JA3s MD5" + Colors.END + 
                     "            : " + Colors.CYAN + "{}".format(session_data['ja3s_digest']) + Colors.END)
        
        return '\n'.join(output)
    
    def _convert_to_hex_values(self, parts):
        """Конвертирует части JA3/JA3S в HEX значения."""
        hex_parts = []
        for i, part in enumerate(parts):
            if i == 0:  # Version
                hex_parts.append('{:04x}'.format(int(part)))
            else:  # Other parts
                if part:
                    hex_values = []
                    for val in part.split('-'):
                        if val:
                            hex_values.append('{:04x}'.format(int(val)))
                    hex_parts.append('-'.join(hex_values))
                else:
                    hex_parts.append('')
        return ','.join(hex_parts)
    
    def format_sessions_list(self, sessions_list):
        """Format sessions list for display."""
        output = []
        output.append("\n" + Colors.CYAN + "=" * 80 + Colors.END)
        output.append(Colors.BOLD + Colors.HEADER + 
                     "                         Sessions List                         " + 
                     Colors.END)
        output.append(Colors.CYAN + "=" * 80 + Colors.END)
        
        if not sessions_list:
            output.append(Colors.YELLOW + "No sessions found." + Colors.END)
            return '\n'.join(output)
        
        output.append(f"{Colors.LIGHT_GRAY}Total sessions: {Colors.BOLD}{Colors.GREEN}{len(sessions_list)}{Colors.END}\n")
        
        for i, session in enumerate(sessions_list, 1):
            # Session number with enhanced styling and colored session key
            colored_session_key = self._colorize_session_key(session['key'])
            output.append(f"{Colors.BOLD}{Colors.BLUE}#{i:3d}{Colors.END} {colored_session_key}")
            
            # Parse IP and port from session key for better coloring
            session_key = session['key']
            if '-' in session_key:
                parts = session_key.split('-')
                if len(parts) >= 2:
                    client_part = parts[0]  # 172.16.91.161:62079
                    server_part = parts[1]  # 46.19.66.166:443
                    
                    # Parse client IP:port
                    if ':' in client_part:
                        client_ip, client_port = client_part.rsplit(':', 1)
                        client_colored = f"{Colors.BLUE}{client_ip}{Colors.END}:{Colors.RED}{client_port}{Colors.END}"
                    else:
                        client_colored = f"{Colors.BLUE}{client_part}{Colors.END}"
                    
                    # Parse server IP:port
                    if ':' in server_part:
                        server_ip, server_port = server_part.rsplit(':', 1)
                        server_colored = f"{Colors.BLUE}{server_ip}{Colors.END}:{Colors.RED}{server_port}{Colors.END}"
                    else:
                        server_colored = f"{Colors.BLUE}{server_part}{Colors.END}"
                    
                    output.append(f"      {Colors.LIGHT_GRAY}Client:{Colors.END} {client_colored}")
                    output.append(f"      {Colors.LIGHT_GRAY}Server:{Colors.END} {server_colored}")
                else:
                    # Fallback to original formatting
                    output.append(f"      {Colors.LIGHT_GRAY}Client:{Colors.END} {Colors.CYAN}{session['client_ip']}:{session['client_port']}{Colors.END}")
                    output.append(f"      {Colors.LIGHT_GRAY}Server:{Colors.END} {Colors.CYAN}{session['server_ip']}:{session['server_port']}{Colors.END}")
            else:
                # Fallback to original formatting
                output.append(f"      {Colors.LIGHT_GRAY}Client:{Colors.END} {Colors.CYAN}{session['client_ip']}:{session['client_port']}{Colors.END}")
                output.append(f"      {Colors.LIGHT_GRAY}Server:{Colors.END} {Colors.CYAN}{session['server_ip']}:{session['server_port']}{Colors.END}")
            
            # JA3/JA3S status with colored checkmarks
            ja3_status = f"{Colors.GREEN}✓{Colors.END}" if session['has_ja3'] else f"{Colors.RED}✗{Colors.END}"
            ja3s_status = f"{Colors.GREEN}✓{Colors.END}" if session['has_ja3s'] else f"{Colors.RED}✗{Colors.END}"
            
            output.append(f"      {Colors.LIGHT_GRAY}JA3:{Colors.END} {ja3_status} {Colors.LIGHT_GRAY}JA3S:{Colors.END} {ja3s_status}")
            output.append("")
        
        output.append(Colors.CYAN + "-" * 80 + Colors.END)
        output.append(f"{Colors.LIGHT_GRAY}Use {Colors.BOLD}--filter-session NUMBER{Colors.END} {Colors.LIGHT_GRAY}to filter by specific session{Colors.END}")
        output.append("")
        
        return '\n'.join(output)
    
    def format_suricata_rules(self, rules, rule_type="hash"):
        """Форматирует Suricata правила."""
        output = []
        header = "Generated {} Suricata Rules".format(rule_type.title())
        output.append("\n" + Colors.CYAN + "=" * 60 + Colors.END)
        output.append(Colors.BOLD + Colors.HEADER + 
                     "              {}              ".format(header) + Colors.END)
        output.append(Colors.CYAN + "=" * 60 + Colors.END)
        
        session_counter = 0
        for i, rule in enumerate(rules):
            if i % 2 == 0:  # Every two rules is one session
                session_counter += 1
                output.append("\n" + Colors.BOLD + Colors.BLUE + 
                             "▶ Suricata Rules for Session {}".format(session_counter) + Colors.END)
            
            rule_type_name = "ClientHello (JA3)" if i % 2 == 0 else "ServerHello (JA3S)"
            output.append("  " + Colors.GREEN + "# {} Rule".format(rule_type_name) + Colors.END)
            output.append(rule)
            output.append("")
        
        output.append(Colors.CYAN + "-" * 60 + Colors.END)
        output.append("Generated {} {}-based Suricata rules for {} sessions".format(
            len(rules), rule_type, session_counter))
        output.append("")
        
        return '\n'.join(output)
    
    def _colorize_session_key(self, session_key):
        """Colorize session key with IP addresses in yellow and ports in red, both bold."""
        if '-' in session_key:
            parts = session_key.split('-')
            if len(parts) >= 2:
                client_part = parts[0]  # 172.16.91.161:62079
                server_part = parts[1]  # 46.19.66.166:443
                
                # Colorize client part
                if ':' in client_part:
                    client_ip, client_port = client_part.rsplit(':', 1)
                    client_colored = f"{Colors.BOLD}{Colors.YELLOW}{client_ip}{Colors.END}:{Colors.BOLD}{Colors.RED}{client_port}{Colors.END}"
                else:
                    client_colored = f"{Colors.BOLD}{Colors.YELLOW}{client_part}{Colors.END}"
                
                # Colorize server part
                if ':' in server_part:
                    server_ip, server_port = server_part.rsplit(':', 1)
                    server_colored = f"{Colors.BOLD}{Colors.ORANGE}{server_ip}{Colors.END}:{Colors.BOLD}{Colors.RED}{server_port}{Colors.END}"
                else:
                    server_colored = f"{Colors.BOLD}{Colors.ORANGE}{server_part}{Colors.END}"
                
                return f"{client_colored} → {server_colored}"
        
        # Fallback to original formatting
        return f"{Colors.BOLD}{Colors.WHITE}{session_key}{Colors.END}"
