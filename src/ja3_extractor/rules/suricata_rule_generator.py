#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Suricata rule generator class based on JA3 and JA3S hashes."""

import re
from ..utils.colors import Colors


class SuricataRuleGenerator:
    """Suricata rule generator class."""
    
    def __init__(self):
        """Initialize rule generator."""
        self.sid_counter = 2000000
        self.hex_sid_counter = 3000000
    
    def _extract_rule_content(self, rule_text):
        """Extract rule content for duplicate comparison."""
        # Extract all content blocks from rule
        content_matches = re.findall(r'content:"([^"]+)"', rule_text)
        if content_matches:
            # Combine all content blocks to create unique key
            return '|'.join(content_matches)
        return None
    
    def _remove_duplicate_rules(self, rules):
        """Remove duplicate rules based on their content."""
        seen_contents = set()
        unique_rules = []
        
        for rule in rules:
            content = self._extract_rule_content(rule)
            if content and content not in seen_contents:
                seen_contents.add(content)
                unique_rules.append(rule)
            elif not content:  # Если не удалось извлечь content, оставляем правило
                unique_rules.append(rule)
        
        return unique_rules
    
    def convert_ja3_to_hex_patterns(self, ja3_string):
        """Конвертирует JA3 строку в HEX паттерны для Suricata правил."""
        parts = ja3_string.split(',')
        hex_patterns = []
        
        for i, part in enumerate(parts):
            if i == 0:  # Version - пропускаем, так как в примере его нет
                continue
            elif i == 1:  # Cipher Suites - объединяем в один блок
                if part:
                    hex_values = []
                    for val in part.split('-'):
                        if val:
                            hex_val = '{:04x}'.format(int(val))
                            hex_values.append('{} {}'.format(hex_val[:2], hex_val[2:]))
                    if hex_values:
                        hex_patterns.append('|{}|'.format(' '.join(hex_values)))
            elif i == 2:  # Extensions - каждое отдельно
                if part:
                    for val in part.split('-'):
                        if val:
                            hex_val = '{:04x}'.format(int(val))
                            hex_patterns.append('|{} {}|'.format(hex_val[:2], hex_val[2:]))
            elif i == 3:  # Supported Groups - объединяем в один блок
                if part:
                    hex_values = []
                    for val in part.split('-'):
                        if val:
                            hex_val = '{:04x}'.format(int(val))
                            hex_values.append('{} {}'.format(hex_val[:2], hex_val[2:]))
                    if hex_values:
                        hex_patterns.append('|{}|'.format(' '.join(hex_values)))
            elif i == 4:  # EC Point Formats - каждое значение отдельно, но без ведущих нулей
                if part:
                    hex_values = []
                    for val in part.split('-'):
                        if val:
                            # Для EC Point Formats используем 2-байтовый формат без ведущих нулей
                            hex_val = '{:02x}'.format(int(val))
                            hex_values.append(hex_val)
                    if hex_values:
                        hex_patterns.append('|{}|'.format(' '.join(hex_values)))
        
        return hex_patterns

    def convert_ja3s_to_hex_patterns(self, ja3s_string):
        """Конвертирует JA3S строку в HEX паттерны для Suricata правил."""
        parts = ja3s_string.split(',')
        hex_patterns = []
        
        for i, part in enumerate(parts):
            if i == 0:  # Version - пропускаем, так как в примере его нет
                continue
            elif i == 1:  # Selected Cipher
                cipher_hex = '{:04x}'.format(int(part))
                hex_patterns.append('|{} {}|'.format(cipher_hex[:2], cipher_hex[2:]))
            else:  # Extensions - каждое отдельно
                if part:
                    for val in part.split('-'):
                        if val:
                            hex_val = '{:04x}'.format(int(val))
                            hex_patterns.append('|{} {}|'.format(hex_val[:2], hex_val[2:]))
        
        return hex_patterns

    def highlight_suricata_syntax(self, rule_text):
        """Подсвечивает синтаксис Suricata правила."""
        # Ключевые слова Suricata
        keywords = ['alert', 'tls', 'any', 'msg', 'content', 'flow', 'flowbits', 
                   'classtype', 'priority', 'sid', 'rev']
        
        # Операторы
        operators = ['->', ';', ':', '=', ',', '(', ')']
        
        # Сначала обрабатываем строки в кавычках
        highlighted_text = rule_text
        
        # Находим все строки в кавычках и подсвечиваем их
        string_pattern = r'"([^"]*)"'
        def highlight_string(match):
            return Colors.SURICATA_STRING + match.group(0) + Colors.END
        
        highlighted_text = re.sub(string_pattern, highlight_string, highlighted_text)
        
        # Разбиваем на части, исключая уже подсвеченные строки
        parts = re.split(r'(\s+|->|;|:|=|,|\(|\))', highlighted_text)
        
        highlighted_parts = []
        
        for part in parts:
            if part.strip() == '':
                highlighted_parts.append(part)
            elif part in keywords:
                highlighted_parts.append(Colors.SURICATA_KEYWORD + part + Colors.END)
            elif part in operators:
                highlighted_parts.append(Colors.SURICATA_OPERATOR + part + Colors.END)
            elif part.isdigit():
                highlighted_parts.append(Colors.SURICATA_NUMBER + part + Colors.END)
            elif part.startswith(Colors.SURICATA_STRING):  # Уже подсвеченная строка
                highlighted_parts.append(part)
            else:
                highlighted_parts.append(Colors.WHITE + part + Colors.END)
        
        return ''.join(highlighted_parts)

    def generate_hash_based_rules(self, sessions, tool_name="JA3 Extractor"):
        """Generate hash-based Suricata rules."""
        rules = []
        session_counter = 0
        
        for session_key, session_data in sessions.items():
            if session_data['ja3'] and session_data['ja3s']:
                session_counter += 1
                
                # Правило для JA3 (ClientHello)
                ja3_rule = ('alert tls any any -> any any '
                           '(msg:"JA3 Client Fingerprint Match - {}"; '
                           'ja3.hash; content:"{}"; flow:established; '
                           'flowbits:set,ja3_client_match; flowbits:noalert; '
                           'classtype:trojan-activity; priority:1; sid:{}; rev:1;)').format(
                    tool_name, session_data['ja3_digest'], self.sid_counter)
                rules.append(ja3_rule)
                self.sid_counter += 1
                
                # Правило для JA3S (ServerHello)
                ja3s_rule = ('alert tls any any -> any any '
                            '(msg:"JA3/JA3s Pair Match - {}"; '
                            'flowbits:isset,ja3_client_match; ja3s.hash; content:"{}"; '
                            'flow:established; flowbits:unset,ja3_client_match; '
                            'classtype:trojan-activity; priority:1; sid:{}; rev:1;)').format(
                    tool_name, session_data['ja3s_digest'], self.sid_counter)
                rules.append(ja3s_rule)
                self.sid_counter += 1
        
        # Remove duplicate rules
        unique_rules = self._remove_duplicate_rules(rules)
        return unique_rules

    def generate_hex_based_rules(self, sessions, tool_name="JA3 Extractor"):
        """Generate HEX-based Suricata rules."""
        rules = []
        session_counter = 0
        
        for session_key, session_data in sessions.items():
            if session_data['ja3'] and session_data['ja3s']:
                session_counter += 1
                
                # Конвертируем JA3 в HEX паттерны
                ja3_hex_patterns = self.convert_ja3_to_hex_patterns(session_data['ja3'])
                
                # Создаем HEX-based правило для JA3
                ja3_hex_rule = 'alert tls any any -> any any (msg:"JA3 Client Fingerprint Match - {}"'.format(tool_name)
                for pattern in ja3_hex_patterns:
                    ja3_hex_rule += '; content:"{}"'.format(pattern)
                ja3_hex_rule += '; flowbits:set,ja3_client_match; flowbits:noalert; sid:{}; rev:2;)'.format(
                    self.hex_sid_counter)
                
                rules.append(ja3_hex_rule)
                self.hex_sid_counter += 1
                
                # Конвертируем JA3S в HEX паттерны
                ja3s_hex_patterns = self.convert_ja3s_to_hex_patterns(session_data['ja3s'])
                
                # Создаем HEX-based правило для JA3S
                ja3s_hex_rule = ('alert tls any any -> any any '
                                 '(msg:"JA3/JA3s Pair Match - {}"; '
                                 'flowbits:isset,ja3_client_match; flow:established').format(tool_name)
                for pattern in ja3s_hex_patterns:
                    ja3s_hex_rule += '; content:"{}"'.format(pattern)
                ja3s_hex_rule += '; flowbits:unset,ja3_client_match; sid:{}; rev:2;)'.format(
                    self.hex_sid_counter)
                
                rules.append(ja3s_hex_rule)
                self.hex_sid_counter += 1
        
        # Remove duplicate rules
        unique_rules = self._remove_duplicate_rules(rules)
        return unique_rules

    def export_rules_to_file(self, rules, filename, rule_type="hash"):
        """Export rules to file."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Suricata Rules - {rule_type.upper()}-based\n")
                f.write(f"# Generated by JA3 Extractor\n")
                f.write(f"# Total rules: {len(rules)}\n\n")
                
                for i, rule in enumerate(rules, 1):
                    f.write(f"# Rule {i}\n")
                    f.write(f"{rule}\n\n")
            
            return True, f"Rules successfully exported to {filename}"
        except Exception as e:
            return False, f"Export error: {str(e)}"
    
    def export_rules_with_metadata(self, sessions, filename, rule_type="hash", tool_name="JA3 Extractor"):
        """Export rules without session metadata."""
        try:
            from datetime import datetime
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Suricata Rules - {rule_type.upper()}-based\n")
                f.write(f"# Tool: {tool_name}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if rule_type == "hash":
                    rules = self.generate_hash_based_rules(sessions, tool_name)
                else:
                    rules = self.generate_hex_based_rules(sessions, tool_name)
                
                for rule in rules:
                    f.write(f"{rule}\n")
            
            return True, f"Rules exported to {filename}"
        except Exception as e:
            return False, f"Export error: {str(e)}"
