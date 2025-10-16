#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Простые тесты для JA3 Extractor."""

import sys
import os
import unittest

# Добавляем путь к src в PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ja3_extractor.core import SessionManager
from ja3_extractor.rules import SuricataRuleGenerator
from ja3_extractor.output import OutputFormatter
from ja3_extractor.utils import Colors


class TestSessionManager(unittest.TestCase):
    """Тесты для SessionManager."""
    
    def setUp(self):
        """Настройка тестов."""
        self.session_manager = SessionManager()
    
    def test_create_session(self):
        """Тест создания сессии."""
        session_key = "192.168.1.1:12345-10.0.0.1:443"
        self.session_manager.update_session(session_key,
            client_ip="192.168.1.1",
            server_ip="10.0.0.1",
            ja3="test_ja3"
        )
        
        session_data = self.session_manager.get_session(session_key)
        self.assertEqual(session_data['client_ip'], "192.168.1.1")
        self.assertEqual(session_data['server_ip'], "10.0.0.1")
        self.assertEqual(session_data['ja3'], "test_ja3")
    
    def test_get_all_sessions(self):
        """Тест получения всех сессий."""
        sessions = self.session_manager.get_all_sessions()
        self.assertIsInstance(sessions, dict)
    
    def test_session_length(self):
        """Тест подсчета сессий."""
        self.assertEqual(len(self.session_manager), 0)
        
        self.session_manager.update_session("test", ja3="test")
        self.assertEqual(len(self.session_manager), 1)


class TestSuricataRuleGenerator(unittest.TestCase):
    """Тесты для SuricataRuleGenerator."""
    
    def setUp(self):
        """Настройка тестов."""
        self.rule_generator = SuricataRuleGenerator()
    
    def test_convert_ja3_to_hex_patterns(self):
        """Тест конвертации JA3 в HEX паттерны."""
        ja3_string = "771,4865-4866,0-11,29-23,0-1"
        hex_patterns = self.rule_generator.convert_ja3_to_hex_patterns(ja3_string)
        self.assertIsInstance(hex_patterns, list)
        self.assertGreater(len(hex_patterns), 0)
    
    def test_convert_ja3s_to_hex_patterns(self):
        """Тест конвертации JA3S в HEX паттерны."""
        ja3s_string = "771,4865,43-51"
        hex_patterns = self.rule_generator.convert_ja3s_to_hex_patterns(ja3s_string)
        self.assertIsInstance(hex_patterns, list)
        self.assertGreater(len(hex_patterns), 0)
    
    def test_generate_hash_based_rules(self):
        """Тест генерации hash-based правил."""
        test_sessions = {
            "test": {
                'client_ip': '192.168.1.1',
                'server_ip': '10.0.0.1',
                'ja3': '771,4865-4866,0-11,29-23,0-1',
                'ja3_digest': 'test_hash_123',
                'ja3s': '771,4865,43-51',
                'ja3s_digest': 'test_hash_456'
            }
        }
        
        rules = self.rule_generator.generate_hash_based_rules(test_sessions)
        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 2)  # JA3 + JA3S правила


class TestOutputFormatter(unittest.TestCase):
    """Тесты для OutputFormatter."""
    
    def setUp(self):
        """Настройка тестов."""
        self.output_formatter = OutputFormatter()
    
    def test_format_json_output(self):
        """Тест форматирования JSON вывода."""
        test_sessions = {
            "test": {
                'client_ip': '192.168.1.1',
                'ja3': 'test_ja3'
            }
        }
        
        json_output = self.output_formatter.format_json_output(test_sessions)
        self.assertIsInstance(json_output, str)
        self.assertIn('"client_ip": "192.168.1.1"', json_output)
    
    def test_convert_to_hex_values(self):
        """Тест конвертации в HEX значения."""
        parts = ["771", "4865-4866", "0-11"]
        hex_values = self.output_formatter._convert_to_hex_values(parts)
        self.assertIsInstance(hex_values, str)
        self.assertIn("0303", hex_values)  # 771 в hex


class TestColors(unittest.TestCase):
    """Тесты для Colors."""
    
    def test_colors_attributes(self):
        """Тест наличия цветовых атрибутов."""
        self.assertTrue(hasattr(Colors, 'HEADER'))
        self.assertTrue(hasattr(Colors, 'BLUE'))
        self.assertTrue(hasattr(Colors, 'GREEN'))
        self.assertTrue(hasattr(Colors, 'RED'))
        self.assertTrue(hasattr(Colors, 'END'))
    
    def test_disable_colors(self):
        """Тест отключения цветов."""
        Colors.disable_colors()
        self.assertEqual(Colors.HEADER, '')
        self.assertEqual(Colors.BLUE, '')
        self.assertEqual(Colors.END, '')


if __name__ == '__main__':
    unittest.main()
