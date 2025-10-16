#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Класс для управления TLS сессиями."""

from collections import defaultdict
from ..utils.utils import create_default_session


class SessionManager:
    """Класс для управления TLS сессиями."""
    
    def __init__(self):
        """Инициализирует менеджер сессий."""
        self.sessions = defaultdict(create_default_session)
    
    def get_session(self, session_key):
        """Получает данные сессии по ключу."""
        return self.sessions[session_key]
    
    def update_session(self, session_key, **kwargs):
        """Обновляет данные сессии."""
        for key, value in kwargs.items():
            if key in self.sessions[session_key]:
                self.sessions[session_key][key] = value
    
    def get_all_sessions(self):
        """Возвращает все сессии."""
        return dict(self.sessions)
    
    def get_complete_sessions(self):
        """Возвращает только полные сессии (с JA3 и JA3S)."""
        return {k: v for k, v in self.sessions.items() 
                if v['ja3'] and v['ja3s']}
    
    def get_sessions_sorted_by_time(self):
        """Возвращает сессии, отсортированные по времени первого пакета."""
        return sorted(self.sessions.items(), 
                     key=lambda x: x[1]['first_timestamp'] or 0)
    
    def get_session_by_key(self, session_key):
        """Возвращает конкретную сессию по ключу."""
        if session_key in self.sessions:
            return {session_key: self.sessions[session_key]}
        return {}
    
    def get_sessions_list(self):
        """Возвращает список всех полных сессий с их ключами и основной информацией."""
        sessions_list = []
        for key, data in self.sessions.items():
            # Показываем только полные сессии
            if data['ja3'] and data['ja3s']:
                sessions_list.append({
                    'key': key,
                    'client_ip': data['client_ip'],
                    'server_ip': data['server_ip'],
                    'client_port': data['client_port'],
                    'server_port': data['server_port'],
                    'has_ja3': bool(data['ja3']),
                    'has_ja3s': bool(data['ja3s']),
                    'is_complete': True,  # Всегда True, так как фильтруем только полные
                    'first_timestamp': data['first_timestamp']
                })
        return sorted(sessions_list, key=lambda x: x['first_timestamp'] or 0)
    
    def filter_sessions_by_pattern(self, pattern):
        """Фильтрует сессии по паттерну в ключе сессии."""
        filtered = {}
        for key, data in self.sessions.items():
            if pattern.lower() in key.lower():
                filtered[key] = data
        return filtered
    
    def clear(self):
        """Очищает все сессии."""
        self.sessions.clear()
    
    def __len__(self):
        """Возвращает количество сессий."""
        return len(self.sessions)
    
    def __iter__(self):
        """Итератор по сессиям."""
        return iter(self.sessions.items())
