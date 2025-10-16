#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Автоматический запуск JA3 Extractor с проверкой зависимостей."""

import sys
import os
import subprocess
import importlib.util

def check_and_install_dependencies():
    """Проверяет и устанавливает необходимые зависимости."""
    required_packages = ['dpkt', 'packaging']
    missing_packages = []
    
    for package in required_packages:
        spec = importlib.util.find_spec(package)
        if spec is None:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Отсутствуют зависимости: {', '.join(missing_packages)}")
        print("Попытка установки...")
        
        try:
            # Пробуем установить с --user флагом
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '--user'
            ] + missing_packages)
            print("Зависимости установлены успешно!")
        except subprocess.CalledProcessError:
            print("Ошибка установки зависимостей.")
            print("Рекомендуется использовать виртуальное окружение:")
            print("  python3 -m venv venv")
            print("  source venv/bin/activate")
            print("  pip install -r requirements.txt")
            return False
    
    return True

def main():
    """Основная функция."""
    print("JA3 Extractor - Автоматический запуск")
    
    # Проверяем зависимости
    if not check_and_install_dependencies():
        sys.exit(1)
    
    # Добавляем путь к src в PYTHONPATH
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(script_dir, 'src')
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    
    try:
        # Импортируем и запускаем основной модуль
        from ja3_extractor import JA3SessionAnalyzer
        
        analyzer = JA3SessionAnalyzer()
        analyzer.run()
        
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        print("Убедитесь, что все файлы проекта на месте.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка выполнения: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
