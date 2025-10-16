#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Утилитарные функции для работы с JA3 и JA3S."""

import socket
import struct
from collections import defaultdict


# GREASE таблица для фильтрации значений
GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}

SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Конвертирует IP адрес из бинарного формата в текстовый."""
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Распаковывает данные из буфера определенной длины."""
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]
    return data, size + byte_len


def ntoh(buf):
    """Конвертирует в сетевой порядок байтов."""
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Конвертирует упакованный массив элементов в JA3 сегмент."""
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def create_session_key(src_ip, dst_ip, src_port, dst_port):
    """Создает ключ сессии на основе IP адресов и портов."""
    # Сортируем IP адреса и порты для создания уникального ключа сессии
    if src_ip < dst_ip:
        return "{}:{}-{}:{}".format(src_ip, src_port, dst_ip, dst_port)
    elif src_ip > dst_ip:
        return "{}:{}-{}:{}".format(dst_ip, dst_port, src_ip, src_port)
    else:
        # Если IP одинаковые, сортируем по портам
        if src_port < dst_port:
            return "{}:{}-{}:{}".format(src_ip, src_port, dst_ip, dst_port)
        else:
            return "{}:{}-{}:{}".format(dst_ip, dst_port, src_ip, src_port)


def create_default_session():
    """Создает словарь с дефолтными значениями для сессии."""
    return {
        'client_ip': '',
        'server_ip': '',
        'client_port': 0,
        'server_port': 0,
        'ja3': '',
        'ja3_digest': '',
        'ja3s': '',
        'ja3s_digest': '',
        'client_hello_frame': 0,
        'server_hello_frame': 0,
        'first_timestamp': None,
        'last_timestamp': None
    }
