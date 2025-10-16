#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Класс для извлечения JA3 и JA3S хэшей из PCAP файлов."""

import dpkt
from packaging.version import Version
from hashlib import md5

from ..utils.utils import (
    convert_ip, parse_variable_array, convert_to_ja3_segment,
    create_session_key, SSL_PORT, TLS_HANDSHAKE
)
from .session_manager import SessionManager


class JA3Extractor:
    """Класс для извлечения JA3 и JA3S хэшей из PCAP файлов."""
    
    def __init__(self):
        """Инициализирует экстрактор JA3."""
        self.session_manager = SessionManager()
    
    def process_client_extensions(self, client_handshake):
        """Обрабатывает расширения клиента и конвертирует в JA3 сегмент."""
        if not hasattr(client_handshake, "extensions"):
            return ["", "", ""]

        exts = list()
        elliptic_curve = ""
        elliptic_curve_point_format = ""
        for ext_val, ext_data in client_handshake.extensions:
            if not hasattr(self, '_grease_table'):
                from ..utils.utils import GREASE_TABLE
                self._grease_table = GREASE_TABLE
            
            if not self._grease_table.get(ext_val):
                exts.append(ext_val)
            if ext_val == 0x0a:
                a, b = parse_variable_array(ext_data, 2)
                elliptic_curve = convert_to_ja3_segment(a, 2)
            elif ext_val == 0x0b:
                a, b = parse_variable_array(ext_data, 1)
                elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
            else:
                continue

        results = list()
        results.append("-".join([str(x) for x in exts]))
        results.append(elliptic_curve)
        results.append(elliptic_curve_point_format)
        return results

    def process_server_extensions(self, server_handshake):
        """Обрабатывает расширения сервера и конвертирует в JA3S сегмент."""
        if not hasattr(server_handshake, "extensions"):
            return [""]

        exts = list()
        for ext_val, ext_data in server_handshake.extensions:
            exts.append(ext_val)

        results = list()
        results.append("-".join([str(x) for x in exts]))
        return results

    def process_client_hello(self, handshake, ip, tcp, frame_number, timestamp):
        """Обрабатывает Client Hello пакет."""
        client_handshake = handshake.data
        buf, ptr = parse_variable_array(client_handshake.data, 1)
        buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
        ja3 = [str(client_handshake.version)]
        ja3.append(convert_to_ja3_segment(buf, 2))
        ja3 += self.process_client_extensions(client_handshake)
        ja3 = ",".join(ja3)

        session_key = create_session_key(
            convert_ip(ip.src), convert_ip(ip.dst), 
            tcp.sport, tcp.dport
        )
        
        self.session_manager.update_session(session_key,
            client_ip=convert_ip(ip.src),
            server_ip=convert_ip(ip.dst),
            client_port=tcp.sport,
            server_port=tcp.dport,
            ja3=ja3,
            ja3_digest=md5(ja3.encode()).hexdigest(),
            client_hello_frame=frame_number
        )
        
        session_data = self.session_manager.get_session(session_key)
        if session_data['first_timestamp'] is None:
            self.session_manager.update_session(session_key, first_timestamp=timestamp)
        self.session_manager.update_session(session_key, last_timestamp=timestamp)

    def process_server_hello(self, handshake, ip, tcp, frame_number):
        """Обрабатывает Server Hello пакет."""
        server_handshake = handshake.data
        ja3s = [str(server_handshake.version)]

        # Cipher Suites (16 bit values)
        if Version(dpkt.__version__) <= Version('1.9.1'):
            ja3s.append(str(server_handshake.cipher_suite))
        else:
            ja3s.append(str(server_handshake.ciphersuite.code))
        ja3s += self.process_server_extensions(server_handshake)
        ja3s = ",".join(ja3s)

        session_key = create_session_key(
            convert_ip(ip.src), convert_ip(ip.dst), 
            tcp.sport, tcp.dport
        )
        
        self.session_manager.update_session(session_key,
            ja3s=ja3s,
            ja3s_digest=md5(ja3s.encode()).hexdigest(),
            server_hello_frame=frame_number
        )

    def process_pcap(self, packets, ssl_port_only=False):
        """Обрабатывает пакеты из PCAP файла и извлекает JA3 и JA3S."""
        frame_number = 0
        for timestamp, buf in packets:
            frame_number += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            if not isinstance(eth.data.data, dpkt.tcp.TCP):
                continue

            ip = eth.data
            tcp = ip.data

            if ssl_port_only and not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT):
                continue
            if len(tcp.data) <= 0:
                continue

            tls_handshake = bytearray(tcp.data)
            if tls_handshake[0] != TLS_HANDSHAKE:
                continue

            records = list()
            try:
                records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
            except dpkt.ssl.SSL3Exception:
                continue
            except dpkt.dpkt.NeedData:
                continue

            if len(records) <= 0:
                continue

            for record in records:
                if record.type != TLS_HANDSHAKE:
                    continue
                if len(record.data) == 0:
                    continue

                handshake_type = bytearray(record.data)[0]
                
                # Обработка Client Hello (тип 1)
                if handshake_type == 1:
                    try:
                        handshake = dpkt.ssl.TLSHandshake(record.data)
                    except dpkt.dpkt.NeedData:
                        continue
                    if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                        continue

                    self.process_client_hello(handshake, ip, tcp, frame_number, timestamp)

                # Обработка Server Hello (тип 2)
                elif handshake_type == 2:
                    try:
                        handshake = dpkt.ssl.TLSHandshake(record.data)
                    except dpkt.dpkt.NeedData:
                        continue
                    if not isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                        continue

                    self.process_server_hello(handshake, ip, tcp, frame_number)

        return self.session_manager.get_all_sessions()
