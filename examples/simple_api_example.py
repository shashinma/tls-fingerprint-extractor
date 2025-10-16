#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple JA3 Session Extractor API Example

This is a minimal example showing how to use the JA3 Session Extractor API.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import JA3 Extractor
from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser


def simple_example():
    """Simple example of using the JA3 Session Extractor API."""
    
    print("JA3 Session Extractor - Simple API Example")
    print("-" * 50)
    
    # Initialize the analyzer
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    # Specify your PCAP file here
    pcap_file = "../capture (2).pcap"  # Change this to your PCAP file
    
    try:
        # Step 1: Load PCAP file
        print(f"Loading PCAP file: {pcap_file}")
        packets = parser.load_pcap_file(pcap_file)
        print(f"✓ Loaded {len(packets)} packets")
        
        # Step 2: Process packets to extract JA3/JA3S
        print("Processing packets...")
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        print(f"✓ Found {len(sessions)} total sessions")
        
        # Step 3: Get complete sessions (with both JA3 and JA3S)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        print(f"✓ Found {len(complete_sessions)} complete sessions")
        
        # Step 4: Display results
        if complete_sessions:
            print("\nSession Analysis:")
            print("=" * 50)
            
            for i, (session_key, session_data) in enumerate(complete_sessions.items(), 1):
                print(f"Session {i}: {session_key}")
                print(f"  Client: {session_data['client_ip']}:{session_data['client_port']}")
                print(f"  Server: {session_data['server_ip']}:{session_data['server_port']}")
                print(f"  JA3: {session_data.get('ja3', 'N/A')[:32]}..." if session_data.get('has_ja3') else "  JA3: Not found")
                print(f"  JA3S: {session_data.get('ja3s', 'N/A')[:32]}..." if session_data.get('has_ja3s') else "  JA3S: Not found")
                print()
        else:
            print("No complete sessions found")
        
        # Step 5: Generate Suricata rules (optional)
        if complete_sessions:
            print("Generating Suricata rules...")
            hash_rules = analyzer.rule_generator.generate_hash_based_rules(complete_sessions)
            print(f"✓ Generated {len(hash_rules)} hash-based rules")
            
            # Display first rule as example
            if hash_rules:
                print("\nSample Suricata rule:")
                rule_content = hash_rules[0] if isinstance(hash_rules[0], str) else hash_rules[0]['content']
                print(rule_content)
        
        print("\n" + "=" * 50)
        print("Analysis completed successfully!")
        
    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found")
        print("Please check the file path and try again")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    simple_example()
