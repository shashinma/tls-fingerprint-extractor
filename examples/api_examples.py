#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JA3 Session Extractor API Usage Examples

This file contains practical examples of how to use the JA3 Session Extractor API.
All examples are ready to run and demonstrate real-world usage scenarios.
"""

import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Any

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import JA3 Extractor components
from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser
from src.ja3_extractor.rules import SuricataRuleGenerator
from src.ja3_extractor.output import OutputFormatter


def example_1_basic_usage():
    """Example 1: Basic API usage - analyze PCAP file and display sessions."""
    
    print("=== Example 1: Basic Usage ===")
    
    # Initialize the main analyzer
    analyzer = JA3SessionAnalyzer()
    
    # Create argument parser
    parser = ArgumentParser()
    
    # Simulate command line arguments
    pcap_file = "../capture (2).pcap"  # Replace with your PCAP file
    
    try:
        # Validate and load PCAP file
        parser.validate_pcap_file(pcap_file)
        packets = parser.load_pcap_file(pcap_file)
        
        print(f"Loaded {len(packets)} packets from {pcap_file}")
        
        # Process packets to extract JA3/JA3S hashes
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        
        # Get only complete sessions (with both JA3 and JA3S)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        print(f"Found {len(sessions)} total sessions")
        print(f"Found {len(complete_sessions)} complete sessions")
        
        # Format and display results
        if complete_sessions:
            output = analyzer.output_formatter.format_session_analysis(complete_sessions)
            print("\nSession Analysis:")
            print(output)
        else:
            print("No complete sessions found")
        
        return complete_sessions
        
    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found")
        print("Please provide a valid PCAP file path")
        return {}
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        return {}


def example_2_rule_generation():
    """Example 2: Generate Suricata rules from sessions."""
    
    print("\n=== Example 2: Rule Generation ===")
    
    # Initialize components
    analyzer = JA3SessionAnalyzer()
    rule_generator = SuricataRuleGenerator()
    parser = ArgumentParser()
    
    pcap_file = "../capture (2).pcap"  # Replace with your PCAP file
    
    try:
        # Load and process PCAP
        packets = parser.load_pcap_file(pcap_file)
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        if not complete_sessions:
            print("No complete sessions found for rule generation")
            return
        
        # Generate hash-based rules
        hash_rules = rule_generator.generate_hash_based_rules(complete_sessions)
        
        # Generate HEX-based rules
        hex_rules = rule_generator.generate_hex_based_rules(complete_sessions)
        
        print(f"Generated {len(hash_rules)} hash-based rules")
        print(f"Generated {len(hex_rules)} HEX-based rules")
        
        # Display formatted rules
        if hash_rules:
            print("\nHash-based Rules:")
            formatted_rules = analyzer.output_formatter.format_suricata_rules(hash_rules)
            print(formatted_rules)
        
        # Export rules to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export hash rules
        hash_file = f"hash_rules_{timestamp}.rules"
        with open(hash_file, "w") as f:
            for rule in hash_rules:
                rule_content = rule if isinstance(rule, str) else rule['content']
                f.write(f"{rule_content}\n")
        
        # Export hex rules
        hex_file = f"hex_rules_{timestamp}.rules"
        with open(hex_file, "w") as f:
            for rule in hex_rules:
                rule_content = rule if isinstance(rule, str) else rule['content']
                f.write(f"{rule_content}\n")
        
        print(f"\nRules exported to:")
        print(f"- {hash_file}")
        print(f"- {hex_file}")
        
        return hash_rules, hex_rules
        
    except Exception as e:
        print(f"Error generating rules: {e}")
        return [], []


def example_3_json_output():
    """Example 3: Export analysis results to JSON format."""
    
    print("\n=== Example 3: JSON Output ===")
    
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    pcap_file = "../capture (2).pcap"  # Replace with your PCAP file
    
    try:
        # Load and process PCAP
        packets = parser.load_pcap_file(pcap_file)
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        # Convert sessions to JSON-serializable format
        json_sessions = []
        for session_key, session_data in complete_sessions.items():
            json_session = {
                'session_key': session_key,
                'client_ip': session_data['client_ip'],
                'client_port': session_data['client_port'],
                'server_ip': session_data['server_ip'],
                'server_port': session_data['server_port'],
                'has_ja3': session_data.get('has_ja3', False),
                'has_ja3s': session_data.get('has_ja3s', False),
                'ja3': session_data.get('ja3', ''),
                'ja3s': session_data.get('ja3s', ''),
                'client_hello_time': session_data.get('client_hello_time', ''),
                'server_hello_time': session_data.get('server_hello_time', '')
            }
            json_sessions.append(json_session)
        
        # Create complete JSON structure
        json_output = {
            'analysis_timestamp': datetime.now().isoformat(),
            'pcap_file': pcap_file,
            'total_sessions': len(sessions),
            'complete_sessions': len(complete_sessions),
            'sessions': json_sessions
        }
        
        # Export to JSON file
        json_file = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, "w") as f:
            json.dump(json_output, f, indent=2, default=str)
        
        print(f"Analysis exported to: {json_file}")
        print(f"Total sessions: {json_output['total_sessions']}")
        print(f"Complete sessions: {json_output['complete_sessions']}")
        
        return json_output
        
    except Exception as e:
        print(f"Error creating JSON output: {e}")
        return {}


def example_4_session_filtering():
    """Example 4: Filter sessions by specific criteria."""
    
    print("\n=== Example 4: Session Filtering ===")
    
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    pcap_file = "../capture (2).pcap"  # Replace with your PCAP file
    
    try:
        # Load and process PCAP
        packets = parser.load_pcap_file(pcap_file)
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        # Filter sessions by HTTPS port (443)
        https_sessions = {}
        for key, session in complete_sessions.items():
            if session['server_port'] == 443:
                https_sessions[key] = session
        
        # Filter sessions by specific IP range (example: 192.168.x.x)
        internal_sessions = {}
        for key, session in complete_sessions.items():
            client_ip = session['client_ip']
            server_ip = session['server_ip']
            if (client_ip.startswith('192.168.') or 
                server_ip.startswith('192.168.')):
                internal_sessions[key] = session
        
        # Group sessions by JA3 hash
        ja3_groups = {}
        for key, session in complete_sessions.items():
            if session.get('has_ja3', False):
                ja3_hash = session.get('ja3', '')
                if ja3_hash not in ja3_groups:
                    ja3_groups[ja3_hash] = []
                ja3_groups[ja3_hash].append(session)
        
        print(f"Total complete sessions: {len(complete_sessions)}")
        print(f"HTTPS sessions (port 443): {len(https_sessions)}")
        print(f"Internal network sessions: {len(internal_sessions)}")
        print(f"Unique JA3 hashes: {len(ja3_groups)}")
        
        # Find most common JA3 hash
        if ja3_groups:
            most_common = max(ja3_groups.items(), key=lambda x: len(x[1]))
            print(f"Most common JA3 hash: {most_common[0][:16]}... ({len(most_common[1])} sessions)")
        
        return {
            'total': complete_sessions,
            'https': https_sessions,
            'internal': internal_sessions,
            'ja3_groups': ja3_groups
        }
        
    except Exception as e:
        print(f"Error filtering sessions: {e}")
        return {}


def main():
    """Main function to run all examples."""
    
    print("JA3 Session Extractor API Examples")
    print("=" * 50)
    
    # Check if PCAP file exists
    pcap_file = "../capture (2).pcap"
    if not os.path.exists(pcap_file):
        print(f"Warning: PCAP file '{pcap_file}' not found.")
        print("Please place a PCAP file named 'capture (2).pcap' in the project root directory")
        print("or modify the pcap_file variable in the examples.")
        print("\nYou can use any of the existing PCAP files:")
        
        # List available PCAP files
        pcap_files = [f for f in os.listdir('..') if f.endswith(('.pcap', '.pcapng'))]
        if pcap_files:
            for f in pcap_files:
                print(f"  - {f}")
        else:
            print("  No PCAP files found in project root directory")
        
        return
    
    # Run examples
    try:
        # Example 1: Basic usage
        sessions = example_1_basic_usage()
        
        if sessions:
            # Example 2: Rule generation
            hash_rules, hex_rules = example_2_rule_generation()
            
            # Example 3: JSON output
            json_output = example_3_json_output()
            
            # Example 4: Session filtering
            filtered_sessions = example_4_session_filtering()
            
            print("\n" + "=" * 50)
            print("All examples completed successfully!")
            print(f"Generated files:")
            print(f"- hash_rules_*.rules")
            print(f"- hex_rules_*.rules")
            print(f"- analysis_*.json")
        else:
            print("No sessions found.")
            
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error running examples: {e}")


if __name__ == "__main__":
    main()
