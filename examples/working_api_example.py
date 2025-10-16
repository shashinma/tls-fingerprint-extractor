#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Working JA3 Session Extractor API Example

This example uses the actual PCAP files in the project directory.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import JA3 Extractor
from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser


def working_example():
    """Working example using actual PCAP files."""
    
    print("JA3 Session Extractor - Working API Example")
    print("=" * 60)
    
    # Initialize the analyzer
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    # Use the actual PCAP file from the project root
    pcap_file = "../capture (2).pcap"
    
    try:
        # Step 1: Load PCAP file
        print(f"📁 Loading PCAP file: {pcap_file}")
        packets = parser.load_pcap_file(pcap_file)
        print(f"✅ Loaded {len(packets)} packets")
        
        # Step 2: Process packets to extract JA3/JA3S
        print("🔍 Processing packets for JA3/JA3S extraction...")
        sessions = analyzer.ja3_extractor.process_pcap(packets)
        print(f"✅ Found {len(sessions)} total sessions")
        
        # Step 3: Get complete sessions (with both JA3 and JA3S)
        complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
        print(f"✅ Found {len(complete_sessions)} complete sessions")
        
        # Step 4: Display detailed results
        if complete_sessions:
            print(f"\n📊 Detailed Session Analysis:")
            print("=" * 60)
            
            for i, (session_key, session_data) in enumerate(complete_sessions.items(), 1):
                print(f"\n🔗 Session {i}: {session_key}")
                print(f"   📍 Client: {session_data['client_ip']}:{session_data['client_port']}")
                print(f"   📍 Server: {session_data['server_ip']}:{session_data['server_port']}")
                
                if session_data.get('has_ja3', False):
                    print(f"   🔑 JA3: {session_data.get('ja3', 'N/A')}")
                else:
                    print(f"   🔑 JA3: Not found")
                
                if session_data.get('has_ja3s', False):
                    print(f"   🔑 JA3S: {session_data.get('ja3s', 'N/A')}")
                else:
                    print(f"   🔑 JA3S: Not found")
                
                # Show timestamps if available
                if 'client_hello_time' in session_data:
                    print(f"   ⏰ Client Hello: {session_data['client_hello_time']}")
                if 'server_hello_time' in session_data:
                    print(f"   ⏰ Server Hello: {session_data['server_hello_time']}")
        else:
            print("❌ No complete sessions found")
            print("💡 This might mean:")
            print("   - No TLS traffic in the file")
            print("   - Incomplete TLS handshakes")
            print("   - Traffic on non-standard ports")
        
        # Step 5: Generate Suricata rules
        if complete_sessions:
            print(f"\n🛡️ Generating Suricata Rules:")
            print("=" * 60)
            
            # Generate hash-based rules
            hash_rules = analyzer.rule_generator.generate_hash_based_rules(complete_sessions)
            print(f"✅ Generated {len(hash_rules)} hash-based rules")
            
            # Generate HEX-based rules
            hex_rules = analyzer.rule_generator.generate_hex_based_rules(complete_sessions)
            print(f"✅ Generated {len(hex_rules)} HEX-based rules")
            
            # Display sample rules
            if hash_rules:
                print(f"\n📝 Sample Hash-based Rule:")
                print("-" * 40)
                print(hash_rules[0] if isinstance(hash_rules[0], str) else hash_rules[0]['content'])
            
            if hex_rules:
                print(f"\n📝 Sample HEX-based Rule:")
                print("-" * 40)
                print(hex_rules[0] if isinstance(hex_rules[0], str) else hex_rules[0]['content'])
            
            # Export rules to files
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Export hash rules
            hash_file = f"hash_rules_{timestamp}.rules"
            with open(hash_file, "w") as f:
                f.write(f"# JA3 Hash-based Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Source: {pcap_file}\n")
                f.write(f"# Sessions: {len(complete_sessions)}\n\n")
                for rule in hash_rules:
                    rule_content = rule if isinstance(rule, str) else rule['content']
                    f.write(f"{rule_content}\n")
            
            # Export hex rules
            hex_file = f"hex_rules_{timestamp}.rules"
            with open(hex_file, "w") as f:
                f.write(f"# JA3 HEX-based Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Source: {pcap_file}\n")
                f.write(f"# Sessions: {len(complete_sessions)}\n\n")
                for rule in hex_rules:
                    rule_content = rule if isinstance(rule, str) else rule['content']
                    f.write(f"{rule_content}\n")
            
            print(f"\n💾 Rules exported to:")
            print(f"   📄 {hash_file}")
            print(f"   📄 {hex_file}")
        
        # Step 6: Summary
        print(f"\n📈 Summary:")
        print("=" * 60)
        print(f"📁 PCAP File: {pcap_file}")
        print(f"📦 Total Packets: {len(packets)}")
        print(f"🔗 Total Sessions: {len(sessions)}")
        print(f"✅ Complete Sessions: {len(complete_sessions)}")
        if complete_sessions:
            print(f"🛡️ Hash Rules: {len(hash_rules) if 'hash_rules' in locals() else 0}")
            print(f"🛡️ HEX Rules: {len(hex_rules) if 'hex_rules' in locals() else 0}")
        
        print(f"\n🎉 Analysis completed successfully!")
        
    except FileNotFoundError:
        print(f"❌ Error: PCAP file '{pcap_file}' not found")
        print("💡 Available PCAP files:")
        pcap_files = [f for f in os.listdir('..') if f.endswith(('.pcap', '.pcapng'))]
        for f in pcap_files:
            print(f"   📄 {f}")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


def test_with_different_files():
    """Test with different PCAP files in the project."""
    
    print("\n" + "=" * 60)
    print("Testing with different PCAP files")
    print("=" * 60)
    
    # Available PCAP files (from project root)
    pcap_files = [
        "../capture (2).pcap",
        "../lig-win-vestadon.ru-all-websocket.pcapng",
        "../lig-win-vestadon.ru-all.pcapng"
    ]
    
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    for pcap_file in pcap_files:
        if os.path.exists(pcap_file):
            print(f"\n🔍 Testing: {pcap_file}")
            try:
                packets = parser.load_pcap_file(pcap_file)
                sessions = analyzer.ja3_extractor.process_pcap(packets)
                complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
                
                print(f"   📦 Packets: {len(packets)}")
                print(f"   🔗 Sessions: {len(sessions)}")
                print(f"   ✅ Complete: {len(complete_sessions)}")
                
                if complete_sessions:
                    # Show first session as example
                    first_session = list(complete_sessions.values())[0]
                    print(f"   🔑 Sample JA3: {first_session.get('ja3', 'N/A')[:16]}...")
                
            except Exception as e:
                print(f"   ❌ Error: {e}")


if __name__ == "__main__":
    # Run the main example
    working_example()
    
    # Test with different files
    test_with_different_files()
