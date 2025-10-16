#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick API Test Example

This is a minimal example to quickly test the JA3 Session Extractor API.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def quick_test():
    """Quick test of the JA3 Session Extractor API."""
    
    print("JA3 Session Extractor - Quick API Test")
    print("=" * 50)
    
    try:
        # Import JA3 Extractor
        from src.ja3_extractor import JA3SessionAnalyzer
        from src.ja3_extractor.cli import ArgumentParser
        
        print("✅ Successfully imported JA3 Session Extractor")
        
        # Initialize components
        analyzer = JA3SessionAnalyzer()
        parser = ArgumentParser()
        
        print("✅ Successfully initialized components")
        
        # Check for PCAP files in project root
        pcap_files = [f for f in os.listdir('..') if f.endswith(('.pcap', '.pcapng'))]
        
        if pcap_files:
            print(f"✅ Found {len(pcap_files)} PCAP files:")
            for f in pcap_files:
                print(f"   📄 {f}")
            
            # Test with first PCAP file (add relative path)
            test_file = f"../{pcap_files[0]}"
            print(f"\n🔍 Testing with: {test_file}")
            
            # Load PCAP
            packets = parser.load_pcap_file(test_file)
            print(f"✅ Loaded {len(packets)} packets")
            
            # Process packets
            sessions = analyzer.ja3_extractor.process_pcap(packets)
            complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
            
            print(f"✅ Found {len(sessions)} total sessions")
            print(f"✅ Found {len(complete_sessions)} complete sessions")
            
            if complete_sessions:
                # Show first session
                first_session = list(complete_sessions.values())[0]
                print(f"\n📊 Sample session:")
                print(f"   Client: {first_session['client_ip']}:{first_session['client_port']}")
                print(f"   Server: {first_session['server_ip']}:{first_session['server_port']}")
                
                if first_session.get('has_ja3'):
                    ja3 = first_session.get('ja3', 'N/A')
                    print(f"   JA3: {ja3[:32]}..." if len(ja3) > 32 else f"   JA3: {ja3}")
                
                if first_session.get('has_ja3s'):
                    ja3s = first_session.get('ja3s', 'N/A')
                    print(f"   JA3S: {ja3s[:32]}..." if len(ja3s) > 32 else f"   JA3S: {ja3s}")
                
                # Generate sample rules
                hash_rules = analyzer.rule_generator.generate_hash_based_rules(complete_sessions)
                print(f"\n🛡️ Generated {len(hash_rules)} hash-based rules")
                
                if hash_rules:
                    rule_content = hash_rules[0] if isinstance(hash_rules[0], str) else hash_rules[0]['content']
                    print(f"📝 Sample rule:")
                    print(f"   {rule_content[:80]}...")
            
            print(f"\n🎉 API test completed successfully!")
            
        else:
            print("❌ No PCAP files found in project root")
            print("💡 Place a PCAP file in the project root directory to test")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure you're in the project root directory")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    quick_test()
