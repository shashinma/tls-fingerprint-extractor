# API Interaction Examples

This document provides practical examples of how to interact with the JA3 Session Extractor using its API.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Advanced Examples](#advanced-examples)
3. [Custom Implementations](#custom-implementations)
4. [Error Handling](#error-handling)
5. [Performance Optimization](#performance-optimization)

## Basic Usage

### Example 1: Simple Session Analysis

```python
#!/usr/bin/env python3
"""Basic API usage example."""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

def basic_analysis_example():
    """Demonstrate basic session analysis."""
    
    # Initialize the analyzer
    analyzer = JA3SessionAnalyzer()
    
    # Parse command line arguments (simulate)
    parser = ArgumentParser()
    
    # Simulate command line arguments
    sys.argv = ['script.py', 'capture.pcap']
    args = parser.parse_args()
    
    # Validate and load PCAP file
    parser.validate_pcap_file(args.pcap)
    packets = parser.load_pcap_file(args.pcap)
    
    # Process packets and extract sessions
    sessions = analyzer.ja3_extractor.process_pcap(packets)
    
    # Get complete sessions only
    complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
    
    # Format and display results
    output = analyzer.output_formatter.format_session_analysis(complete_sessions)
    print(output)
    
    return complete_sessions

if __name__ == "__main__":
    sessions = basic_analysis_example()
    print(f"\nFound {len(sessions)} complete sessions")
```

### Example 2: Rule Generation

```python
#!/usr/bin/env python3
"""Rule generation example."""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.rules import SuricataRuleGenerator
from src.ja3_extractor.cli import ArgumentParser

def rule_generation_example():
    """Demonstrate rule generation."""
    
    # Initialize components
    analyzer = JA3SessionAnalyzer()
    rule_generator = SuricataRuleGenerator()
    
    # Parse arguments
    parser = ArgumentParser()
    sys.argv = ['script.py', 'capture.pcap']
    args = parser.parse_args()
    
    # Load and process PCAP
    packets = parser.load_pcap_file(args.pcap)
    sessions = analyzer.ja3_extractor.process_pcap(packets)
    complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
    
    # Generate hash-based rules
    hash_rules = rule_generator.generate_hash_based_rules(complete_sessions)
    
    # Generate HEX-based rules
    hex_rules = rule_generator.generate_hex_based_rules(complete_sessions)
    
    # Format rules with syntax highlighting
    formatted_hash_rules = analyzer.output_formatter.format_suricata_rules(hash_rules)
    formatted_hex_rules = analyzer.output_formatter.format_suricata_rules(hex_rules)
    
    print("=== Hash-based Rules ===")
    print(formatted_hash_rules)
    
    print("\n=== HEX-based Rules ===")
    print(formatted_hex_rules)
    
    # Export rules to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    with open(f"hash_rules_{timestamp}.rules", "w") as f:
        for rule in hash_rules:
            f.write(f"{rule['content']}\n")
    
    with open(f"hex_rules_{timestamp}.rules", "w") as f:
        for rule in hex_rules:
            f.write(f"{rule['content']}\n")
    
    print(f"\nRules exported to files:")
    print(f"- hash_rules_{timestamp}.rules")
    print(f"- hex_rules_{timestamp}.rules")
    
    return hash_rules, hex_rules

if __name__ == "__main__":
    hash_rules, hex_rules = rule_generation_example()
    print(f"\nGenerated {len(hash_rules)} hash-based rules and {len(hex_rules)} HEX-based rules")
```

## Advanced Examples

### Example 3: Custom Session Filtering

```python
#!/usr/bin/env python3
"""Custom session filtering example."""

import sys
import os
import json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

class CustomSessionAnalyzer:
    """Custom session analyzer with advanced filtering."""
    
    def __init__(self):
        self.analyzer = JA3SessionAnalyzer()
    
    def filter_by_ip_range(self, sessions, ip_range):
        """Filter sessions by IP range."""
        filtered = {}
        for key, session in sessions.items():
            client_ip = session['client_ip']
            server_ip = session['server_ip']
            
            if (self._ip_in_range(client_ip, ip_range) or 
                self._ip_in_range(server_ip, ip_range)):
                filtered[key] = session
        
        return filtered
    
    def filter_by_port(self, sessions, port):
        """Filter sessions by specific port."""
        filtered = {}
        for key, session in sessions.items():
            if (session['client_port'] == port or 
                session['server_port'] == port):
                filtered[key] = session
        
        return filtered
    
    def group_by_ja3_hash(self, sessions):
        """Group sessions by JA3 hash."""
        groups = defaultdict(list)
        for key, session in sessions.items():
            if session['has_ja3']:
                ja3_hash = session['ja3']
                groups[ja3_hash].append(session)
        
        return dict(groups)
    
    def _ip_in_range(self, ip, ip_range):
        """Check if IP is in range (simplified)."""
        # This is a simplified implementation
        # In practice, you'd use ipaddress module
        return ip.startswith(ip_range.split('/')[0])
    
    def analyze_sessions(self, pcap_file):
        """Analyze sessions with custom filtering."""
        
        # Load and process PCAP
        parser = ArgumentParser()
        packets = parser.load_pcap_file(pcap_file)
        sessions = self.analyzer.ja3_extractor.process_pcap(packets)
        complete_sessions = self.analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        print(f"Total complete sessions: {len(complete_sessions)}")
        
        # Filter by IP range (example: 192.168.0.0/16)
        internal_sessions = self.filter_by_ip_range(complete_sessions, "192.168.0.0")
        print(f"Internal network sessions: {len(internal_sessions)}")
        
        # Filter by HTTPS port
        https_sessions = self.filter_by_port(complete_sessions, 443)
        print(f"HTTPS sessions: {len(https_sessions)}")
        
        # Group by JA3 hash
        ja3_groups = self.group_by_ja3_hash(complete_sessions)
        print(f"Unique JA3 hashes: {len(ja3_groups)}")
        
        # Find most common JA3 hash
        if ja3_groups:
            most_common = max(ja3_groups.items(), key=lambda x: len(x[1]))
            print(f"Most common JA3 hash: {most_common[0]} ({len(most_common[1])} sessions)")
        
        return {
            'total': complete_sessions,
            'internal': internal_sessions,
            'https': https_sessions,
            'ja3_groups': ja3_groups
        }

def custom_filtering_example():
    """Demonstrate custom session filtering."""
    
    analyzer = CustomSessionAnalyzer()
    
    # Analyze sessions
    results = analyzer.analyze_sessions('capture.pcap')
    
    # Export results to JSON
    export_data = {
        'summary': {
            'total_sessions': len(results['total']),
            'internal_sessions': len(results['internal']),
            'https_sessions': len(results['https']),
            'unique_ja3_hashes': len(results['ja3_groups'])
        },
        'sessions': results['total']
    }
    
    with open('analysis_results.json', 'w') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    print("\nAnalysis results exported to analysis_results.json")
    
    return results

if __name__ == "__main__":
    results = custom_filtering_example()
```

### Example 4: Batch Processing

```python
#!/usr/bin/env python3
"""Batch processing example."""

import sys
import os
import glob
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.rules import SuricataRuleGenerator
from src.ja3_extractor.cli import ArgumentParser

class BatchProcessor:
    """Batch processor for multiple PCAP files."""
    
    def __init__(self, max_workers=4):
        self.max_workers = max_workers
        self.results = []
    
    def process_single_file(self, pcap_file):
        """Process a single PCAP file."""
        try:
            print(f"Processing {pcap_file}...")
            
            # Initialize components
            analyzer = JA3SessionAnalyzer()
            rule_generator = SuricataRuleGenerator()
            
            # Load and process
            parser = ArgumentParser()
            packets = parser.load_pcap_file(pcap_file)
            sessions = analyzer.ja3_extractor.process_pcap(packets)
            complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
            
            # Generate rules
            hash_rules = rule_generator.generate_hash_based_rules(complete_sessions)
            hex_rules = rule_generator.generate_hex_based_rules(complete_sessions)
            
            # Prepare result
            result = {
                'file': pcap_file,
                'timestamp': datetime.now().isoformat(),
                'total_sessions': len(sessions),
                'complete_sessions': len(complete_sessions),
                'hash_rules_count': len(hash_rules),
                'hex_rules_count': len(hex_rules),
                'sessions': complete_sessions,
                'hash_rules': hash_rules,
                'hex_rules': hex_rules
            }
            
            print(f"Completed {pcap_file}: {len(complete_sessions)} sessions, {len(hash_rules)} hash rules")
            return result
            
        except Exception as e:
            print(f"Error processing {pcap_file}: {str(e)}")
            return {
                'file': pcap_file,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def process_files(self, pcap_files):
        """Process multiple PCAP files in parallel."""
        
        print(f"Processing {len(pcap_files)} files with {self.max_workers} workers...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.process_single_file, pcap_file): pcap_file 
                for pcap_file in pcap_files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                result = future.result()
                self.results.append(result)
        
        return self.results
    
    def export_summary(self, output_file='batch_summary.json'):
        """Export batch processing summary."""
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_files': len(self.results),
            'successful_files': len([r for r in self.results if 'error' not in r]),
            'failed_files': len([r for r in self.results if 'error' in r]),
            'total_sessions': sum(r.get('complete_sessions', 0) for r in self.results),
            'total_hash_rules': sum(r.get('hash_rules_count', 0) for r in self.results),
            'total_hex_rules': sum(r.get('hex_rules_count', 0) for r in self.results),
            'files': self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        print(f"\nBatch summary exported to {output_file}")
        return summary

def batch_processing_example():
    """Demonstrate batch processing."""
    
    # Find all PCAP files in current directory
    pcap_files = glob.glob("*.pcap") + glob.glob("*.pcapng")
    
    if not pcap_files:
        print("No PCAP files found in current directory")
        return
    
    # Process files
    processor = BatchProcessor(max_workers=2)
    results = processor.process_files(pcap_files)
    
    # Export summary
    summary = processor.export_summary()
    
    # Print summary
    print(f"\n=== Batch Processing Summary ===")
    print(f"Files processed: {summary['total_files']}")
    print(f"Successful: {summary['successful_files']}")
    print(f"Failed: {summary['failed_files']}")
    print(f"Total sessions: {summary['total_sessions']}")
    print(f"Total hash rules: {summary['total_hash_rules']}")
    print(f"Total hex rules: {summary['total_hex_rules']}")
    
    return results

if __name__ == "__main__":
    results = batch_processing_example()
```

## Custom Implementations

### Example 5: Custom Rule Generator

```python
#!/usr/bin/env python3
"""Custom rule generator example."""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

class CustomRuleGenerator:
    """Custom rule generator for different IDS systems."""
    
    def __init__(self, tool_name="CustomTool"):
        self.tool_name = tool_name
        self.sid_counter = 4000000  # Different SID range
    
    def generate_snort_rules(self, sessions):
        """Generate Snort-style rules."""
        rules = []
        
        for session in sessions:
            if session['has_ja3']:
                rule = self._create_snort_rule(session)
                rules.append(rule)
        
        return rules
    
    def generate_zeek_rules(self, sessions):
        """Generate Zeek notice rules."""
        rules = []
        
        for session in sessions:
            if session['has_ja3']:
                rule = self._create_zeek_notice(session)
                rules.append(rule)
        
        return rules
    
    def generate_custom_format(self, sessions):
        """Generate custom format rules."""
        rules = []
        
        for session in sessions:
            if session['has_ja3']:
                rule = {
                    'type': 'JA3_DETECTION',
                    'client_ip': session['client_ip'],
                    'server_ip': session['server_ip'],
                    'ja3_hash': session['ja3'],
                    'timestamp': datetime.now().isoformat(),
                    'tool': self.tool_name
                }
                rules.append(rule)
        
        return rules
    
    def _create_snort_rule(self, session):
        """Create Snort rule."""
        ja3_hash = session['ja3']
        sid = self.sid_counter
        self.sid_counter += 1
        
        rule = f"alert tcp {session['client_ip']} any -> {session['server_ip']} 443 " \
               f"(msg:\"JA3 Hash Detection - {self.tool_name}\"; " \
               f"content:\"{ja3_hash}\"; sid:{sid}; rev:1;)"
        
        return {
            'content': rule,
            'sid': sid,
            'rule_type': 'snort',
            'ja3_hash': ja3_hash
        }
    
    def _create_zeek_notice(self, session):
        """Create Zeek notice."""
        notice = {
            'notice_type': 'JA3_Hash_Detection',
            'client_ip': session['client_ip'],
            'server_ip': session['server_ip'],
            'ja3_hash': session['ja3'],
            'tool': self.tool_name,
            'timestamp': datetime.now().isoformat()
        }
        
        return notice

def custom_rule_generation_example():
    """Demonstrate custom rule generation."""
    
    # Load and process PCAP
    analyzer = JA3SessionAnalyzer()
    parser = ArgumentParser()
    
    sys.argv = ['script.py', 'capture.pcap']
    args = parser.parse_args()
    
    packets = parser.load_pcap_file(args.pcap)
    sessions = analyzer.ja3_extractor.process_pcap(packets)
    complete_sessions = analyzer.ja3_extractor.session_manager.get_complete_sessions()
    
    # Generate custom rules
    custom_generator = CustomRuleGenerator("SecurityTeam")
    
    snort_rules = custom_generator.generate_snort_rules(complete_sessions)
    zeek_rules = custom_generator.generate_zeek_rules(complete_sessions)
    custom_rules = custom_generator.generate_custom_format(complete_sessions)
    
    # Export rules
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Snort rules
    with open(f"snort_rules_{timestamp}.rules", "w") as f:
        for rule in snort_rules:
            f.write(f"{rule['content']}\n")
    
    # Zeek notices
    with open(f"zeek_notices_{timestamp}.json", "w") as f:
        import json
        json.dump(zeek_rules, f, indent=2)
    
    # Custom format
    with open(f"custom_rules_{timestamp}.json", "w") as f:
        import json
        json.dump(custom_rules, f, indent=2)
    
    print(f"Generated {len(snort_rules)} Snort rules")
    print(f"Generated {len(zeek_rules)} Zeek notices")
    print(f"Generated {len(custom_rules)} custom format rules")
    
    return snort_rules, zeek_rules, custom_rules

if __name__ == "__main__":
    snort_rules, zeek_rules, custom_rules = custom_rule_generation_example()
```

## Error Handling

### Example 6: Robust Error Handling

```python
#!/usr/bin/env python3
"""Error handling example."""

import sys
import os
import logging
from typing import Optional, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

class RobustAnalyzer:
    """Robust analyzer with comprehensive error handling."""
    
    def __init__(self, log_level=logging.INFO):
        self.setup_logging(log_level)
        self.analyzer = JA3SessionAnalyzer()
        self.parser = ArgumentParser()
    
    def setup_logging(self, level):
        """Setup logging configuration."""
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ja3_analysis.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def safe_process_pcap(self, pcap_file: str) -> Optional[Dict[str, Any]]:
        """Safely process PCAP file with error handling."""
        
        try:
            self.logger.info(f"Starting analysis of {pcap_file}")
            
            # Validate file
            self.parser.validate_pcap_file(pcap_file)
            self.logger.info("File validation passed")
            
            # Load file
            packets = self.parser.load_pcap_file(pcap_file)
            self.logger.info(f"Loaded {len(packets)} packets")
            
            # Process packets
            sessions = self.analyzer.ja3_extractor.process_pcap(packets)
            self.logger.info(f"Processed {len(sessions)} sessions")
            
            # Get complete sessions
            complete_sessions = self.analyzer.ja3_extractor.session_manager.get_complete_sessions()
            self.logger.info(f"Found {len(complete_sessions)} complete sessions")
            
            return {
                'file': pcap_file,
                'total_sessions': len(sessions),
                'complete_sessions': len(complete_sessions),
                'sessions': complete_sessions,
                'status': 'success'
            }
            
        except FileNotFoundError as e:
            self.logger.error(f"File not found: {e}")
            return {'file': pcap_file, 'error': str(e), 'status': 'file_not_found'}
            
        except PermissionError as e:
            self.logger.error(f"Permission denied: {e}")
            return {'file': pcap_file, 'error': str(e), 'status': 'permission_denied'}
            
        except Exception as e:
            self.logger.error(f"Unexpected error processing {pcap_file}: {e}")
            return {'file': pcap_file, 'error': str(e), 'status': 'error'}
    
    def safe_generate_rules(self, sessions: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Safely generate rules with error handling."""
        
        try:
            if not sessions:
                self.logger.warning("No sessions provided for rule generation")
                return {'rules': [], 'status': 'no_sessions'}
            
            # Generate rules
            hash_rules = self.analyzer.rule_generator.generate_hash_based_rules(sessions)
            hex_rules = self.analyzer.rule_generator.generate_hex_based_rules(sessions)
            
            self.logger.info(f"Generated {len(hash_rules)} hash rules and {len(hex_rules)} hex rules")
            
            return {
                'hash_rules': hash_rules,
                'hex_rules': hex_rules,
                'status': 'success'
            }
            
        except Exception as e:
            self.logger.error(f"Error generating rules: {e}")
            return {'error': str(e), 'status': 'error'}

def error_handling_example():
    """Demonstrate robust error handling."""
    
    analyzer = RobustAnalyzer(log_level=logging.DEBUG)
    
    # Test with various scenarios
    test_files = [
        'valid_capture.pcap',      # Valid file
        'nonexistent.pcap',        # Non-existent file
        'permission_denied.pcap',  # Permission denied
        'invalid_format.pcap'      # Invalid format
    ]
    
    results = []
    
    for pcap_file in test_files:
        result = analyzer.safe_process_pcap(pcap_file)
        results.append(result)
        
        if result['status'] == 'success':
            # Try to generate rules
            rule_result = analyzer.safe_generate_rules(result['sessions'])
            result['rule_generation'] = rule_result
    
    # Print summary
    print("\n=== Processing Summary ===")
    for result in results:
        print(f"File: {result['file']}")
        print(f"Status: {result['status']}")
        if 'error' in result:
            print(f"Error: {result['error']}")
        if 'complete_sessions' in result:
            print(f"Sessions: {result['complete_sessions']}")
        print()
    
    return results

if __name__ == "__main__":
    results = error_handling_example()
```

## Performance Optimization

### Example 7: Memory-Efficient Processing

```python
#!/usr/bin/env python3
"""Memory-efficient processing example."""

import sys
import os
import gc
from typing import Generator, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

class MemoryEfficientProcessor:
    """Memory-efficient processor for large PCAP files."""
    
    def __init__(self):
        self.analyzer = JA3SessionAnalyzer()
        self.parser = ArgumentParser()
    
    def process_pcap_generator(self, pcap_file: str) -> Generator[Dict[str, Any], None, None]:
        """Process PCAP file using generator to save memory."""
        
        try:
            # Load packets
            packets = self.parser.load_pcap_file(pcap_file)
            
            # Process packets in chunks
            chunk_size = 1000
            for i in range(0, len(packets), chunk_size):
                chunk = packets[i:i + chunk_size]
                
                # Process chunk
                sessions = self.analyzer.ja3_extractor.process_pcap(chunk)
                complete_sessions = self.analyzer.ja3_extractor.session_manager.get_complete_sessions()
                
                # Yield results
                yield {
                    'chunk': i // chunk_size + 1,
                    'sessions': complete_sessions,
                    'session_count': len(complete_sessions)
                }
                
                # Clear memory
                del chunk, sessions, complete_sessions
                gc.collect()
                
        except Exception as e:
            yield {'error': str(e)}
    
    def process_large_file(self, pcap_file: str):
        """Process large PCAP file efficiently."""
        
        print(f"Processing large file: {pcap_file}")
        
        total_sessions = 0
        chunk_count = 0
        
        for chunk_result in self.process_pcap_generator(pcap_file):
            if 'error' in chunk_result:
                print(f"Error: {chunk_result['error']}")
                break
            
            chunk_count += 1
            total_sessions += chunk_result['session_count']
            
            print(f"Chunk {chunk_result['chunk']}: {chunk_result['session_count']} sessions")
        
        print(f"\nTotal: {total_sessions} sessions in {chunk_count} chunks")
        return total_sessions

def memory_efficient_example():
    """Demonstrate memory-efficient processing."""
    
    processor = MemoryEfficientProcessor()
    
    # Process large file
    total_sessions = processor.process_large_file('large_capture.pcap')
    
    return total_sessions

if __name__ == "__main__":
    total_sessions = memory_efficient_example()
```

## Integration Examples

### Example 8: Integration with External Systems

```python
#!/usr/bin/env python3
"""Integration with external systems example."""

import sys
import os
import requests
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ja3_extractor import JA3SessionAnalyzer
from src.ja3_extractor.cli import ArgumentParser

class ExternalSystemIntegration:
    """Integration with external security systems."""
    
    def __init__(self, siem_url=None, threat_intel_url=None):
        self.siem_url = siem_url
        self.threat_intel_url = threat_intel_url
        self.analyzer = JA3SessionAnalyzer()
        self.parser = ArgumentParser()
    
    def send_to_siem(self, sessions):
        """Send analysis results to SIEM."""
        
        if not self.siem_url:
            print("SIEM URL not configured")
            return False
        
        try:
            # Prepare data for SIEM
            siem_data = {
                'timestamp': datetime.now().isoformat(),
                'source': 'JA3_Session_Extractor',
                'sessions': sessions,
                'summary': {
                    'total_sessions': len(sessions),
                    'sessions_with_ja3': len([s for s in sessions.values() if s['has_ja3']]),
                    'sessions_with_ja3s': len([s for s in sessions.values() if s['has_ja3s']])
                }
            }
            
            # Send to SIEM
            response = requests.post(
                self.siem_url,
                json=siem_data,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"Successfully sent {len(sessions)} sessions to SIEM")
                return True
            else:
                print(f"SIEM request failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error sending to SIEM: {e}")
            return False
    
    def check_threat_intel(self, ja3_hash):
        """Check JA3 hash against threat intelligence."""
        
        if not self.threat_intel_url:
            print("Threat intelligence URL not configured")
            return None
        
        try:
            response = requests.get(
                f"{self.threat_intel_url}/ja3/{ja3_hash}",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
                
        except Exception as e:
            print(f"Error checking threat intelligence: {e}")
            return None
    
    def analyze_with_integration(self, pcap_file):
        """Analyze PCAP with external system integration."""
        
        # Process PCAP
        packets = self.parser.load_pcap_file(pcap_file)
        sessions = self.analyzer.ja3_extractor.process_pcap(packets)
        complete_sessions = self.analyzer.ja3_extractor.session_manager.get_complete_sessions()
        
        # Check threat intelligence
        threat_results = {}
        for session in complete_sessions.values():
            if session['has_ja3']:
                ja3_hash = session['ja3']
                threat_info = self.check_threat_intel(ja3_hash)
                if threat_info:
                    threat_results[ja3_hash] = threat_info
        
        # Send to SIEM
        siem_success = self.send_to_siem(complete_sessions)
        
        return {
            'sessions': complete_sessions,
            'threat_results': threat_results,
            'siem_success': siem_success
        }

def integration_example():
    """Demonstrate external system integration."""
    
    # Configure integration
    integration = ExternalSystemIntegration(
        siem_url="http://localhost:8080/api/events",
        threat_intel_url="http://localhost:8081/api"
    )
    
    # Analyze with integration
    results = integration.analyze_with_integration('capture.pcap')
    
    print(f"Processed {len(results['sessions'])} sessions")
    print(f"Found {len(results['threat_results'])} threat intelligence matches")
    print(f"SIEM integration: {'Success' if results['siem_success'] else 'Failed'}")
    
    return results

if __name__ == "__main__":
    results = integration_example()
```

These examples demonstrate various ways to interact with the JA3 Session Extractor API, from basic usage to advanced integration scenarios. Each example includes error handling and best practices for production use.
