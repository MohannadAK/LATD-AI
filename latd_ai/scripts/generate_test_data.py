import os
import pandas as pd
import numpy as np
import argparse
import random
from datetime import datetime, timedelta

def generate_test_data(num_samples=100, output_file=None, anomaly_ratio=0.2):
    """Generate a CSV file with test network log data"""
    if output_file is None:
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'test'))
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f'test_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
    
    # Define feature ranges
    protocols = ['tcp', 'udp', 'icmp', 'arp', 'ospf']
    services = ['http', 'https', 'dns', 'smtp', 'ftp', 'ssh', 'telnet', '-']
    states = ['FIN', 'CON', 'REQ', 'RST', 'PAR', 'ACC', 'CLO', '-']
    
    # Generate random source and destination IPs
    source_ips = [f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(20)]
    dest_ips = [f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(20)]
    dest_ips.extend([f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(10)])
    dest_ips.extend([f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(5)])
    
    print(f"Generating {num_samples} test log entries with {anomaly_ratio*100:.0f}% anomalies...")
    
    # Generate normal traffic logs
    normal_count = int(num_samples * (1 - anomaly_ratio))
    anomaly_count = num_samples - normal_count
    
    data = []
    
    # Generate normal logs
    for i in range(normal_count):
        log = {
            'srcip': random.choice(source_ips),
            'sport': random.randint(10000, 65535),
            'dstip': random.choice(dest_ips[:25]),  # More likely to be internal
            'dsport': random.choice([80, 443, 53, 25, 21, 22, 110, 143, 3306, 5432]),
            'proto': random.choice(protocols[:2]),  # More likely TCP/UDP
            'state': random.choice(states[:3]),  # More likely connected states
            'dur': random.uniform(0.001, 2.0),
            'sbytes': random.randint(40, 1500),
            'dbytes': random.randint(40, 8000),
            'sttl': random.randint(60, 128),
            'dttl': random.randint(60, 128),
            'sloss': 0,
            'dloss': 0,
            'service': random.choice(services[:6]),
            'sload': random.uniform(0, 1),
            'dload': random.uniform(0, 3),
            'spkts': random.randint(1, 20),
            'dpkts': random.randint(1, 30),
            'label': 0  # Normal
        }
        data.append(log)
    
    # Generate anomalous logs
    attack_types = [
        "port_scan", "dos", "bruteforce", "data_exfiltration", "backdoor"
    ]
    
    for i in range(anomaly_count):
        attack = random.choice(attack_types)
        
        if attack == "port_scan":
            log = {
                'srcip': random.choice(source_ips),
                'sport': random.randint(10000, 65535),
                'dstip': random.choice(dest_ips),
                'dsport': random.randint(1, 1024),  # Targeting lower privileged ports
                'proto': 'tcp',
                'state': 'RST',  # Often reset
                'dur': random.uniform(0.001, 0.01),  # Very short
                'sbytes': random.randint(40, 100),  # Small packets
                'dbytes': random.randint(0, 40),  # Often no response
                'sttl': random.randint(60, 128),
                'dttl': random.randint(0, 128),
                'sloss': 0,
                'dloss': 0,
                'service': '-',
                'sload': random.uniform(0, 0.1),
                'dload': 0,
                'spkts': random.randint(1, 3),
                'dpkts': random.randint(0, 1),
                'ct_srv_src': random.randint(20, 50),  # Many services targeted
                'ct_src_dport_ltm': random.randint(20, 100),  # Many ports targeted
                'label': 1  # Anomalous
            }
        elif attack == "dos":
            log = {
                'srcip': random.choice(source_ips),
                'sport': random.randint(10000, 65535),
                'dstip': random.choice(dest_ips[:5]),  # Target important servers
                'dsport': random.choice([80, 443, 22, 3389]),  # Target important services
                'proto': random.choice(['tcp', 'udp']),
                'state': random.choice(['CON', 'REQ']),
                'dur': random.uniform(10, 300),  # Long duration
                'sbytes': random.randint(10000, 10000000),  # High volume
                'dbytes': random.randint(0, 1000),
                'sttl': random.randint(60, 128),
                'dttl': random.randint(60, 128),
                'sloss': random.randint(0, 100),
                'dloss': random.randint(0, 100),
                'service': random.choice(['http', 'https']),
                'sload': random.uniform(10, 100),  # High load
                'dload': random.uniform(0, 1),
                'spkts': random.randint(1000, 100000),  # Many packets
                'dpkts': random.randint(0, 100),
                'label': 1  # Anomalous
            }
        elif attack == "bruteforce":
            log = {
                'srcip': random.choice(source_ips),
                'sport': random.randint(10000, 65535),
                'dstip': random.choice(dest_ips[:10]),
                'dsport': random.choice([22, 3389, 21, 25]),  # Target auth services
                'proto': 'tcp',
                'state': random.choice(['REQ', 'RST']),
                'dur': random.uniform(0.1, 5.0),
                'sbytes': random.randint(100, 500),
                'dbytes': random.randint(100, 500),
                'sttl': random.randint(60, 128),
                'dttl': random.randint(60, 128),
                'sloss': 0,
                'dloss': 0,
                'service': random.choice(['ssh', 'telnet', 'ftp']),
                'sload': random.uniform(0.1, 2),
                'dload': random.uniform(0.1, 2),
                'spkts': random.randint(10, 50),
                'dpkts': random.randint(10, 50),
                'ct_dst_src_ltm': random.randint(50, 200),  # Many connections to same host
                'label': 1  # Anomalous
            }
        elif attack == "data_exfiltration":
            log = {
                'srcip': random.choice(source_ips),
                'sport': random.randint(10000, 65535),
                'dstip': random.choice(dest_ips[25:]),  # External IP
                'dsport': random.choice([443, 53, 6667, 8080]),  # Common exfil channels
                'proto': random.choice(['tcp', 'udp']),
                'state': 'CON',
                'dur': random.uniform(10, 60),
                'sbytes': random.randint(10000, 1000000),  # Large outbound data
                'dbytes': random.randint(100, 1000),  # Small inbound data
                'sttl': random.randint(60, 128),
                'dttl': random.randint(60, 128),
                'sloss': 0,
                'dloss': 0,
                'service': random.choice(['https', 'dns', 'http']),
                'sload': random.uniform(1, 10),
                'dload': random.uniform(0.1, 1),
                'spkts': random.randint(100, 1000),
                'dpkts': random.randint(10, 100),
                'label': 1  # Anomalous
            }
        else:  # backdoor
            log = {
                'srcip': random.choice(dest_ips[25:]),  # External IP
                'sport': random.randint(10000, 65535),
                'dstip': random.choice(source_ips),  # Internal target
                'dsport': random.randint(10000, 65535),  # High ports
                'proto': random.choice(['tcp', 'udp']),
                'state': 'CON',
                'dur': random.uniform(100, 3600),  # Long-lived
                'sbytes': random.randint(1000, 10000),
                'dbytes': random.randint(1000, 10000),
                'sttl': random.randint(60, 128),
                'dttl': random.randint(60, 128),
                'sloss': 0,
                'dloss': 0,
                'service': random.choice(['http', '-']),
                'sload': random.uniform(0.1, 1),
                'dload': random.uniform(0.1, 1),
                'spkts': random.randint(10, 100),
                'dpkts': random.randint(10, 100),
                'ct_dst_ltm': random.randint(1, 5),  # Few connections
                'label': 1  # Anomalous
            }
        
        data.append(log)
    
    # Convert to DataFrame and shuffle
    df = pd.DataFrame(data)
    df = df.sample(frac=1).reset_index(drop=True)  # Shuffle
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"✅ Generated {num_samples} log entries ({anomaly_count} anomalous, {normal_count} normal)")
    print(f"📁 Saved to: {output_file}")
    
    return output_file

def main():
    parser = argparse.ArgumentParser(description='Generate test data for LATD-AI Log Analyzer')
    parser.add_argument('--samples', type=int, default=100, help='Number of log entries to generate')
    parser.add_argument('--output', type=str, help='Output CSV file path')
    parser.add_argument('--anomaly-ratio', type=float, default=0.2, 
                       help='Ratio of anomalous entries (0.0-1.0)')
    
    args = parser.parse_args()
    generate_test_data(args.samples, args.output, args.anomaly_ratio)

if __name__ == "__main__":
    main() 