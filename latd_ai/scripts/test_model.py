import os
import sys
import pandas as pd
import numpy as np
import argparse
from tabulate import tabulate

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.model import load_model, predict_log_instance


def generate_test_cases():
    """Generate normal and suspicious test cases for demonstration"""
    test_cases = []
    
    # Normal cases
    normal_cases = [
        {
            "description": "Regular web browsing",
            "srcip": "192.168.1.5",
            "sport": 54321,
            "dstip": "172.217.10.14",
            "dsport": 80,
            "proto": "tcp",
            "state": "CON",
            "dur": 0.5,
            "sbytes": 246,
            "dbytes": 1452,
            "sttl": 64,
            "dttl": 128,
            "service": "http"
        },
        {
            "description": "Regular DNS query",
            "srcip": "192.168.1.10",
            "sport": 33451,
            "dstip": "8.8.8.8",
            "dsport": 53,
            "proto": "udp",
            "state": "CON",
            "dur": 0.01,
            "sbytes": 64,
            "dbytes": 128,
            "sttl": 64,
            "dttl": 64,
            "service": "dns"
        }
    ]
    
    # Suspicious cases
    suspicious_cases = [
        {
            "description": "Port scanning activity",
            "srcip": "192.168.1.50",
            "sport": 31337,
            "dstip": "192.168.1.1",
            "dsport": 22,  # SSH port
            "proto": "tcp",
            "state": "RST",
            "dur": 0.01,
            "sbytes": 40,
            "dbytes": 0,
            "sttl": 64,
            "dttl": 0,
            "service": "-",
            "spkts": 50,
            "dpkts": 0,
            "ct_srv_src": 30,  # High connection count to different services
            "ct_src_dport_ltm": 25  # Many different destination ports
        },
        {
            "description": "Potential DoS attack",
            "srcip": "192.168.1.60",
            "sport": 55555,
            "dstip": "192.168.1.1",
            "dsport": 80,
            "proto": "tcp",
            "state": "CON",
            "dur": 120,  # Long duration
            "sbytes": 100000,  # High traffic volume
            "dbytes": 500,
            "sttl": 64,
            "dttl": 64,
            "service": "http",
            "spkts": 10000,  # Many packets
            "dpkts": 500
        },
        {
            "description": "Data exfiltration attempt",
            "srcip": "192.168.1.70",
            "sport": 44444,
            "dstip": "203.0.113.10",  # External IP
            "dsport": 443,
            "proto": "tcp",
            "state": "CON",
            "dur": 30,
            "sbytes": 50000,  # Large outbound data
            "dbytes": 1200,
            "sttl": 64,
            "dttl": 64,
            "service": "https"
        }
    ]
    
    for case in normal_cases:
        case["expected"] = "Normal"
        test_cases.append(case)
    
    for case in suspicious_cases:
        case["expected"] = "Anomalous"
        test_cases.append(case)
    
    return test_cases


def test_model(model_path=None):
    """Test the model with predefined test cases"""
    # Find latest model if not specified
    if not model_path:
        models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models'))
        model_dirs = [os.path.join(models_dir, d) for d in os.listdir(models_dir) 
                     if os.path.isdir(os.path.join(models_dir, d)) and d.startswith('log_analyzer_model_')]
        
        if not model_dirs:
            print("❌ No trained models found. Please train a model first.")
            return
        
        # Get the most recent model
        model_path = max(model_dirs, key=os.path.getmtime)
    
    print(f"🔍 Testing model: {os.path.basename(model_path)}")
    
    # Load the model
    try:
        model_dict = load_model(model_path)
        print("✅ Model loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return
    
    # Generate test cases
    test_cases = generate_test_cases()
    print(f"📊 Testing {len(test_cases)} predefined test cases")
    
    # Test each case
    results = []
    for i, case in enumerate(test_cases):
        description = case.pop("description")
        expected = case.pop("expected")
        
        try:
            result = predict_log_instance(case, model_dict)
            prediction = result["prediction"]
            confidence = result["confidence"]
            
            is_correct = (prediction == expected)
            
            results.append({
                "ID": i+1,
                "Description": description,
                "Expected": expected,
                "Predicted": prediction,
                "Confidence": f"{confidence:.2%}",
                "Correct": "✅" if is_correct else "❌"
            })
        except Exception as e:
            results.append({
                "ID": i+1,
                "Description": description,
                "Expected": expected,
                "Predicted": "ERROR",
                "Confidence": "N/A",
                "Correct": "❌",
                "Error": str(e)
            })
    
    # Display results as a table
    print("\n📋 Test Results:")
    print(tabulate([r.values() for r in results], 
                  headers=["ID", "Description", "Expected", "Predicted", "Confidence", "Correct"], 
                  tablefmt="grid"))
    
    # Calculate accuracy
    correct_count = sum(1 for r in results if "✅" in r["Correct"])
    accuracy = correct_count / len(results)
    print(f"\n📊 Overall accuracy: {accuracy:.2%} ({correct_count}/{len(results)})")
    
    # Show accuracy for normal vs anomalous
    normal_cases = [r for r in results if r["Expected"] == "Normal"]
    normal_correct = sum(1 for r in normal_cases if "✅" in r["Correct"])
    normal_accuracy = normal_correct / len(normal_cases) if normal_cases else 0
    
    anomalous_cases = [r for r in results if r["Expected"] == "Anomalous"]
    anomalous_correct = sum(1 for r in anomalous_cases if "✅" in r["Correct"])
    anomalous_accuracy = anomalous_correct / len(anomalous_cases) if anomalous_cases else 0
    
    print(f"   - Normal traffic accuracy: {normal_accuracy:.2%} ({normal_correct}/{len(normal_cases)})")
    print(f"   - Anomalous traffic accuracy: {anomalous_accuracy:.2%} ({anomalous_correct}/{len(anomalous_cases)})")


def main():
    parser = argparse.ArgumentParser(description='Test LATD-AI Log Analyzer model')
    parser.add_argument('--model_path', type=str, help='Path to the model directory')
    
    args = parser.parse_args()
    test_model(args.model_path)


if __name__ == "__main__":
    main() 