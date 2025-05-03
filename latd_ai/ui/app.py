import os
import json
import pandas as pd
import sys
import glob
import numpy as np
from datetime import datetime
from werkzeug.utils import send_from_directory

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, render_template, jsonify
from core.model import load_model, predict_log_instance

# Custom JSON encoder to handle NaN, Infinity values
class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            # Replace NaN and Infinity with None (null in JSON)
            if np.isnan(obj) or np.isinf(obj):
                return None
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if pd.isna(obj):
            return None
        return super(NpEncoder, self).default(obj)

app = Flask(__name__)
app.template_folder = '../templates'
app.json_encoder = NpEncoder  # Use our custom encoder for JSON responses

# Global variable to store the loaded model
model_dict = None

def find_latest_model(models_dir='../models'):
    """Find the most recent model in the models directory."""
    try:
        # Ensure the models directory exists
        if not os.path.exists(models_dir):
            return None
            
        # Get all model directories
        model_dirs = glob.glob(os.path.join(models_dir, 'log_analyzer_model_*'))
        
        if not model_dirs:
            return None
            
        # Sort by modification time (most recent first)
        latest_model = max(model_dirs, key=os.path.getmtime)
        
        return latest_model
    except Exception as e:
        print(f"Error finding latest model: {e}")
        return None

def find_default_test_log():
    """Find the most recent test log file to use as default."""
    try:
        test_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'test'))
        if not os.path.exists(test_dir):
            return None
            
        # Get all CSV files in the test directory
        test_files = glob.glob(os.path.join(test_dir, '*.csv'))
        
        if not test_files:
            return None
            
        # Sort by modification time (most recent first)
        latest_test_file = max(test_files, key=os.path.getmtime)
        
        return latest_test_file
    except Exception as e:
        print(f"Error finding default test log: {e}")
        return None

@app.route('/')
def home():
    global model_dict
    
    # Check if model is already loaded
    if model_dict is None:
        # Try to find and load the latest model
        latest_model_path = find_latest_model()
        
        if latest_model_path:
            try:
                model_dict = load_model(latest_model_path)
                print(f"Automatically loaded model from {latest_model_path}")
            except Exception as e:
                print(f"Error automatically loading model: {e}")
    
    # Find default test log file
    default_test_log = find_default_test_log()
    default_test_log_url = None
    
    if default_test_log:
        # Extract just the filename for the URL
        default_test_log_name = os.path.basename(default_test_log)
        default_test_log_url = f'/test_data/{default_test_log_name}'
    
    # Pass information about whether a model is loaded to the template
    model_loaded = model_dict is not None
    model_path = "" if not model_loaded else latest_model_path
    
    return render_template('index.html', 
                          model_loaded=model_loaded, 
                          model_path=model_path,
                          default_test_log=default_test_log_url)

@app.route('/load_model', methods=['POST'])
def load_model_route():
    global model_dict
    
    try:
        model_path = request.form.get('model_path')
        if not model_path or not os.path.exists(model_path):
            return jsonify({'status': 'error', 'message': f'Model path not found: {model_path}'})
            
        model_dict = load_model(model_path)
        return jsonify({'status': 'success', 'message': f'Model loaded successfully from {model_path}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error loading model: {str(e)}'})

@app.route('/predict', methods=['POST'])
def predict():
    global model_dict
    
    if model_dict is None:
        return jsonify({'status': 'error', 'message': 'No model loaded. Please load a model first.'})
    
    try:
        # Get data from request
        data = request.json
        
        # Clean data by replacing any NaN values with None
        cleaned_data = {}
        for key, value in data.items():
            if isinstance(value, str) and value.lower() == 'nan':
                cleaned_data[key] = None
            else:
                cleaned_data[key] = value
        
        # Make prediction
        result = predict_log_instance(cleaned_data, model_dict)
        
        # Enhance the response with additional analysis
        analysis = {}
        
        # Determine the risk level based on the confidence
        confidence = result.get('confidence', 0)
        if result['prediction'] == 'Anomalous':
            if confidence >= 0.9:
                risk_level = "Critical"
                interpretation = "This log entry shows strong indicators of malicious activity"
            elif confidence >= 0.7:
                risk_level = "High"
                interpretation = "This log entry contains suspicious patterns that likely indicate an attack"
            elif confidence >= 0.5:
                risk_level = "Medium"
                interpretation = "This log entry shows some unusual characteristics that warrant investigation"
            else:
                risk_level = "Low"
                interpretation = "This log entry is flagged as anomalous but with low confidence"
            
            # Add feature importance analysis if available
            if 'feature_importance' in result:
                key_indicators = []
                for feature, importance in result['feature_importance'].items():
                    if importance > 0.1:  # Only include high-importance features
                        key_indicators.append({
                            'feature': feature,
                            'importance': importance,
                            'value': cleaned_data.get(feature, 'N/A')
                        })
                analysis['key_indicators'] = key_indicators
                
            analysis['risk_level'] = risk_level
            analysis['interpretation'] = interpretation
            
            # Add potential attack type analysis
            potential_attack_types = identify_potential_attack_types(cleaned_data, result)
            if potential_attack_types:
                analysis['potential_attack_types'] = potential_attack_types
                
            # Add recommendations
            analysis['recommendations'] = single_prediction_recommendations(risk_level)
        else:
            analysis['risk_level'] = "None"
            analysis['interpretation'] = "This log entry appears to be normal network activity"
        
        # Add enhanced analysis to the response
        result['analysis'] = analysis
        
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'Error making prediction: {str(e)}'})

def identify_potential_attack_types(data, result):
    """Identify potential attack types based on log characteristics."""
    potential_attacks = []
    
    # Example rules for identifying attack types
    # In a real implementation, these would be more sophisticated and based on domain knowledge
    
    # Check for potential port scanning
    if 'port' in data and 'connection_count' in data:
        connection_count = data.get('connection_count')
        if connection_count is not None and not pd.isna(connection_count):
            try:
                if int(float(connection_count)) > 10:
                    potential_attacks.append({
                        'type': 'Port Scanning',
                        'description': 'Multiple connection attempts detected which may indicate port scanning activity'
                    })
            except (ValueError, TypeError):
                pass
    
    # Check for potential DoS attack
    if 'bytes' in data and 'packets' in data:
        bytes_val = data.get('bytes')
        packets_val = data.get('packets')
        
        if bytes_val is not None and packets_val is not None and not pd.isna(bytes_val) and not pd.isna(packets_val):
            try:
                bytes_val = float(bytes_val)
                packets_val = float(packets_val)
                if bytes_val > 10000 and packets_val > 100:
                    potential_attacks.append({
                        'type': 'Denial of Service',
                        'description': 'High volume of traffic detected which may indicate a DoS attempt'
                    })
            except (ValueError, TypeError):
                pass
    
    # Check for potential data exfiltration
    if 'bytes_out' in data and 'bytes_in' in data:
        bytes_out = data.get('bytes_out')
        bytes_in = data.get('bytes_in')
        
        if bytes_out is not None and bytes_in is not None and not pd.isna(bytes_out) and not pd.isna(bytes_in):
            try:
                bytes_out = float(bytes_out)
                bytes_in = float(bytes_in)
                if bytes_out > 5 * bytes_in and bytes_out > 1000:
                    potential_attacks.append({
                        'type': 'Data Exfiltration',
                        'description': 'Unusually high outbound data volume which may indicate data exfiltration'
                    })
            except (ValueError, TypeError):
                pass
    
    return potential_attacks

def single_prediction_recommendations(risk_level):
    """Generate recommendations based on the risk level of a single prediction."""
    if risk_level == "Critical":
        return [
            "Immediately investigate this connection",
            "Block the source IP address temporarily",
            "Check for similar patterns in recent logs",
            "Consider this as part of a potential attack campaign"
        ]
    elif risk_level == "High":
        return [
            "Investigate this connection within 24 hours",
            "Monitor the source IP for additional suspicious activity",
            "Review related system logs for context"
        ]
    elif risk_level == "Medium":
        return [
            "Flag for review during regular security monitoring",
            "Look for patterns of similar activity",
            "Consider adding to watchlist for future monitoring"
        ]
    elif risk_level == "Low":
        return [
            "No immediate action required",
            "Consider as part of aggregate analysis",
            "Monitor if similar patterns emerge"
        ]
    else:
        return ["No specific recommendations"]

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    global model_dict
    
    if model_dict is None:
        return jsonify({'status': 'error', 'message': 'No model loaded. Please load a model first.'})
    
    try:
        # Check if we're using the default test dataset
        if request.content_type == 'application/json':
            data = request.json
            if data.get('use_default', False) and data.get('default_url'):
                # Extract filename from URL
                default_url = data.get('default_url')
                filename = default_url.split('/')[-1]
                
                # Build path to the file
                test_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'test'))
                file_path = os.path.join(test_dir, filename)
                
                if not os.path.exists(file_path):
                    return jsonify({'status': 'error', 'message': f'Default test file not found: {filename}'})
                
                # Load the CSV file
                try:
                    df = pd.read_csv(file_path)
                except Exception as e:
                    return jsonify({'status': 'error', 'message': f'Error reading default test file: {str(e)}'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid request format'})
        else:
            # Get uploaded file
            if 'file' not in request.files:
                return jsonify({'status': 'error', 'message': 'No file part'})
                
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'status': 'error', 'message': 'No selected file'})
                
            # Process the CSV file
            try:
                df = pd.read_csv(file)
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Error reading CSV file: {str(e)}'})
        
        # Replace NaN values with None for JSON compatibility
        df = df.replace({np.nan: None})
        
        # Make predictions on the dataframe
        results = []
        anomaly_count = 0
        total_entries = len(df)
        anomaly_confidence_sum = 0
        
        # Sample of anomalies to return
        sample_anomalies = []
        
        # Process each row
        for index, row in df.iterrows():
            # Convert row to dictionary and handle NaN values
            log_entry = row.to_dict()
            
            # Clean NaN values (convert to None for JSON)
            for key, value in log_entry.items():
                if pd.isna(value):
                    log_entry[key] = None
            
            # Make prediction
            result = predict_log_instance(log_entry, model_dict)
            
            # Add the source data to the result
            result.update(log_entry)
            
            # Track anomalies
            if result['prediction'] == 'Anomalous':
                anomaly_count += 1
                anomaly_confidence_sum += result['confidence']
                
                # Keep a sample of anomalies (up to 5)
                if len(sample_anomalies) < 5:
                    # Create a clean copy of log entry without NaN values
                    clean_sample = {}
                    for key, value in log_entry.items():
                        if not pd.isna(value):
                            clean_sample[key] = value
                    
                    clean_sample['confidence'] = result['confidence']
                    clean_sample['prediction'] = 'Anomalous'
                    sample_anomalies.append(clean_sample)
            
            results.append(result)
        
        # Calculate statistics
        anomaly_percentage = (anomaly_count / total_entries) * 100 if total_entries > 0 else 0
        avg_confidence = anomaly_confidence_sum / anomaly_count if anomaly_count > 0 else 0
        
        # Determine overall threat level
        if anomaly_percentage >= 15:
            threat_level = "High"
        elif anomaly_percentage >= 5:
            threat_level = "Medium"
        else:
            threat_level = "Low"
        
        # Generate conclusion text
        conclusion = generate_conclusion(anomaly_count, total_entries, threat_level, avg_confidence)
        
        # Generate recommendations
        recommendations = generate_recommendations(threat_level, anomaly_percentage)
        
        # Clean results for JSON serialization (limit to 100 entries for performance)
        clean_results = []
        for i, res in enumerate(results[:100]):
            if i >= 100:
                break
                
            # Clean record
            clean_record = {}
            for key, value in res.items():
                if not pd.isna(value):
                    clean_record[key] = value
            
            clean_results.append(clean_record)
        
        # Build response with limited results for efficiency
        response = {
            'status': 'success',
            'result': {
                'total_entries': total_entries,
                'anomaly_count': anomaly_count,
                'anomaly_percentage': anomaly_percentage,
                'avg_confidence': float(avg_confidence),
                'threat_level': threat_level,
                'conclusion': conclusion,
                'recommendations': recommendations,
                'sample_anomalies': sample_anomalies,
                'predictions': clean_results
            }
        }
        
        return jsonify(response)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'Error during batch prediction: {str(e)}'})

def generate_conclusion(anomaly_count, total_entries, threat_level, avg_confidence):
    """Generate a detailed conclusion based on analysis results."""
    anomaly_percentage = (anomaly_count / total_entries) * 100 if total_entries > 0 else 0
    
    if anomaly_count == 0:
        return "No anomalies detected in the log file. The system appears to be operating normally."
    
    confidence_desc = "low"
    if avg_confidence >= 0.7 and avg_confidence < 0.9:
        confidence_desc = "moderate"
    elif avg_confidence >= 0.9:
        confidence_desc = "high"
    
    conclusion = f"Analysis detected {anomaly_count} anomalous entries ({anomaly_percentage:.1f}%) with {confidence_desc} confidence. "
    
    if threat_level == "Low":
        conclusion += "The system shows minimal signs of suspicious activity. These could be false positives or minor issues."
    elif threat_level == "Medium":
        conclusion += "The system shows signs of potential intrusion or unusual behavior that warrant investigation."
    elif threat_level == "High":
        conclusion += "Significant anomalous activity detected. This strongly suggests a security breach or system misconfiguration."
    elif threat_level == "Critical":
        conclusion += "Critical level of anomalies detected. Immediate investigation is required as the system shows signs of active compromise."
    
    return conclusion

def generate_recommendations(threat_level, anomaly_percentage):
    """Generate recommendations based on threat level."""
    recommendations = []
    
    if threat_level == "Low":
        recommendations = [
            "Monitor the system for any changes in behavior",
            "Review the few detected anomalies to confirm if they are false positives",
            "No immediate action required if anomalies are confirmed as benign"
        ]
    elif threat_level == "Medium":
        recommendations = [
            "Investigate the detected anomalies, focusing on patterns and timing",
            "Check system logs for unauthorized access attempts",
            "Consider temporary enhanced monitoring of the affected systems"
        ]
    elif threat_level == "High":
        recommendations = [
            "Immediately investigate all anomalous entries",
            "Consider isolating affected systems if possible",
            "Review all recent changes and access to the system",
            "Prepare for potential incident response procedures"
        ]
    elif threat_level == "Critical":
        recommendations = [
            "Initiate incident response procedures immediately",
            "Isolate affected systems from the network",
            "Collect and preserve forensic evidence",
            "Consider bringing in security specialists for assistance",
            "Prepare for potential system recovery operations"
        ]
    
    return recommendations

@app.route('/test_data/<path:filename>')
def test_data(filename):
    """Serve test data files"""
    test_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'test'))
    return send_from_directory(test_dir, filename)

def main():
    # Ensure models directory exists
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models'))
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
        print(f"Created models directory at {models_dir}")
    
    # Check if there are any models available
    latest_model = find_latest_model(models_dir)
    if latest_model:
        print(f"Found latest model at: {latest_model}")
        print("This model will be automatically loaded when the web interface starts")
    else:
        print("No trained models found in the models directory")
        print("Please train a model first using scripts/run_train.sh or scripts/run_train.bat")
    
    print("\nStarting web interface on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main() 