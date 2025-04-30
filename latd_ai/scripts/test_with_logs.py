import os
import sys
import pandas as pd
import numpy as np
import argparse
from tabulate import tabulate
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report, precision_recall_curve, roc_curve, auc

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.model import load_model, predict_log_instance


def test_with_log_file(log_file_path, model_path=None):
    """Test the model with a log file containing test data"""
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
    
    # Load test data
    try:
        print(f"📂 Loading test data from {log_file_path}")
        df = pd.read_csv(log_file_path)
        print(f"✅ Loaded {len(df)} log entries")
        
        # Check if the test data has label column
        has_labels = 'label' in df.columns
        if has_labels:
            print(f"✅ Test data includes labels: {df['label'].value_counts().to_dict()}")
            true_labels = df['label'].copy()
            # Convert binary labels to text for display
            true_labels = true_labels.map({0: "Normal", 1: "Anomalous"})
        else:
            print("ℹ️ Test data does not include labels, will only show predictions")
        
    except Exception as e:
        print(f"❌ Failed to load test data: {e}")
        return
    
    # Process each log entry
    print(f"🔄 Processing {len(df)} log entries...")
    
    results = []
    predictions = []
    confidences = []
    
    for i, row in df.iterrows():
        # Copy the row to avoid modifying the original
        log_entry = row.copy()
        
        # Remove label if present (don't cheat!)
        if 'label' in log_entry:
            true_label = "Normal" if log_entry['label'] == 0 else "Anomalous"
            log_entry = log_entry.drop('label')
        else:
            true_label = "Unknown"
        
        # Make prediction
        try:
            result = predict_log_instance(log_entry.to_dict(), model_dict)
            prediction = result["prediction"]
            confidence = result["confidence"]
            
            predictions.append(1 if prediction == "Anomalous" else 0)
            confidences.append(confidence)
            
            # Add results (only storing a sample for display)
            if i < 10 or i % max(1, len(df) // 20) == 0:  # Only store some samples for display
                results.append({
                    "ID": i+1,
                    "Source IP": log_entry.get('srcip', 'N/A'),
                    "Dest IP": log_entry.get('dstip', 'N/A'),
                    "Dest Port": log_entry.get('dsport', 'N/A'),
                    "Protocol": log_entry.get('proto', 'N/A'),
                    "True Label": true_label if has_labels else "Unknown",
                    "Predicted": prediction,
                    "Confidence": f"{confidence:.2%}"
                })
            
            # Show progress for large files
            if len(df) > 100 and i % (len(df) // 10) == 0:
                print(f"  ⏳ Processed {i+1}/{len(df)} entries ({(i+1)/len(df):.1%})")
                
        except Exception as e:
            print(f"  ❌ Error processing entry {i+1}: {e}")
    
    print("✅ Processing complete")
    
    # Display sample results
    print("\n📋 Sample Results:")
    print(tabulate([r.values() for r in results], 
                  headers=results[0].keys(), 
                  tablefmt="grid"))
    
    # Calculate and display metrics if we have true labels
    if has_labels:
        true_binary = true_labels.map({"Normal": 0, "Anomalous": 1})
        
        # Calculate overall stats
        correct_count = sum(1 for p, t in zip(predictions, true_binary) if p == t)
        accuracy = correct_count / len(true_binary)
        
        # Create confusion matrix
        cm = confusion_matrix(true_binary, predictions)
        tn, fp, fn, tp = cm.ravel()
        
        # Calculate summary metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n📊 Model Performance Metrics:")
        print(f"  Accuracy: {accuracy:.2%} ({correct_count}/{len(true_binary)})")
        print(f"  Precision: {precision:.2%}")
        print(f"  Recall (Detection Rate): {recall:.2%}")
        print(f"  F1 Score: {f1:.2%}")
        
        print("\n🔍 Confusion Matrix:")
        print(f"  True Negative: {tn} (Correctly identified normal traffic)")
        print(f"  False Positive: {fp} (Normal traffic misclassified as anomalous)")
        print(f"  False Negative: {fn} (Missed anomalies)")
        print(f"  True Positive: {tp} (Correctly detected anomalies)")
        
        # Generate more detailed classification report
        report = classification_report(true_binary, predictions, 
                                     target_names=["Normal", "Anomalous"],
                                     output_dict=True)
        
        print("\n📋 Detailed Classification Report:")
        print("  Class      Precision    Recall  F1-Score   Support")
        print(f"  Normal      {report['0']['precision']:.2f}        {report['0']['recall']:.2f}     {report['0']['f1-score']:.2f}     {report['0']['support']}")
        print(f"  Anomalous   {report['1']['precision']:.2f}        {report['1']['recall']:.2f}     {report['1']['f1-score']:.2f}     {report['1']['support']}")
        print(f"  Accuracy                          {report['accuracy']:.2f}     {sum(report[c]['support'] for c in ['0', '1'])}")
        
        # Analyze results by confidence level
        confidence_bins = [0.1, 0.3, 0.5, 0.7, 0.9, 1.0]
        print("\n📈 Analysis by Confidence Level:")
        for i in range(len(confidence_bins)-1):
            low = confidence_bins[i]
            high = confidence_bins[i+1]
            mask = (confidences >= low) & (confidences < high)
            if sum(mask) > 0:
                bin_acc = sum((true_binary == predictions)[mask]) / sum(mask)
                print(f"  {low:.1f} - {high:.1f}: {bin_acc:.2%} accuracy ({sum(mask)} entries)")
    
    else:
        # Just summarize predictions if no labels
        anomaly_count = sum(1 for p in predictions if p == 1)
        normal_count = len(predictions) - anomaly_count
        print("\n📊 Prediction Summary:")
        print(f"  Normal traffic: {normal_count} ({normal_count/len(predictions):.1%})")
        print(f"  Anomalous traffic: {anomaly_count} ({anomaly_count/len(predictions):.1%})")
        
        # Analyze by confidence level
        confidence_bins = [0.1, 0.3, 0.5, 0.7, 0.9, 1.0]
        print("\n📈 Analysis by Confidence Level:")
        for i in range(len(confidence_bins)-1):
            low = confidence_bins[i]
            high = confidence_bins[i+1]
            mask = (confidences >= low) & (confidences < high)
            if sum(mask) > 0:
                anomaly_pct = sum(np.array(predictions)[mask]) / sum(mask)
                print(f"  {low:.1f} - {high:.1f}: {anomaly_pct:.2%} anomalous ({sum(mask)} entries)")

    # Print information on where to find more detailed results
    print("\n📋 To view detailed results with the web interface:")
    print("  1. Start the web interface: python -m ui.app")
    print("  2. Go to http://localhost:5000")
    print("  3. Upload the test file in the 'Log File Analysis' tab")
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Test LATD-AI Log Analyzer model with log file')
    parser.add_argument('--log_file', type=str, required=False, 
                        help='Path to the CSV file containing test logs')
    parser.add_argument('--model_path', type=str, help='Path to the model directory')
    parser.add_argument('--generate', type=int, help='Generate N test log entries before testing')
    parser.add_argument('--anomaly-ratio', type=float, default=0.2, 
                        help='Ratio of anomalous entries when generating data (0.0-1.0)')
    
    args = parser.parse_args()
    
    # Generate test data if requested
    if args.generate:
        from generate_test_data import generate_test_data
        print(f"Generating {args.generate} test log entries...")
        test_file = generate_test_data(args.generate, anomaly_ratio=args.anomaly_ratio)
        log_file_path = test_file
    else:
        log_file_path = args.log_file
    
    # If no log file specified, look for most recent one
    if not log_file_path:
        test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'test'))
        if os.path.exists(test_dir):
            test_files = [f for f in os.listdir(test_dir) if f.endswith('.csv')]
            if test_files:
                # Get most recent file
                log_file_path = os.path.join(test_dir, max(test_files, key=lambda f: os.path.getmtime(os.path.join(test_dir, f))))
                print(f"Using most recent test file: {log_file_path}")
            else:
                print("No test files found. Generating sample data...")
                from generate_test_data import generate_test_data
                log_file_path = generate_test_data(100)
        else:
            print("No test directory found. Generating sample data...")
            from generate_test_data import generate_test_data
            log_file_path = generate_test_data(100)
    
    # Test with the log file
    test_with_log_file(log_file_path, args.model_path)


if __name__ == "__main__":
    main() 