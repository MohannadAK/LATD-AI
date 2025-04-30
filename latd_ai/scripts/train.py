import os
import argparse
import sys
import time

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.model import train_model, save_model, download_unsw_nb15

def print_banner(title):
    """Display a fancy banner for the training process"""
    terminal_width = os.get_terminal_size().columns
    width = min(terminal_width - 4, 80)
    padding = (width - len(title)) // 2
    
    print("\n" + "=" * width)
    print(" " * padding + title)
    print("=" * width + "\n")

def main():
    parser = argparse.ArgumentParser(description='Train and save LATD-AI Log Analyzer model')
    parser.add_argument('--train_data', type=str, help='Path to training data CSV file')
    parser.add_argument('--test_data', type=str, help='Path to test data CSV file')
    parser.add_argument('--output_dir', type=str, default='../models', 
                       help='Directory to save trained model')
    parser.add_argument('--download_data', action='store_true', 
                       help='Download the UNSW-NB15 dataset')
    
    args = parser.parse_args()
    
    # Display banner
    print_banner("LATD-AI Log Analyzer - Model Training")
    
    start_time = time.time()
    
    # Convert paths to absolute and normalize
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(root_dir, 'data', 'UNSW_NB15')
    models_dir = os.path.join(root_dir, 'models')
    
    # Ensure directories exist
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    
    # Download data if requested
    if args.download_data:
        print_banner("Dataset Download")
        download_unsw_nb15(data_dir)
        
    # Default paths if not specified
    if not args.train_data:
        args.train_data = os.path.join(data_dir, "UNSW_NB15_training-set.csv")
    else:
        args.train_data = os.path.abspath(args.train_data)
        
    if not args.test_data:
        args.test_data = os.path.join(data_dir, "UNSW_NB15_testing-set.csv")
    else:
        args.test_data = os.path.abspath(args.test_data)
        
    if not args.output_dir:
        args.output_dir = models_dir
    else:
        args.output_dir = os.path.abspath(args.output_dir)
    
    # Verify data files exist
    if not os.path.exists(args.train_data):
        print(f"❌ Training data file not found: {args.train_data}")
        return
        
    if not os.path.exists(args.test_data):
        print(f"❌ Test data file not found: {args.test_data}")
        return
    
    print_banner("Training Process")
    print(f"🔍 Training dataset: {args.train_data}")
    print(f"🔍 Testing dataset: {args.test_data}")
    print(f"💾 Output directory: {args.output_dir}")
    print("\n" + "-" * 50 + "\n")
    
    # Train model
    model_dict = train_model(args.train_data, args.test_data)
    
    if model_dict:
        # Save model
        print_banner("Saving Model")
        model_path = save_model(model_dict, model_dir=args.output_dir)
        
        # Summary
        total_time = time.time() - start_time
        print_banner("Training Complete")
        print(f"✅ Total process completed in {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
        print(f"🔹 Model saved to: {model_path}")
        print(f"🔹 You can now use this model with the web interface")
        print("\n" + "=" * 50 + "\n")
    else:
        print_banner("Training Failed")
        print("❌ Model training failed. Please check the error messages above.")

if __name__ == "__main__":
    main() 