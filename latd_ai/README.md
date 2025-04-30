# LATD-AI: Log Analyzer Threat Detection System

## Overview

LATD-AI is a machine learning-based system for detecting anomalous activities in network logs. It uses a combination of supervised learning (Random Forest) and unsupervised learning (Isolation Forest) to identify potential security threats in network traffic.

## Project Structure

```
latd_ai/
├── core/                # Core ML functionality
│   ├── __init__.py
│   └── model.py         # Machine learning models and algorithms
├── ui/                  # Web user interface
│   ├── __init__.py
│   └── app.py           # Flask web application
├── scripts/             # Command-line utilities
│   ├── __init__.py
│   ├── train.py         # Training script
│   ├── run_train.bat    # Windows script to run training
│   ├── run_train.sh     # Unix script to run training
│   ├── run_ui.bat       # Windows script to run web UI
│   └── run_ui.sh        # Unix script to run web UI
├── data/                # Data storage
│   └── sample_log.csv   # Sample log file for testing
├── models/              # Trained model storage (created during training)
├── logs/                # Log files (created during execution)
├── templates/           # HTML templates for web UI
│   └── index.html       # Main UI template
├── __init__.py          # Package initialization
└── requirements.txt     # Project dependencies
```

## Installation

1. Clone the repository
2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Training the Model

1. **Windows**:
   - Run `scripts/run_train.bat`

2. **Linux/macOS**:
   - Make script executable: `chmod +x scripts/run_train.sh`
   - Run `./scripts/run_train.sh`

This will:
1. Download the UNSW-NB15 dataset if not already present
2. Train the model on the dataset
3. Save the trained model to the `models` directory
4. Output the path to the model, which you'll need for the web interface

Training options:
- `--train_data`: Custom path to training data CSV
- `--test_data`: Custom path to test data CSV
- `--output_dir`: Custom directory to save the model (default: `models`)
- `--download_data`: Download the UNSW-NB15 dataset if needed

### Using the Web Interface

1. **Windows**:
   - Run `scripts/run_ui.bat`

2. **Linux/macOS**:
   - Make script executable: `chmod +x scripts/run_ui.sh`
   - Run `./scripts/run_ui.sh`

3. Open a web browser and navigate to: http://127.0.0.1:5000

4. In the web interface:
   - Enter the full path to your trained model directory (e.g., `models/log_analyzer_model_20240425_123456`)
   - Click "Load Model"
   - Use either the single entry form or batch upload to analyze log data

## Log Format

For analysis, the system requires the following log fields:
- Source IP (`srcip`)
- Source Port (`sport`)
- Destination IP (`dstip`)
- Destination Port (`dsport`)
- Protocol (`proto`)
- State (`state`)
- Duration (`dur`)
- Source Bytes (`sbytes`)
- Destination Bytes (`dbytes`)

A sample log file is provided in `data/sample_log.csv`.

## Model Information

The system uses two models working together:
1. **Random Forest Classifier**: A supervised model trained on labeled data
2. **Isolation Forest**: An anomaly detection model trained on normal traffic

The final prediction combines both models to improve accuracy.

## About the UNSW-NB15 Dataset

The system is trained on the UNSW-NB15 dataset, which contains a mix of normal and attack network traffic. The dataset includes various types of attacks, such as DoS, backdoors, exploits, reconnaissance, and more.

## Troubleshooting

Common issues:
1. **Model loading fails**:
   - Ensure the model path is correct
   - Check that all model files exist in the specified directory

2. **Prediction errors**:
   - Verify that your log data includes the necessary fields
   - Check the format of numeric fields (they should be numbers, not strings)

3. **Flask server issues**:
   - Make sure port 5000 is available
   - Check that Flask is properly installed 