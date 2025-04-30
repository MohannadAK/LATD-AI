# LATD-AI: Log Analysis Threat Detection

A machine learning-based system for analyzing network logs and detecting potential security threats.

## Features

- **Machine Learning Core**: Train models to detect anomalies in network logs
- **Web Interface**: User-friendly UI for log analysis and threat detection
- **Separation of Concerns**: Training and prediction are separate operations
- **Visual Threat Assessment**: Clear visualization of threat levels with explanations

## Project Structure

- `latd_ai/core/`: ML model implementation
- `latd_ai/ui/`: Flask web interface
- `latd_ai/scripts/`: Command-line utilities
- `latd_ai/templates/`: HTML templates for the web interface

## Getting Started

### Prerequisites

- Python 3.8+
- Required Python packages (install via pip):
  ```
  pip install -r requirements.txt
  ```

### Training a Model

```
# Windows
run_latd_ai.bat train

# Unix
./run_latd_ai.sh train
```

### Running the Web Interface

```
# Windows
run_latd_ai.bat ui

# Unix
./run_latd_ai.sh ui
```

## Usage

1. Train the model using the training script
2. Launch the web interface
3. Upload log files for analysis through the drag-and-drop interface
4. Review the threat assessment and detailed analysis

## Note

This repository does not include the datasets used for training. You will need to provide your own network log datasets or use the UNSW-NB15 dataset (available at [https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/)). 