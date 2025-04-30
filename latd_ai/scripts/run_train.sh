#!/bin/bash

echo "LATD-AI Log Analyzer - Model Training"
echo "==================================="
echo
echo "This will train the model on the UNSW-NB15 dataset."
echo "This process will display detailed progress indicators for:"
echo " - Dataset download (if needed)"
echo " - Data loading and processing" 
echo " - Training progress for each model component"
echo " - Cross-validation and evaluation"
echo

read -p "Download dataset? (y/n): " download

if [[ $download == "y" || $download == "Y" ]]; then
    cd ..
    python -m scripts.train --download_data
else
    cd ..
    python -m scripts.train
fi

echo
echo "Training complete! The model has been saved."
echo "The new model will be automatically loaded when you start the web interface."
echo "To start the web interface, run: scripts/run_web.sh"
echo 