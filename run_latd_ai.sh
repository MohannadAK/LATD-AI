#!/bin/bash

echo "LATD-AI Log Analyzer"
echo "================="
echo

echo "Select an option:"
echo "1. Train a model"
echo "2. Start the web interface"
echo

read -p "Enter option (1-2): " option

if [ "$option" = "1" ]; then
    cd latd_ai/scripts
    ./run_train.sh
elif [ "$option" = "2" ]; then
    cd latd_ai/scripts
    ./run_ui.sh
else
    echo "Invalid option."
fi 