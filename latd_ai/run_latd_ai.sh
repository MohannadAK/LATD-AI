#!/bin/bash
clear

echo "LATD-AI Log Analyzer"
echo "================="
echo
echo "Select an option:"
echo
echo "1. Train a model"
echo "2. Start the web interface"
echo "3. Test the model"
echo "4. Exit"
echo

read -p "Enter option (1-4): " option

if [ "$option" = "1" ]; then
    scripts/run_train.sh
elif [ "$option" = "2" ]; then
    scripts/run_web.sh
elif [ "$option" = "3" ]; then
    scripts/run_test.sh
elif [ "$option" = "4" ]; then
    exit 0
else
    echo "Invalid option, please try again."
fi 