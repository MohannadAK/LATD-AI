#!/bin/bash

echo "LATD-AI Log Analyzer - Model Testing"
echo "================================="
echo
echo "Choose a testing option:"
echo " 1. Test with predefined examples"
echo " 2. Generate and test with synthetic logs"
echo " 3. Test with existing log file"
echo " 4. Run all tests"
echo " 5. Exit"
echo

read -p "Enter your choice (1-5): " choice

cd ..

if [ "$choice" = "1" ]; then
    echo
    echo "--------------------------------"
    echo "Running model tests with predefined examples..."
    echo "--------------------------------"
    python -m scripts.test_model

elif [ "$choice" = "2" ]; then
    echo
    echo "--------------------------------"
    echo "Generating test data and performing analysis..."
    echo "--------------------------------"
    read -p "Number of log entries to generate (default 200): " samples
    
    if [ -z "$samples" ]; then
        samples=200
    fi
    
    python -m scripts.test_with_logs --generate $samples

elif [ "$choice" = "3" ]; then
    echo
    echo "--------------------------------"
    echo "Testing with existing log file..."
    echo "--------------------------------"
    read -p "Enter path to log file (or press Enter to use most recent): " file
    
    if [ -z "$file" ]; then
        python -m scripts.test_with_logs
    else
        python -m scripts.test_with_logs --log_file "$file"
    fi

elif [ "$choice" = "4" ]; then
    echo
    echo "--------------------------------"
    echo "1. Running model tests with predefined examples..."
    echo "--------------------------------"
    python -m scripts.test_model
    
    echo
    echo "--------------------------------"
    echo "2. Generating and testing with synthetic logs..."
    echo "--------------------------------"
    python -m scripts.test_with_logs --generate 200
    
    echo
    echo "--------------------------------"
    echo "3. Open the web interface to upload the generated test file"
    echo "--------------------------------"
    echo "Go to http://localhost:5000 and upload the generated CSV file from the data/test directory"
    echo

elif [ "$choice" = "5" ]; then
    exit 0

else
    echo "Invalid choice, please try again."
fi

read -p "Press Enter to continue..." 