@echo off
echo LATD-AI Log Analyzer
echo =================
echo.

echo Select an option:
echo 1. Train a model
echo 2. Start the web interface
echo.

set /p option=Enter option (1-2): 

if "%option%"=="1" (
    cd latd_ai\scripts
    call run_train.bat
) else if "%option%"=="2" (
    cd latd_ai\scripts
    call run_ui.bat
) else (
    echo Invalid option.
    pause
) 