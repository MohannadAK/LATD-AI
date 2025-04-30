@echo off
cls
echo LATD-AI Log Analyzer
echo =================
echo.
echo Select an option:
echo.
echo 1. Train a model
echo 2. Start the web interface
echo 3. Test the model
echo 4. Exit
echo.

set /p option=Enter option (1-4): 

if "%option%"=="1" (
    scripts\run_train.bat
    goto end
)

if "%option%"=="2" (
    scripts\run_web.bat
    goto end
)

if "%option%"=="3" (
    scripts\run_test.bat
    goto end
)

if "%option%"=="4" (
    goto end
)

echo Invalid option, please try again.

:end 