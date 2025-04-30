@echo off
echo LATD-AI Log Analyzer - Model Testing
echo =================================
echo.
echo Choose a testing option:
echo  1. Test with predefined examples
echo  2. Generate and test with synthetic logs
echo  3. Test with existing log file
echo  4. Run all tests
echo  5. Exit
echo.

set /p choice=Enter your choice (1-5): 

cd ..

if "%choice%"=="1" (
    echo.
    echo --------------------------------
    echo Running model tests with predefined examples...
    echo --------------------------------
    python -m scripts.test_model
    goto end
)

if "%choice%"=="2" (
    echo.
    echo --------------------------------
    echo Generating test data and performing analysis...
    echo --------------------------------
    set /p samples=Number of log entries to generate (default 200): 
    
    if "%samples%"=="" set samples=200
    
    python -m scripts.test_with_logs --generate %samples%
    goto end
)

if "%choice%"=="3" (
    echo.
    echo --------------------------------
    echo Testing with existing log file...
    echo --------------------------------
    set /p file=Enter path to log file (or press Enter to use most recent): 
    
    if "%file%"=="" (
        python -m scripts.test_with_logs
    ) else (
        python -m scripts.test_with_logs --log_file "%file%"
    )
    goto end
)

if "%choice%"=="4" (
    echo.
    echo --------------------------------
    echo 1. Running model tests with predefined examples...
    echo --------------------------------
    python -m scripts.test_model
    
    echo.
    echo --------------------------------
    echo 2. Generating and testing with synthetic logs...
    echo --------------------------------
    python -m scripts.test_with_logs --generate 200
    
    echo.
    echo --------------------------------
    echo 3. Open the web interface to upload the generated test file
    echo --------------------------------
    echo Go to http://localhost:5000 and upload the generated CSV file from the data/test directory
    echo.
    goto end
)

if "%choice%"=="5" (
    goto end
)

echo Invalid choice, please try again.

:end
pause 