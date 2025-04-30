@echo off
echo LATD-AI Log Analyzer Web Interface
echo =================================
echo.
echo Starting the web interface...
echo The most recently trained model will be automatically loaded.
echo.
cd ..
python -m ui.app
pause 