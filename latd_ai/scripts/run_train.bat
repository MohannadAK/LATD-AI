@echo off
echo LATD-AI Log Analyzer - Model Training
echo ===================================
echo.
echo This will train the model on the UNSW-NB15 dataset.
echo This process will display detailed progress indicators for:
echo  - Dataset download (if needed)
echo  - Data loading and processing 
echo  - Training progress for each model component
echo  - Cross-validation and evaluation
echo.
set /p download=Download dataset? (y/n): 

if /i "%download%"=="y" (
    cd ..
    python -m scripts.train --download_data
) else (
    cd ..
    python -m scripts.train
)

echo.
echo Training complete! The model has been saved.
echo The new model will be automatically loaded when you start the web interface.
echo To start the web interface, run: scripts/run_web.bat
echo.
pause 