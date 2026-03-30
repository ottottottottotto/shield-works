@echo off
title Shield Works Security Scanner Launcher
echo ==============================================
echo    Starting Shield Works Security Scanner...
echo ==============================================
echo.

:: 1. Ensure all required Python packages are installed first
echo [1/3] Checking and installing required Python modules...
python -m pip install fastapi "uvicorn[standard]" httpx dnspython pydantic certifi python-multipart
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [CRITICAL ERROR]: Python could not be found or pip failed. 
    echo Please ensure you have Python 3.9+ installed and added to your SYSTEM PATH!
    echo Download it for free at: https://www.python.org/downloads/
    echo.
    pause
    exit /b
)

:: 2. Start the backend server in a separate, dedicated window
echo [2/3] Spinning up FastAPI Backend Server on Port 8000...
start "Shield Works Server Backend" cmd /k "python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

:: 3. Give the server a couple of seconds to bind to the port before launching the browser
echo [3/3] Waiting for server bootup...
timeout /t 3 /nobreak > nul

:: 4. Launch the exact target URL
echo Launching Application Dashboard!
start http://127.0.0.1:8000
