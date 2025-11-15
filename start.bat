@echo off
setlocal enabledelayedexpansion

REM Check if running with administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    REM No privileges, restart with UAC
    powershell -Command "Start-Process '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

REM Now has administrator privileges
cls
cd /d "%~dp0"

echo.
echo ========================================
echo Starting IPMI-FanPilot...
echo ========================================
echo.

if not exist node_modules (
    echo Installing dependencies...
    call npm install
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install dependencies
        echo Press any key to exit...
        pause
        exit /b 1
    )
)

echo.
echo Server starting on http://localhost:3000
echo.
echo Open your browser: http://localhost:3000
echo.
echo Press Ctrl+C to stop the server
echo.
echo ========================================
echo.

node server.js

if %errorlevel% neq 0 (
    echo.
    echo ========================================
    echo ERROR: Server failed to start
    echo Press any key to exit...
    echo ========================================
    pause
    exit /b 1
)
