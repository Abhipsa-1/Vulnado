@echo off
REM VulnGuard AI Virtual Environment Activation Script for Command Prompt (Windows)
REM This script can be run from any path to activate the project's virtual environment
REM Usage: activate.bat or activate.bat deactivate or activate.bat help

setlocal enabledelayedexpansion

if "%1"=="help" (
    goto show_help
)

if "%1"=="deactivate" (
    goto deactivate_venv
)

REM Get the script directory
set "scriptDir=%~dp0"
set "projectRoot=%scriptDir%"
set "venvPath=%projectRoot%.venv"
set "activateScript=%venvPath%\Scripts\activate.bat"

REM Check if venv exists
if not exist "%venvPath%" (
    echo.
    echo [X] Virtual environment not found at: %venvPath%
    echo.
    echo Please create a virtual environment first:
    echo   python -m venv .venv
    echo.
    exit /b 1
)

REM Activate virtual environment
if exist "%activateScript%" (
    call "%activateScript%"
    echo.
    echo [OK] Virtual environment activated: %venvPath%
    echo      Python: %python --version%
    echo      Executable: %venvPath%\Scripts\python.exe
    echo.
    echo Next steps:
    echo   1. Install requirements: pip install -r requirements.txt
    echo   2. Run stages: python -m VULNGUARD_AI.components.stage_XX
    echo   3. Deactivate venv: deactivate
    echo.
) else (
    echo.
    echo [X] Activation script not found at: %activateScript%
    echo Your virtual environment may be corrupted. Try recreating it:
    echo   rmdir /s /q .venv
    echo   python -m venv .venv
    echo.
    exit /b 1
)

exit /b 0

:show_help
echo.
echo VulnGuard AI Virtual Environment Activation Script
echo.
echo USAGE:
echo     activate.bat              - Activate venv
echo     activate.bat deactivate   - Deactivate venv
echo     activate.bat help         - Show this help
echo.
echo DESCRIPTION:
echo     Activates the .venv virtual environment for the VulnGuard AI project.
echo     This script updates PATH, VIRTUAL_ENV, and other environment variables.
echo.
echo NOTES:
echo     - Run from the project root directory
echo     - On older Windows versions, you may need to run CMD as Administrator
echo.
exit /b 0

:deactivate_venv
echo.
if defined VIRTUAL_ENV (
    deactivate
    echo [OK] Virtual environment deactivated
) else (
    echo [!] Virtual environment is not currently active
)
echo.
exit /b 0
