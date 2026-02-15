# VulnGuard AI Virtual Environment Activation Script for PowerShell
# This script can be run from any path to activate the project's virtual environment
# Usage: . .\activate.ps1 (from project root) or powershell -ExecutionPolicy Bypass -File "C:\path\to\activate.ps1"

param(
    [switch]$Help,
    [switch]$Deactivate
)

# Display help
if ($Help) {
    Write-Host @"
VulnGuard AI Virtual Environment Activation Script

USAGE:
    . .\activate.ps1              # Activate from project root
    . .\activate.ps1 -Deactivate  # Deactivate venv
    . .\activate.ps1 -Help        # Show this help

DESCRIPTION:
    Activates the .venv virtual environment for the VulnGuard AI project.
    This script updates PATH, VIRTUAL_ENV, and other environment variables.

NOTES:
    - Run from the project root directory
    - Use dot-sourcing (. .\activate.ps1) to apply changes to current shell
    - On Windows, you may need to set execution policy:
      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

"@
    exit 0
}

# Get the script directory
$scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$projectRoot = $scriptDir

# Define venv paths
$venvPath = Join-Path -Path $projectRoot -ChildPath ".venv"
$activateScript = Join-Path -Path $venvPath -ChildPath "Scripts" | Join-Path -ChildPath "Activate.ps1"

# Check if venv exists
if (-not (Test-Path $venvPath)) {
    Write-Error "Virtual environment not found at: $venvPath"
    Write-Host "Please create a virtual environment first:"
    Write-Host "  python -m venv .venv"
    exit 1
}

# Deactivate if requested
if ($Deactivate) {
    if (Test-Path function:deactivate) {
        deactivate
        Write-Host "✓ Virtual environment deactivated" -ForegroundColor Green
    } else {
        Write-Host "⚠ Virtual environment is not currently active" -ForegroundColor Yellow
    }
    exit 0
}

# Activate virtual environment
if (Test-Path $activateScript) {
    & $activateScript
    Write-Host "✓ Virtual environment activated: $venvPath" -ForegroundColor Green
    Write-Host "  Python: $(python --version)"
    Write-Host "  Executable: $(python -c 'import sys; print(sys.executable)')"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Install requirements: pip install -r requirements.txt"
    Write-Host "  2. Run stages: python -m VULNGUARD_AI.components.stage_XX"
    Write-Host "  3. Deactivate venv: . .\activate.ps1 -Deactivate"
    Write-Host ""
} else {
    Write-Error "Activation script not found at: $activateScript"
    Write-Error "Your virtual environment may be corrupted. Try recreating it:"
    Write-Error "  rmdir /s .venv"
    Write-Error "  python -m venv .venv"
    exit 1
}
