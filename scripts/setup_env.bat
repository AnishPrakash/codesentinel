@echo off
REM Create the code_env conda environment, install CodeSentinel, and verify it.
REM Usage:  scripts\setup_env.bat

setlocal
if "%CS_ENV_NAME%"=="" set CS_ENV_NAME=code_env
cd /d "%~dp0.."

where conda >nul 2>nul
if errorlevel 1 (
  echo conda not found on PATH.
  echo Open an "Anaconda Prompt", or use a plain venv instead:
  echo   py -3.11 -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -e .
  exit /b 1
)

call conda env list | findstr /R /C:"^%CS_ENV_NAME% " >nul
if errorlevel 1 (
  echo ==^> creating '%CS_ENV_NAME%' ^(python 3.11^)
  call conda create -n %CS_ENV_NAME% python=3.11 -y || exit /b 1
) else (
  echo ==^> environment '%CS_ENV_NAME%' already exists
)

call conda activate %CS_ENV_NAME% || exit /b 1

echo ==^> installing dependencies
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements-dev.txt || exit /b 1
python -m pip install -e . || exit /b 1

echo ==^> tests
python -m pytest -q || exit /b 1

echo ==^> dogfood: scanning our own source
python -m codesentinel scan codesentinel/ --fail-on critical --quiet || exit /b 1

echo.
echo Done. Activate it with:  conda activate %CS_ENV_NAME%
echo Then:                    cs scan demo\invoices.py
echo.
echo For the VS Code extension, set codesentinel.pythonPath to:
python -c "import sys; print('  ' + sys.executable)"
endlocal
