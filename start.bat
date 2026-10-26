@echo off
title ConfigSentry
cd /d "%~dp0"

rem ---- find Python ------------------------------------------------------
set "PY="
py -3 --version >nul 2>nul && set "PY=py -3"
if not defined PY python --version >nul 2>nul && set "PY=python"
if not defined PY (
  echo.
  echo  Python was not found.
  echo  Install Python 3.10 or newer from https://www.python.org/downloads/
  echo  and tick "Add python.exe to PATH" during setup. Then run start.bat again.
  echo.
  pause
  exit /b 1
)

rem ---- first run: create a virtual environment --------------------------
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY% -m venv .venv || (echo Failed to create the virtual environment. & pause & exit /b 1)
)

echo Checking requirements (the first run takes a few minutes)...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || (
  echo Failed to install requirements. Check your Internet connection.
  pause
  exit /b 1
)

echo.
echo Starting ConfigSentry. Your browser will open. Close this window to stop it.
echo.
".venv\Scripts\python.exe" run.py
pause
