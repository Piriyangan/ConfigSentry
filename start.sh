#!/usr/bin/env bash
# Start ConfigSentry on Linux / macOS:  ./start.sh
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 was not found. Install Python 3.10 or newer, for example:"
  echo "  Ubuntu/Debian:  sudo apt install python3 python3-venv"
  echo "  RHEL/Rocky:     sudo dnf install python3"
  echo "  macOS:          brew install python"
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "Creating virtual environment..."
  if ! python3 -m venv .venv 2>/dev/null; then
    rm -rf .venv
    echo "Could not create a virtual environment. On Ubuntu/Debian run:"
    echo "  sudo apt install python3-venv"
    exit 1
  fi
fi

echo "Checking requirements (the first run takes a few minutes)..."
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt
echo "Starting ConfigSentry. Press Ctrl+C to stop."
exec .venv/bin/python run.py "$@"
