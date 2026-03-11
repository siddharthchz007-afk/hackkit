#!/usr/bin/env bash
# Quick-start script for HackKit Pro
# Usage: bash run.sh

set -e

echo "============================================"
echo "  💀 HackKit Pro — Quick Start"
echo "============================================"

# Install dependencies if not already installed
echo "[1/2] Installing dependencies..."
pip install -r requirements.txt -q

echo "[2/2] Starting HackKit Pro..."
echo ""
echo "  Open your browser at: http://localhost:8501"
echo "  Press Ctrl+C to stop the app."
echo ""

streamlit run app.py
