#!/usr/bin/env bash
echo "========================================================"
echo "Starting AI Network Compliance Auditor - Backend API"
echo "========================================================"
export PYTHONPATH=$(pwd)
python3 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
