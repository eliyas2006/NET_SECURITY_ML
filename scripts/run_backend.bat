@echo off
echo ========================================================
echo Starting AI Network Compliance Auditor - Backend API
echo ========================================================
set PYTHONPATH=%CD%
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause
