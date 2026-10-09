@echo off
rem MST Monitoring Agent launcher (used by the automatic start; can also be double-clicked).
rem The window stays visible on purpose: monitoring on lab PCs is never hidden.
title MST Monitoring Agent
cd /d "%~dp0"
rem Python environment: agent\.venv (lab PCs) or the project's .venv one folder up (the MST laptop).
set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=..\.venv\Scripts\python.exe
if not exist "%PY%" (
  echo The agent is not installed yet. See agent\README.md, section 2.
  pause
  exit /b 1
)
:run
"%PY%" run_agent.py
set CODE=%ERRORLEVEL%
rem 0 = stopped with Ctrl+C, 2 = config.json problem, 3 = the agent is already running: do not restart.
if %CODE%==0 exit /b 0
if %CODE%==2 (echo Fix config.json, then start the agent again. & pause & exit /b 2)
if %CODE%==3 (timeout /t 10 >nul & exit /b 0)
echo The agent stopped unexpectedly (code %CODE%). Restarting in 30 seconds... (close this window to cancel)
timeout /t 30 >nul
goto run
