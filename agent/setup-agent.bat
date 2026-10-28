@echo off
rem MST agent setup for a lab PC: installs the agent's Python packages, enrolls this PC with the enrollment key
rem (Computers > Add Computers on the MST website) and optionally starts the agent at sign-in.
rem Double-click it in C:\MST\agent. Put enrollment.txt (downloaded from the website) in the same folder,
rem or type the key when asked.
title MST agent setup
cd /d "%~dp0"
echo ============================================================
echo  MST Monitoring Agent - setup for this PC
echo ============================================================
echo.

rem 1. Python: use the first one that really runs (a half-removed Python can still be listed by "py").
set PYTHON=
for %%v in ("py -3.13" "py -3.12" "py -3.11" "py -3.14" "py -3" "python") do (
  if not defined PYTHON (
    %%~v -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PYTHON=%%~v"
  )
)
if not defined PYTHON (
  echo No working Python 3.10 or newer was found on this PC.
  echo Install Python 3.13 ^(64-bit^) from https://www.python.org/downloads/windows/ and tick "Add python.exe to PATH".
  echo If Python is listed but broken, run in PowerShell:  py list   then remove the broken version and install 3.13.
  echo Then double-click setup-agent.bat again.
  pause
  exit /b 1
)
echo Using Python: %PYTHON%

rem 2. Python environment and packages (offline from the "wheels" folder when it exists)
rem A .venv made with a Python that was removed later no longer works: make it again.
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import sys" >nul 2>nul || rmdir /s /q .venv
)
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating the Python environment...
  %PYTHON% -m venv .venv || (echo Could not create the Python environment. & pause & exit /b 1)
)
set PY=.venv\Scripts\python.exe
echo [1/3] Installing the agent's packages...
if exist "wheels\" (
  "%PY%" -m pip install --quiet --no-index --find-links wheels -r requirements.txt
) else (
  "%PY%" -m pip install --quiet -r requirements.txt
)
if errorlevel 1 (echo Installing the packages failed. Check the internet connection, then run setup-agent.bat again. & pause & exit /b 1)

rem 3. Enroll. One PC: the config.json downloaded from Add Computers > One PC is enough (no key).
rem Many PCs: an enrollment key (enrollment.txt or typed).
"%PY%" run_agent.py --is-enrolled >nul 2>nul && goto checkconn
"%PY%" run_agent.py --import-config && goto checkconn
goto needkey

:checkconn
echo [2/3] This PC has its config.json. Checking the connection to the MST server...
"%PY%" run_agent.py --find-server && goto autostart
echo.
echo The MST server could not be reached, or it did not accept this PC's token.
echo  - On the server: start-server.bat must be running, and port 8081 allowed in the firewall.
echo  - This PC must be on the same network (LAN cable or the same Wi-Fi) as the server.
echo  - If the PC was deleted on the website or got a New Token, download its config.json again.
choice /c RKS /m "R = try again, K = enroll with a key instead, S = skip"
if errorlevel 3 goto autostart
if errorlevel 2 goto needkey
goto checkconn

:needkey
set KEY=
set SERVER=
if exist enrollment.txt (
  for /f "usebackq tokens=1,* delims==" %%a in ("enrollment.txt") do (
    if /i "%%a"=="KEY" set KEY=%%b
    if /i "%%a"=="SERVER" set SERVER=%%b
  )
)
if defined KEY goto haskey
echo.
echo This PC has no config.json from the MST website yet.
echo  ONE PC  : website - Computers - Add Computers - One PC - Register Computer - Download config.json.
echo            Put config.json in this folder or leave it in Downloads, then run setup-agent.bat again.
echo  MANY PCs: type the enrollment key from the "Many PCs (enrollment key)" tab.
echo.
set /p KEY=Enrollment key (or press Enter to stop): 
if not defined KEY (
  echo Setup stopped. Get config.json or a key from the MST website, then run setup-agent.bat again.
  pause
  exit /b 1
)
:haskey
echo [2/3] Enrolling this PC...
set ENROLLED=
if defined SERVER (
  "%PY%" run_agent.py --enroll "%KEY%" --server "%SERVER%" && set ENROLLED=1
  if not defined ENROLLED echo The server address in enrollment.txt did not work; searching this network instead...
)
if not defined ENROLLED "%PY%" run_agent.py --enroll "%KEY%" && set ENROLLED=1
if not defined ENROLLED (
  echo.
  echo Enrollment failed - see the message above.
  echo Check that this PC is on the same network as the MST server, that the API is running
  echo ^(start-server.bat on the server^) and that the key is still active.
  pause
  exit /b 1
)

:autostart
echo.
echo [3/3] Start the agent
choice /c YN /m "Start the agent automatically when this Windows user signs in"
if errorlevel 2 goto startnow
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-autostart.ps1"
goto done
:startnow
choice /c YN /m "Start the agent now"
if errorlevel 2 goto done
start "MST Monitoring Agent" "%~dp0start-agent.bat"
:done
echo.
echo Setup finished. This PC now appears on the Computers page of the MST website.
pause
