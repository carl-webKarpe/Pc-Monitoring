@echo off
rem Starts MST on this laptop: the API for the lab PCs (port 8081, all network adapters) and the website.
rem Double-click it in the project folder. Close the two windows it opens to stop MST.
title MST server
cd /d "%~dp0"
where php >nul 2>nul || (echo PHP was not found. Install PHP or add it to PATH, then try again. & pause & exit /b 1)
start "MST API - port 8081 (keep open)" cmd /k php -S 0.0.0.0:8081 backend/public/index.php
start "MST website - port 8000 (keep open)" cmd /k php -S localhost:8000 router.php
echo MST is running.
echo   Website : http://localhost:8000/login.html
echo   API     : http://localhost:8081/api
echo.
echo This laptop's network addresses (lab PCs find the server by themselves; you only need these
echo if a PC asks for the server address):
ipconfig | findstr /c:"IPv4"
echo.
echo If lab PCs cannot connect, allow port 8081 once in PowerShell as Administrator:
echo   New-NetFirewallRule -DisplayName "MST API 8081" -Direction Inbound -Protocol TCP -LocalPort 8081 -Action Allow -Profile Any
timeout /t 2 >nul
start "" http://localhost:8000/login.html
pause
