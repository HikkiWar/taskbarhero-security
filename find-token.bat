@echo off
setlocal
title THB Token Finder
color 0A

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:MENU
cls
echo.
echo  +-----------------------------------------------+
echo  ^|   Taskbar Hero - Dual-Method Token Verifier  ^|
echo  +-----------------------------------------------+
echo  ^|                                               ^|
echo  ^|  [1] FULL  - Restart game + scan             ^|
echo  ^|  [2] QUICK - Scan running game               ^|
echo  ^|  [0] Exit                                    ^|
echo  +-----------------------------------------------+
echo.
set /p CHOICE=  Choice:

if "%CHOICE%"=="0" exit /b
if "%CHOICE%"=="1" goto FULL
if "%CHOICE%"=="2" goto QUICK
goto MENU

:FULL
cls
echo.
echo  [*] Stopping game...
taskkill /IM TaskBarHero.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul

echo  [*] Launching via Steam...
start "" "steam://rungameid/3678970"

echo  [*] Waiting 35 seconds for game to load and authenticate...
timeout /t 35

echo  [*] Scanning for token (120 seconds)...
echo      -- Go to game: open shop, inventory or start a level --
echo.
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0find-token.ps1"
goto END

:QUICK
cls
echo.
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0find-token.ps1" -Quick
goto END

:END
echo.
pause
