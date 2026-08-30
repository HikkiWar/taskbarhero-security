@echo off
title THB Token Capture
color 0B
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║       Taskbar Hero — Bearer Token Capture            ║
echo  ║       BACKND API Auth Token Extractor                ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Choose capture method:
echo.
echo  [1] Memory Scan  — scans RAM of the running game
echo      • No game restart needed
echo      • Works while game is active and making requests
echo      • Do something in-game to trigger API calls
echo.
echo  [2] SSL Intercept — MITM proxy on port 443
echo      • Requires game RESTART after this starts
echo      • Captures 100%% of HTTPS requests cleanly
echo      • Needs administrator rights
echo.
echo  [3] Both simultaneously (recommended)
echo.
echo  [0] Exit
echo.
set /p CHOICE="  Your choice [1/2/3/0]: "

if "%CHOICE%"=="0" exit /b
if "%CHOICE%"=="1" goto MEMSCAN
if "%CHOICE%"=="2" goto SSLCAP
if "%CHOICE%"=="3" goto BOTH
goto MENU

:: ─────────────────────────────────────────────────────────────────────────────
:MEMSCAN
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  Method 1: Memory Scan                              ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  [*] Checking game is running...

powershell -NoProfile -Command "if (-not (Get-Process TaskbarHero -ErrorAction SilentlyContinue)) { Write-Host '  [!] TaskbarHero.exe not found! Start the game first.' -ForegroundColor Red; Read-Host 'Press Enter to exit'; exit 1 } else { Write-Host '  [+] Game found: PID ' + (Get-Process TaskbarHero).Id -ForegroundColor Green }"

echo.
echo  [*] Starting memory scanner...
echo      Searching for Bearer token in ASCII and UTF-16LE
echo      Do something in-game to trigger API calls!
echo.
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0scan-memory.ps1"
goto DONE

:: ─────────────────────────────────────────────────────────────────────────────
:SSLCAP
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  Method 2: SSL Interceptor                          ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator rights required for port 443.
    echo  [*] Relaunching as administrator...
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && run-capture.bat' -Verb RunAs"
    exit /b
)

echo  [+] Running as administrator.
echo.
echo  [*] Starting SSL interceptor on port 443...
echo      After it says "Waiting for Bearer token..."
echo      → RESTART THE GAME
echo      → Token will be saved to token.txt
echo.
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0capture-token.ps1"
goto DONE

:: ─────────────────────────────────────────────────────────────────────────────
:BOTH
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  Method 3: Memory Scan + SSL Intercept              ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator required for SSL intercept (port 443).
    echo  [*] Relaunching as administrator...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && run-capture.bat' -Verb RunAs"
    exit /b
)

echo  [+] Running as administrator.
echo.
echo  [*] Starting memory scanner in background window...
start "THB Memory Scanner" pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0scan-memory.ps1"

echo  [*] Starting SSL interceptor in this window...
echo.
echo  INSTRUCTIONS:
echo   1. Memory scanner is running in the other window
echo   2. SSL interceptor will start now
echo   3. Restart the game when prompted
echo   4. Token will appear in BOTH windows if found
echo   5. Saved to: token.txt
echo.
timeout /t 2 /nobreak > nul
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0capture-token.ps1"
goto DONE

:: ─────────────────────────────────────────────────────────────────────────────
:DONE
echo.
if exist "%~dp0token.txt" (
    echo  ════════════════════════════════════════════════════
    echo  Captured token saved to token.txt:
    echo  ════════════════════════════════════════════════════
    type "%~dp0token.txt"
    echo  ════════════════════════════════════════════════════
) else (
    echo  No token captured yet. Try again while the game is active.
)
echo.
pause
