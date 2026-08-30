@echo off
title THB Security Demo
color 0A
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║       Taskbar Hero — Security Research Demo          ║
echo  ║       BACKND BaaS Vulnerability Showcase             ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  [*] Checking if server is already running...

powershell -NoProfile -Command "try { $r = Invoke-WebRequest http://localhost:8080/api/status -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop; Write-Host '  [+] Server already running' -ForegroundColor Green } catch { Write-Host '  [-] Server not running, starting...' -ForegroundColor Yellow }"

powershell -NoProfile -Command "try { Invoke-WebRequest http://localhost:8080/api/status -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop | Out-Null } catch { Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -NoExit -File ""%~dp0server.ps1""' -WindowStyle Normal }"

echo.
echo  [*] Waiting for server to start...
timeout /t 3 /nobreak > nul

echo  [*] Opening security report in browser...
start "" http://localhost:8080/security-report.html

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║  Demo server: http://localhost:8080                  ║
echo  ║  Report:      http://localhost:8080/security-report  ║
echo  ║                                                      ║
echo  ║  API endpoints:                                      ║
echo  ║    /api/vuln/*   - vulnerable responses              ║
echo  ║    /api/fixed/*  - hardened responses                ║
echo  ║    /api/status   - server health                     ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Close this window to stop the demo server.
echo  Press any key to exit without stopping the server.
echo.
pause > nul
