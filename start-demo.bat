@echo off
title THB Security Demo Server
echo.
echo  ================================================
echo   Taskbar Hero - Security Demo Server
echo  ================================================
echo.
echo  Starting local HTTP server on port 8080...
echo  Report will open in your browser automatically.
echo.
echo  Modes:
echo    /api/vuln/*   - vulnerable mock responses
echo    /api/fixed/*  - protected mock responses
echo    /api/proxy/*  - forward to real backend
echo.
echo  Press Ctrl+C to stop the server.
echo  ================================================
echo.
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0server.ps1"
pause
