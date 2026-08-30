@echo off
REM Build es3hook.dll and injector.exe using MSVC
set VCDIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64
set INCLUDE_BASE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include
set SDK_INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib
set MSVC_LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\lib\x64

REM Find latest SDK version
for /d %%v in ("%SDK_INCLUDE%\*") do set SDK_VER=%%~nxv

set CL="%VCDIR%\cl.exe"
set LINK="%VCDIR%\link.exe"

echo [*] Using SDK version: %SDK_VER%
echo [*] Compiling es3hook.dll...

%CL% /nologo /O2 /EHsc /MD /LD ^
    /I"%INCLUDE_BASE%" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\um" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\shared" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\ucrt" ^
    es3hook.cpp ^
    /link ^
    /DLL /OUT:es3hook.dll ^
    /LIBPATH:"%MSVC_LIB%" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\um\x64" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\ucrt\x64" ^
    kernel32.lib psapi.lib ucrt.lib vcruntime.lib msvcrt.lib

if errorlevel 1 (
    echo [-] DLL build FAILED
) else (
    echo [+] es3hook.dll built successfully
)

echo.
echo [*] Compiling injector.exe...

%CL% /nologo /O2 /EHsc /MD ^
    /I"%INCLUDE_BASE%" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\um" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\shared" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\ucrt" ^
    injector.cpp ^
    /link /OUT:injector.exe ^
    /LIBPATH:"%MSVC_LIB%" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\um\x64" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\ucrt\x64" ^
    kernel32.lib ucrt.lib vcruntime.lib msvcrt.lib

if errorlevel 1 (
    echo [-] injector.exe build FAILED
) else (
    echo [+] injector.exe built successfully
)

echo.
echo Done. Run: injector.exe TaskbarHero.exe
