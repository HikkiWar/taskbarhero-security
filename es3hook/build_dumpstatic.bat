@echo off
set VCDIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64
set INCLUDE_BASE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include
set SDK_INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib
set MSVC_LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\lib\x64

for /d %%v in ("%SDK_INCLUDE%\*") do set SDK_VER=%%~nxv
set CLEXE="%VCDIR%\cl.exe"

%CLEXE% /nologo /O2 /EHsc /MD /LD ^
    /I"%INCLUDE_BASE%" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\um" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\shared" ^
    /I"%SDK_INCLUDE%\%SDK_VER%\ucrt" ^
    dumpstatic.cpp ^
    /link ^
    /DLL /OUT:dumpstatic.dll ^
    /LIBPATH:"%MSVC_LIB%" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\um\x64" ^
    /LIBPATH:"%SDK_LIB%\%SDK_VER%\ucrt\x64" ^
    kernel32.lib psapi.lib ucrt.lib vcruntime.lib msvcrt.lib

if errorlevel 1 ( echo [-] dumpstatic FAILED & exit /b 1 )
echo [+] dumpstatic.dll OK

