@echo off
set VCDIR=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64
set INC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include
set SDK=C:\Program Files (x86)\Windows Kits\10\Include
set SLIB=C:\Program Files (x86)\Windows Kits\10\Lib
set MLIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\lib\x64
set VER=10.0.22621.0

"%VCDIR%\cl.exe" /nologo /O2 /EHsc /MD /LD ^
    /I"%INC%" ^
    /I"%SDK%\%VER%\um" ^
    /I"%SDK%\%VER%\shared" ^
    /I"%SDK%\%VER%\ucrt" ^
    stagespy.cpp ^
    /link ^
    /DLL /OUT:stagespy3.dll ^
    /LIBPATH:"%MLIB%" ^
    /LIBPATH:"%SLIB%\%VER%\um\x64" ^
    /LIBPATH:"%SLIB%\%VER%\ucrt\x64" ^
    kernel32.lib psapi.lib ucrt.lib vcruntime.lib msvcrt.lib

if errorlevel 1 ( echo [-] FAILED & exit /b 1 )
echo [+] stagespy3.dll OK
