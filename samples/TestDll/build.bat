@echo off
REM Build the test DLL with the MSVC toolchain. Run from an
REM "x64 Native Tools Command Prompt for VS" in this directory.
cl /nologo /LD /O2 /EHsc TestDll.cpp /Fe:phantest.dll /link /IMPLIB:phantest.lib
echo.
echo Built phantest.dll
