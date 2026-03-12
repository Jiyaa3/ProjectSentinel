@echo off
:: build_exe.bat
:: Compiles fake_virus.py into a standalone virus.exe
:: Run this ONCE to generate simulation\virus.exe
::
:: Requirements:
::   pip install pyinstaller
::
:: Usage:
::   Double-click this file OR run in terminal:
::   cd Project_Sentinel
::   build_exe.bat

echo ============================================
echo   Project Sentinel — Building virus.exe
echo ============================================
echo.

:: Install pyinstaller if not present
pip install pyinstaller --quiet

echo [1/3] Compiling fake_virus.py...
pyinstaller --onefile ^
            --noconsole ^
            --name virus ^
            --distpath simulation ^
            simulation\fake_virus.py

echo.
echo [2/3] Cleaning up build files...
rmdir /s /q build
del /q virus.spec

echo.
echo [3/3] Done!
echo.
echo virus.exe is now at: simulation\virus.exe
echo Run "python app.py" and click "Launch Full Attack Demo"
echo.
pause