@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Building Beacon.exe ...
python -m PyInstaller --noconfirm --onefile --noconsole --name Beacon --icon app.ico ^
  --add-data "templates;templates" ^
  --add-data "icons;icons" ^
  --collect-all webview --collect-all clr_loader --hidden-import clr ^
  app.py
if errorlevel 1 goto fail
echo.
echo Done. Output: dist\Beacon.exe
pause
exit /b 0
:fail
echo.
echo Build failed.
pause
exit /b 1
