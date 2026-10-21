@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0data" mkdir "%~dp0data"
set "FRAMEFLOW_DATA_DIR=%~dp0data"
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":8765 .*LISTENING"') do taskkill /PID %%P /F >nul 2>&1
python -u server.py --host 127.0.0.1 --port 8765 >> "%FRAMEFLOW_DATA_DIR%\frameflow-server.log" 2>&1
pause
