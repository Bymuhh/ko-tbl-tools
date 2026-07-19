@echo off
cd /d "%~dp0"
python "%~dp0tbl_crypto.py" %*
if errorlevel 1 pause
