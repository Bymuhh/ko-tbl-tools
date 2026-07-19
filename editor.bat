@echo off
cd /d "%~dp0"
python "%~dp0tbl_editor.py"
if errorlevel 1 (
  echo.
  echo Hata olustu. Python / Tkinter kurulu mu?
  pause
)
