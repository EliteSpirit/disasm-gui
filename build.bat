@echo off
REM Сборка Disasm GUI в один .exe через PyInstaller.

pip install --upgrade pyinstaller
pip install --upgrade -r requirements.txt

python -m PyInstaller --noconfirm --onefile --windowed --name "DisasmGUI" --collect-all customtkinter --collect-all capstone gui.py

echo.
echo Готово: dist\DisasmGUI.exe
pause
