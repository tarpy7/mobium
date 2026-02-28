@echo off
REM Simple placeholder icon generator using PowerShell graphics
REM This creates basic colored squares as placeholders

echo Generating placeholder icons...

powershell -Command "Add-Type -AssemblyName System.Drawing; $b=New-Object Drawing.Bitmap(256,256); $g=[Drawing.Graphics]::FromImage($b); $g.Clear([Drawing.Color]::FromArgb(59,130,246)); $g.FillRectangle([Drawing.Brushes]::White, 76, 128, 104, 78); $g.FillRectangle([Drawing.Brushes]::White, 102, 90, 52, 40); $b.Save('icons/icon.png'); $b.Save('icons/128x128.png'); $b.Save('icons/32x32.png'); $b.Save('icons/128x128@2x.png'); Copy-Item 'icons/icon.png' 'icons/icon.icns' -Force; echo 'Icons created successfully!'"

if errorlevel 1 (
    echo ERROR: Failed to generate icons
    echo Make sure PowerShell is available and you have write permissions
    exit /b 1
)

echo.
echo Placeholder icons created in: client\src-tauri\icons\
echo You can replace these with proper icons later.
echo.
pause