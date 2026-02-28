@echo off
REM Create a minimal valid ICO file for Windows builds
REM This creates a 1x1 pixel blue ICO file

cd /d "%~dp0"

REM Create a minimal valid ICO file (1x1 pixel, blue)
REM ICO format: Header (6 bytes) + Directory (16 bytes) + Image data

powershell -NoProfile -ExecutionPolicy Bypass -Command "
# ICO Header (6 bytes): Reserved(2) + Type(2) + Count(2)
$header = [byte[]]@(0, 0, 1, 0, 1, 0)

# ICO Directory Entry (16 bytes):
# Width(1) + Height(1) + Colors(1) + Reserved(1) + Planes(2) + BitDepth(2) + Size(4) + Offset(4)
$directory = [byte[]]@(1, 1, 0, 0, 1, 0, 32, 0, 70, 0, 0, 0, 22, 0, 0, 0)

# PNG data for 1x1 blue pixel
$pngHeader = [byte[]]@(137, 80, 78, 71, 13, 10, 26, 10)
$pngData = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')

# Combine all parts
$icoData = $header + $directory + $pngData

# Write to file
[IO.File]::WriteAllBytes('icons\icon.ico', $icoData)
Write-Host 'Created: icons\icon.ico'

# Create simple 32x32 PNG (blue square)
$png32 = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAsUlEQVRYR+2XMQ7AIAzFcpF7cJTuO3FTD8rB0W0oKpSkP8V7f4l5gRC+iEeO+d8B3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfcF3BdwX8B9AfMJ/ABud9vL6uJrEAAAAASUVORK5CYII=')
[IO.File]::WriteAllBytes('icons\32x32.png', $png32)
[IO.File]::WriteAllBytes('icons\128x128.png', $png32)
[IO.File]::WriteAllBytes('icons\128x128@2x.png', $png32)
[IO.File]::WriteAllBytes('icons\icon.png', $png32)
[IO.File]::WriteAllBytes('icons\icon.icns', $png32)

Write-Host 'Created: icons\32x32.png'
Write-Host 'Created: icons\128x128.png'
Write-Host 'Created: icons\128x128@2x.png'
Write-Host 'Created: icons\icon.png'
Write-Host 'Created: icons\icon.icns'
Write-Host 'All icon files created successfully!'
"

if errorlevel 1 (
    echo Failed to create icons with PowerShell
    echo Trying alternative method...
    
    REM Alternative: Use certutil to create binary files
    echo Creating minimal files...
    type nul > "icons\icon.ico"
    type nul > "icons\icon.png"
    type nul > "icons\32x32.png"
    type nul > "icons\128x128.png"
    type nul > "icons\128x128@2x.png"
    type nul > "icons\icon.icns"
    echo Created empty placeholder files
)

echo.
echo Icon files should now exist in: %~dp0icons\
echo You can replace these with proper icons later.
pause