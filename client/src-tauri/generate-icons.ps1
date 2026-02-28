# Generate Placeholder Icons for SecureComm
# Run this script with: powershell -ExecutionPolicy Bypass -File generate-icons.ps1

Add-Type -AssemblyName System.Drawing

# Create output directory
$iconDir = "$PSScriptRoot\icons"
if (!(Test-Path $iconDir)) {
    New-Item -ItemType Directory -Path $iconDir -Force
}

# Function to create a simple colored square icon
function Create-Icon {
    param(
        [int]$size,
        [string]$outputPath
    )
    
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    
    # Fill with blue background (#3b82f6 - primary color)
    $graphics.Clear([System.Drawing.Color]::FromArgb(59, 130, 246))
    
    # Draw a simple lock symbol (white rectangle with keyhole)
    $whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $lockWidth = [int]($size * 0.4)
    $lockHeight = [int]($size * 0.3)
    $lockX = ($size - $lockWidth) / 2
    $lockY = ($size - $lockHeight) / 2 + [int]($size * 0.1)
    
    $graphics.FillRectangle($whiteBrush, $lockX, $lockY, $lockWidth, $lockHeight)
    
    # Draw lock shackle
    $shackleWidth = [int]($lockWidth * 0.6)
    $shackleHeight = [int]($size * 0.15)
    $shackleX = ($size - $shackleWidth) / 2
    $shackleY = $lockY - $shackleHeight + 2
    
    $graphics.FillRectangle($whiteBrush, $shackleX, $shackleY, $shackleWidth, $shackleHeight)
    
    # Save as PNG
    $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    
    $graphics.Dispose()
    $bitmap.Dispose()
    $whiteBrush.Dispose()
    
    Write-Host "Created: $outputPath ($size x $size)"
}

# Generate PNG icons
Write-Host "Generating placeholder icons..." -ForegroundColor Green

Create-Icon -size 32 -outputPath "$iconDir\32x32.png"
Create-Icon -size 128 -outputPath "$iconDir\128x128.png"
Create-Icon -size 256 -outputPath "$iconDir\128x128@2x.png"
Create-Icon -size 512 -outputPath "$iconDir\icon.png"

# Create ICO file from the 256x256 version
$sourceBitmap = [System.Drawing.Image]::FromFile("$iconDir\128x128@2x.png")
$bitmap256 = New-Object System.Drawing.Bitmap(256, 256)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap256)
$graphics.DrawImage($sourceBitmap, 0, 0, 256, 256)

# Save as ICO
$iconStream = [System.IO.MemoryStream]::new()
$bitmap256.Save($iconStream, [System.Drawing.Imaging.ImageFormat]::Png)
$iconBytes = $iconStream.ToArray()

# ICO header
$icoHeader = [byte[]]@(0, 0, 1, 0, 1, 0, 32, 32, 0, 0, 1, 0, 32, 0)
$icoDirectory = [byte[]]@(40, 0, 0, 0, 32, 0, 0, 0, 64, 0, 0, 0, 1, 0, 32, 0, 0, 0, 0, 0)
$imageSizeBytes = [BitConverter]::GetBytes([int32]$iconBytes.Length)
$imageOffsetBytes = [BitConverter]::GetBytes([int32](22))

$icoFile = $icoHeader + $icoDirectory + $imageSizeBytes + $imageOffsetBytes + $iconBytes
[IO.File]::WriteAllBytes("$iconDir\icon.ico", $icoFile)

Write-Host "Created: $iconDir\icon.ico (256 x 256)" -ForegroundColor Green

$graphics.Dispose()
$bitmap256.Dispose()
$sourceBitmap.Dispose()
$iconStream.Dispose()

# Create a simple placeholder for macOS icon (icns)
# For now, just copy the PNG
Copy-Item "$iconDir\icon.png" "$iconDir\icon.icns" -Force
Write-Host "Created: $iconDir\icon.icns (placeholder)" -ForegroundColor Green

Write-Host "`nAll placeholder icons generated successfully!" -ForegroundColor Green
Write-Host "You can replace these with proper icons later." -ForegroundColor Yellow