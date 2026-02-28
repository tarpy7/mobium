#!/usr/bin/env python3
"""Generate placeholder icons for SecureComm"""

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Installing Pillow...")
    import subprocess
    subprocess.run(["pip", "install", "Pillow"], check=True)
    from PIL import Image, ImageDraw

def create_icon(size, filename):
    """Create a simple blue square icon with a lock symbol"""
    # Create image with blue background
    img = Image.new('RGBA', (size, size), (59, 130, 246, 255))  # #3b82f6
    draw = ImageDraw.Draw(img)
    
    # Draw a simple white lock body (rectangle)
    lock_width = int(size * 0.5)
    lock_height = int(size * 0.35)
    lock_x = (size - lock_width) // 2
    lock_y = (size - lock_height) // 2 + int(size * 0.1)
    
    draw.rectangle(
        [lock_x, lock_y, lock_x + lock_width, lock_y + lock_height],
        fill=(255, 255, 255, 255)
    )
    
    # Draw lock shackle (arc)
    shackle_width = int(lock_width * 0.6)
    shackle_height = int(size * 0.15)
    shackle_x = (size - shackle_width) // 2
    shackle_y = lock_y - shackle_height + 2
    
    draw.rectangle(
        [shackle_x, shackle_y, shackle_x + shackle_width, shackle_y + shackle_height],
        fill=(255, 255, 255, 255)
    )
    
    # Save as PNG
    if filename.endswith('.png'):
        img.save(filename, 'PNG')
    elif filename.endswith('.icns'):
        img.save(filename, 'PNG')  # ICNS format not directly supported, use PNG as placeholder
    
    print(f"Created: {filename} ({size}x{size})")
    return img

def create_ico(filename):
    """Create a multi-size ICO file"""
    sizes = [16, 32, 48, 64, 128, 256]
    images = []
    
    for size in sizes:
        img = Image.new('RGBA', (size, size), (59, 130, 246, 255))
        draw = ImageDraw.Draw(img)
        
        # Draw lock body
        lock_width = int(size * 0.5)
        lock_height = int(size * 0.35)
        lock_x = (size - lock_width) // 2
        lock_y = (size - lock_height) // 2 + int(size * 0.1)
        
        draw.rectangle(
            [lock_x, lock_y, lock_x + lock_width, lock_y + lock_height],
            fill=(255, 255, 255, 255)
        )
        
        # Draw shackle
        shackle_width = int(lock_width * 0.6)
        shackle_height = int(size * 0.15)
        shackle_x = (size - shackle_width) // 2
        shackle_y = lock_y - shackle_height + 2
        
        draw.rectangle(
            [shackle_x, shackle_y, shackle_x + shackle_width, shackle_y + shackle_height],
            fill=(255, 255, 255, 255)
        )
        
        images.append(img)
    
    # Save as ICO
    images[0].save(filename, format='ICO', sizes=[(s, s) for s in sizes], append_images=images[1:])
    print(f"Created: {filename} (multi-size ICO)")

if __name__ == "__main__":
    import os
    
    # Create icons directory if it doesn't exist
    os.makedirs("icons", exist_ok=True)
    
    print("Generating placeholder icons for SecureComm...")
    print()
    
    # Create individual PNG files
    create_icon(32, "icons/32x32.png")
    create_icon(128, "icons/128x128.png")
    create_icon(256, "icons/128x128@2x.png")
    create_icon(256, "icons/icon.png")
    create_icon(256, "icons/icon.icns")  # macOS placeholder
    
    # Create multi-size ICO file
    create_ico("icons/icon.ico")
    
    print()
    print("All icon files created successfully!")
    print("These are placeholder icons - replace with proper icons before production.")
    print()
    print("To verify the ICO file is valid, check its size:")
    import os
    ico_size = os.path.getsize("icons/icon.ico")
    print(f"  icon.ico size: {ico_size} bytes")