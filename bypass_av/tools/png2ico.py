#!/usr/bin/env python3
"""
png2ico.py — wrap a PNG inside an ICO container (works on Windows Vista+).

Usage:
    python png2ico.py <input.png> [output.ico]
    python png2ico.py path/to/Newico.png path/to/app.ico
"""
import struct, os, sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python png2ico.py <input.png> [output.ico]")
        sys.exit(1)

    png_path = sys.argv[1]
    if len(sys.argv) >= 3:
        ico_path = sys.argv[2]
    else:
        base = os.path.splitext(png_path)[0]
        ico_path = base + ".ico"

    with open(png_path, 'rb') as f:
        png_data = f.read()

    # Read PNG dimensions from IHDR chunk
    w = struct.unpack('>I', png_data[16:20])[0]
    h = struct.unpack('>I', png_data[20:24])[0]

    count = 1
    header = struct.pack('<HHH', 0, 1, count)  # reserved, type=1(ico), count

    # Directory entry: width, height, 0 colors, 0 reserved, 1 plane, 32 bpp
    entry = struct.pack('<BBBBHHII',
        w if w < 256 else 0, h if h < 256 else 0,
        0, 0, 1, 32,
        len(png_data), 6 + count * 16)

    with open(ico_path, 'wb') as f:
        f.write(header)
        f.write(entry)
        f.write(png_data)

    print(f"Converted {png_path} -> {ico_path}")
    print(f"Size: {w}x{h}, ICO size: {os.path.getsize(ico_path)} bytes")

if __name__ == "__main__":
    main()
