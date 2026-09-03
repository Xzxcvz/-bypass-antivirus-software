"""Compute djb2 hashes for API function names"""
import sys

def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

if __name__ == "__main__":
    for name in sys.argv[1:]:
        print(f"#define H_{name:<25} 0x{djb2(name):08X}")
