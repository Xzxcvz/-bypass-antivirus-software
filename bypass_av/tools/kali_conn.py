#!/usr/bin/env python3
import socket, sys, threading, os
os.system("clear" if os.name != "nt" else "cls")
s=socket.socket()
s.connect(('192.168.30.17',54321))
def recv_loop():
    while True:
        try:
            d=s.recv(4096)
            if not d: break
            sys.stdout.buffer.write(d)
            sys.stdout.flush()
        except: break
threading.Thread(target=recv_loop,daemon=True).start()
while True:
    try:
        d=sys.stdin.buffer.read(4096)
        if not d: break
        s.sendall(d)
    except: break
s.close()
