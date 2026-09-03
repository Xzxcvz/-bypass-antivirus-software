import socket, ssl, json

host = 'maxapi112.netlify.app'

def https_req(method, path, body=b"", extra_headers=""):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, 443), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}"
    if body:
        req += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    req += "Connection: close\r\n\r\n"
    req_bytes = req.encode()
    if isinstance(body, str):
        req_bytes += body.encode()
    else:
        req_bytes += body
    ssock.sendall(req_bytes)
    resp = b''
    while True:
        chunk = ssock.recv(4096)
        if not chunk: break
        resp += chunk
    ssock.close()
    return resp

def extract_json(resp_bytes):
    body = resp_bytes.split(b'\r\n\r\n', 1)[1]
    lines = body.split(b'\r\n')
    content_parts = []
    for l in lines:
        if not l.strip():
            continue
        try:
            int(l.strip(), 16)
            continue
        except:
            content_parts.append(l)
    return b''.join(content_parts).decode('utf-8', errors='replace')

# 1. Login
resp = https_req('POST', '/api/auth', json.dumps({"password":"Admin917813"}, separators=(',',':')))
token = json.loads(extract_json(resp))['token']
print(f"Token OK ({token[:30]}...)")

# 2. Test receive with auth
resp = https_req('POST', '/api/receive', json.dumps({"sender":"WindowsUpdate","content":"HELLO|1.2.3.4","type":"info"}, separators=(',',':')), extra_headers=f"Authorization: Bearer {token}\r\n")
print(f"Receive: {extract_json(resp)}")

# 3. Test messages
resp = https_req('GET', '/api/messages', extra_headers=f"Authorization: Bearer {token}\r\n")
print(f"Messages: {extract_json(resp)[:300]}")
