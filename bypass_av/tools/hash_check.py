def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

def djb2_up(s):
    h = 5381
    for c in s.upper():
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

print("// Module hashes")
print(f"#define MH_WINHTTP  0x{djb2_up('winhttp.dll'):08X}")

print("\n// WinHTTP func hashes")
funcs = ["WinHttpOpen","WinHttpConnect","WinHttpOpenRequest","WinHttpSetOption",
         "WinHttpSendRequest","WinHttpReceiveResponse","WinHttpReadData","WinHttpCloseHandle",
         "WinHttpQueryDataAvailable"]
for f in funcs:
    print(f"#define H_{f}  0x{djb2(f):08X}")

print("\n// HWID func hashes")
funcs2 = ["GetComputerNameA","GetVolumeInformationA"]
for f in funcs2:
    print(f"#define H_{f}  0x{djb2(f):08X}")
