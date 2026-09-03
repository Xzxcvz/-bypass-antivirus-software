def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
        h = h & 0xFFFFFFFF
    return h

modules = ['NTDLL.DLL', 'KERNEL32.DLL', 'USER32.DLL', 'WS2_32.DLL', 'ADVAPI32.DLL']
for m in modules:
    tag = m.split('.')[0]
    print(f'#define MH_{tag:12s} 0x{djb2(m):08X}')

print()
apis = [
    'WSAStartup', 'WSACleanup', 'socket', 'bind', 'listen', 'accept',
    'closesocket', 'setsockopt', 'recv', 'send', 'shutdown',
    'htonl', 'htons', 'inet_addr', 'connect',
    'LoadLibraryA', 'GetProcAddress', 'GetModuleHandleA', 'VirtualProtect',
    'GetTickCount', 'Sleep', 'GetLastError', 'GetCurrentProcess',
    'GetCurrentThread', 'GetThreadContext', 'SetThreadContext',
    'GetStartupInfoA', 'CreateProcessA', 'CreatePipe', 'CloseHandle',
    'TerminateProcess', 'SetHandleInformation', 'GetTempPathA',
    'CreateFileA', 'WriteFile', 'ReadFile', 'HeapAlloc', 'HeapFree',
    'GetProcessHeap', 'WaitForSingleObject', 'MessageBoxA',
    'VirtualAlloc', 'VirtualFree', 'GetModuleFileNameA',
    'CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW',
    'OpenProcess', 'PeekNamedPipe',
]
for a in apis:
    print(f'#define H_{a:30s} 0x{djb2(a):08X}')
