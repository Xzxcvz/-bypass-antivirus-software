# payload.exe — 完整逆向重构

原始文件：`payload.exe`（本地样本，见 SHA256）  
SHA256：`4e6e8393a421e0a42d75411ecc77c58d4720620f6f19508c12633b091e997907`  
大小：7168 字节  
架构：x86 PE32 (Windows GUI)

## 文件清单

| 文件 | 说明 |
|------|------|
| `payload_reconstructed.c` | 高级 C 语言重构 — 使用标准 Win32 API 实现相同功能，适合阅读 |
| `payload_shellcode.c` | 低级 C 语言重构 — 使用 PEB 遍历 + ROR-13 哈希查找，**匹配原始 shellcode 算法** |
| `payload_shellcode.asm` | 汇编级重构 — 逐指令翻译原始 .zsrp 节字节码 |
| `build.bat` | MSVC 构建脚本 |

## 原始 PE 结构映射

```
偏移量      节          内容
0x000-0x3FF DOS头/PE头  MZ + PE 签名 + Rich 头
0x400-0x5FF .text       VirtualProtect 存根 (40 字节)
0x600-0x7FF .rdata      导入表 (KERNEL32.dll:VirtualProtect)
0x800-0x17FF.data       数据 (RW)
0x1800-0x19FF.reloc     基址重定位
0x1A00-0x1BFF .zsrp     实际 shellcode (入口点 @ RVA 0x5000)
```

## 分析摘要

**类型**：反向 Shell 恶意软件  
**C2 服务器**：`192.168.30.15:4444` (TCP)  
**协议**：TCP (WinSock)  
**编译时间**：2025-08-29

### 执行流程

1. `.text` 存根调用 `VirtualProtect(PAGE_EXECUTE_READWRITE)` 修改 `.zsrp` 内存保护
2. 跳转到 `.zsrp` shellcode
3. Shellcode 通过 PEB 遍历定位 kernel32.dll
4. 使用 ROR-13 哈希算法动态解析 API（无静态导入）
5. 加载 `ws2_32.dll`，初始化 WinSock
6. 创建 TCP socket → 连接 `192.168.30.15:4444`
7. 连接失败时递减端口号重试
8. 成功后创建 `cmd.exe`，stdin/stdout/stderr 重定向到 socket

### 关键 ROR-13 哈希值

| 哈希值 | 函数 | 原始偏移 |
|--------|------|----------|
| `0x0726774C` | LoadLibraryA | 0xA1 |
| `0x006B8029` | WSAStartup | 0xB3 |
| `0xE0DF0FEA` | WSASocketA | 0xD0 |
| `0x6174A599` | connect | 0xDC |
| `0x5FC8D902` | CreateProcessA | 0xF7 |

---

**警告**：此代码仅用于教育和研究目的。请勿在未经授权的系统上运行。
