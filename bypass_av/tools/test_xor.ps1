# XOR remoting test
$key = @(0x42,0x7A,0x1F,0xE3,0x9C,0x55,0xB0,0x2D)
function xor-buf { param([byte[]]$b) for($i=0;$i -lt $b.Length;$i++){ $b[$i] = $b[$i] -bxor $key[$i % $key.Length] } }

$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1',54321)
$s = $c.GetStream()
$d = [Text.Encoding]::ASCII.GetBytes("whoami`necho __C2DONE__`n")
Write-Host "Sending $($d.Length) bytes: $([Text.Encoding]::ASCII.GetString($d))"
xor-buf $d
$s.Write($d, 0, $d.Length)
Start-Sleep 3
$b = New-Object byte[] 4096
$n = $s.Read($b, 0, 4096)
Write-Host "Received $n bytes"
xor-buf $b
Write-Host "Decrypted hex: $([System.BitConverter]::ToString($b,0,[Math]::Min(60,$n)))"
Write-Host "Text: $([Text.Encoding]::ASCII.GetString($b,0,$n))"
$c.Close()
