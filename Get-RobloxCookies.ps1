<#
.SYNOPSIS
    Kendi tarayicinda kayitli roblox.com cerezlerini (cookies) disari aktarir.

.DESCRIPTION
    Chromium tabanli tarayicilar (Chrome, Edge, Brave, Opera, Vivaldi) icin profil
    kopyalanip gecici bir user-data-dir uzerinden DevTools Protocol'e baglanilir;
    cerezleri tarayicinin kendisi cozerek verir, bu yuzden App-Bound Encryption
    (v20) dahil hicbir surumde sifreleme engeli yoktur.

    Firefox icin cookies.sqlite dosyalari Windows'un kendi winsqlite3.dll'i ile
    dogrudan okunur (Firefox cerezleri sifrelemez).

    Tarayicinin ACIK olmasi sorun degildir: profil kopyalandigi icin calisan
    oturuma dokunulmaz, ayri bir headless instance ayaga kalkar.

.EXAMPLE
    .\Get-RobloxCookies.ps1

.EXAMPLE
    .\Get-RobloxCookies.ps1 -Browser Chrome -ProfileName "Profile 1" -Save cookies.json

.EXAMPLE
    .\Get-RobloxCookies.ps1 -Raw          # sadece .ROBLOSECURITY degerini yazdirir

.NOTES
    CIKTISI BIR KIMLIK BILGISIDIR. .ROBLOSECURITY'yi ele geciren biri hesaba
    tam erisim saglar. Paylasma, repoya commit'leme, ekran goruntusu alma.
#>

[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi', 'Firefox')]
    [string]$Browser = 'Auto',

    [string]$ProfileName,

    [switch]$AllDomains,

    [string]$Save,

    [switch]$Raw
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try { Add-Type -AssemblyName System.Net.WebSockets.Client -ErrorAction SilentlyContinue } catch { }
if (-not ('System.Net.WebSockets.ClientWebSocket' -as [type])) {
    try { [void][System.Reflection.Assembly]::LoadWithPartialName('System.Net.WebSockets.Client') } catch { }
}
if (-not ('System.Net.WebSockets.ClientWebSocket' -as [type])) {
    throw 'System.Net.WebSockets.Client yuklenemedi. PowerShell 7 (pwsh) ile calistirmayi dene.'
}

#region Yardimci fonksiyonlar

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Copy-LockedFile {
    param([string]$Source, [string]$Destination)

    $dir = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $in = [System.IO.File]::Open($Source, 'Open', 'Read', [System.IO.FileShare]::ReadWrite)
    try {
        $out = [System.IO.File]::Create($Destination)
        try { $in.CopyTo($out) } finally { $out.Dispose() }
    }
    finally { $in.Dispose() }
}

function Stop-BrowserTree {
    param([string]$ProcessName, [string]$Marker)

    Get-CimInstance Win32_Process -Filter "Name = '$ProcessName'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Marker) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Read-WsText {
    param([System.Net.WebSockets.ClientWebSocket]$Socket)

    $stream = [System.IO.MemoryStream]::new()
    $buffer = New-Object byte[] 131072
    $segment = [System.ArraySegment[byte]]::new($buffer)

    do {
        $result = $Socket.ReceiveAsync($segment, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            throw 'DevTools WebSocket baglantisi tarayici tarafindan kapatildi.'
        }
        $stream.Write($buffer, 0, $result.Count)
    } while (-not $result.EndOfMessage)
