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

    return [System.Text.Encoding]::UTF8.GetString($stream.ToArray())
}

function Invoke-Cdp {
    param([System.Net.WebSockets.ClientWebSocket]$Socket, [int]$Id, [string]$Method)

    $payload = @{ id = $Id; method = $Method } | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $Socket.SendAsync([System.ArraySegment[byte]]::new($bytes),
                      [System.Net.WebSockets.WebSocketMessageType]::Text, $true,
                      [System.Threading.CancellationToken]::None).GetAwaiter().GetResult() | Out-Null

    while ($true) {
        $message = Read-WsText $Socket | ConvertFrom-Json
        if ($message.PSObject.Properties['id'] -and $message.id -eq $Id) {
            if ($message.PSObject.Properties['error']) { return $null }
            return $message.result
        }
    }
}

function New-CookieObject {
    param([string]$BrowserName, [string]$Profile, $Raw)

    $expires = $null
    if ($Raw.PSObject.Properties.Match('expires').Count -gt 0 -and $Raw.expires -gt 0) {
        $expires = [System.DateTimeOffset]::FromUnixTimeMilliseconds([long]($Raw.expires * 1000)).LocalDateTime
    }

    $path = '/'
    if ($Raw.PSObject.Properties.Match('path').Count -gt 0 -and $Raw.path) { $path = $Raw.path }

    [pscustomobject]@{
        Browser  = $BrowserName
        Profile  = $Profile
        Name     = $Raw.name
        Value    = $Raw.value
        Domain   = $Raw.domain
        Path     = $path
        Expires  = $expires
        HttpOnly = [bool]$Raw.httpOnly
        Secure   = [bool]$Raw.secure
    }
}

function Test-RobloxDomain {
    param([string]$Domain)

    if ($AllDomains) { return $true }
    $d = $Domain.TrimStart('.').ToLowerInvariant()
    return ($d -eq 'roblox.com' -or $d.EndsWith('.roblox.com'))
}

#endregion

#region Chromium: profil kopyala + DevTools Protocol

function Get-ChromiumCookies {
    param($Definition, [string]$ExePath, [string]$UserDataDir, [string]$ProfileDir)

    $leaf = if ($ProfileDir.Length -gt $UserDataDir.Length) {
        $ProfileDir.Substring($UserDataDir.Length).Trim('\')
    } else { '' }

    # Chrome 136+ varsayilan user-data-dir uzerinde remote debugging'i kapatiyor.
    # Bu yuzden profil gecici bir dizine kopyalanip oradan aciliyor.
    $temp = Join-Path $env:TEMP ("qcdp-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $temp 'Default\Network') -Force | Out-Null

    try {
        foreach ($candidate in @((Join-Path $UserDataDir 'Local State'),
                                 (Join-Path (Split-Path -Parent $UserDataDir) 'Local State'))) {
            if (Test-Path -LiteralPath $candidate) { Copy-LockedFile $candidate (Join-Path $temp 'Local State'); break }
        }

        $prefs = Join-Path $ProfileDir 'Preferences'
        if (Test-Path -LiteralPath $prefs) { Copy-LockedFile $prefs (Join-Path $temp 'Default\Preferences') }

        $cookieDb = Join-Path $ProfileDir 'Network\Cookies'
        if (-not (Test-Path -LiteralPath $cookieDb)) { throw "Cerez veritabani bulunamadi: $cookieDb" }
        Copy-LockedFile $cookieDb (Join-Path $temp 'Default\Network\Cookies')
        foreach ($suffix in @('-journal', '-wal', '-shm')) {
            $side = "$cookieDb$suffix"
            if (Test-Path -LiteralPath $side) { Copy-LockedFile $side (Join-Path $temp "Default\Network\Cookies$suffix") }
        }

        $port = Get-FreeTcpPort
        $found = $null

        foreach ($headless in @('--headless=new', '--headless')) {
            $arguments = @(
                $headless
                "--user-data-dir=$temp"
                "--remote-debugging-port=$port"
                '--remote-allow-origins=*'
                '--no-first-run'
                '--no-default-browser-check'
                '--disable-gpu'
                '--disable-extensions'
                '--disable-background-networking'
                '--disable-sync'
                '--disable-session-crashed-bubble'
                '--hide-crash-restore-bubble'
                '--mute-audio'
                'about:blank'
            )

            Start-Process -FilePath $ExePath -ArgumentList $arguments -WindowStyle Hidden | Out-Null

            $version = $null
            $deadline = (Get-Date).AddSeconds(25)
            while ((Get-Date) -lt $deadline -and -not $version) {
                Start-Sleep -Milliseconds 400
                try {
                    $version = Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/version" -TimeoutSec 3
                } catch { $version = $null }
            }

            if (-not $version) {
                Stop-BrowserTree $Definition.Proc $temp
                Start-Sleep -Milliseconds 500
                continue
            }

            try {
                $socket = [System.Net.WebSockets.ClientWebSocket]::new()
                $socket.ConnectAsync([Uri]$version.webSocketDebuggerUrl,
                                     [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

                $result = Invoke-Cdp $socket 1 'Storage.getCookies'
                $rawCookies = $null
                if ($result -and $result.PSObject.Properties['cookies']) { $rawCookies = $result.cookies }

                if (-not $rawCookies) {
                    # Browser seviyesi desteklenmezse sayfa hedefine dus.
                    $targets = Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/list" -TimeoutSec 5 |
                               Where-Object { $_.type -eq 'page' } | Select-Object -First 1
                    if ($targets) {
                        $socket.Dispose()
                        $socket = [System.Net.WebSockets.ClientWebSocket]::new()
                        $socket.ConnectAsync([Uri]$targets.webSocketDebuggerUrl,
                                             [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
                        $result = Invoke-Cdp $socket 1 'Network.getAllCookies'
                        if ($result -and $result.PSObject.Properties['cookies']) { $rawCookies = $result.cookies }
                    }
                }

                $socket.Dispose()
            }
            finally {
                Stop-BrowserTree $Definition.Proc $temp
            }

            if ($rawCookies) {
                $label = if ($leaf) { $leaf } else { $Definition.Name }
                $found = @($rawCookies | Where-Object { Test-RobloxDomain $_.domain } |
                           ForEach-Object { New-CookieObject $Definition.Name $label $_ })
                break
            }
        }

        if ($null -eq $found) {
            throw 'DevTools yanit vermedi veya cerez listesi bos dondu.'
        }
        return $found
    }
    finally {
        Stop-BrowserTree $Definition.Proc $temp
        Start-Sleep -Milliseconds 300
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region Firefox: winsqlite3.dll uzerinden cookies.sqlite

function Add-WinSqliteType {
    if ('WinSqliteReader' -as [type]) { return }
    if (-not (Test-Path "$env:SystemRoot\System32\winsqlite3.dll")) {
        throw 'winsqlite3.dll bulunamadi (Windows 10+ gerekir).'
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class WinSqliteReader
{
    private const string Dll = "winsqlite3.dll";
    private const int SqliteOk = 0;
    private const int SqliteRow = 100;
    private const int OpenReadOnly = 1;

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nBytes, out IntPtr stmt, IntPtr tail);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr stmt);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_column_count(IntPtr stmt);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_name(IntPtr stmt, int col);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close_v2(IntPtr db);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_errmsg(IntPtr db);

    private static string Utf8(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero) return null;
        int len = 0;
        while (Marshal.ReadByte(ptr, len) != 0) len++;
        byte[] buffer = new byte[len];
        Marshal.Copy(ptr, buffer, 0, len);
        return Encoding.UTF8.GetString(buffer);
    }

    public static List<Dictionary<string, string>> Query(string path, string sql)
    {
        IntPtr db;
        int rc = sqlite3_open_v2(Encoding.UTF8.GetBytes(path + "\0"), out db, OpenReadOnly, IntPtr.Zero);
        if (rc != SqliteOk) throw new Exception("sqlite3_open: " + Utf8(sqlite3_errmsg(db)));
        try
        {
            IntPtr stmt;
            rc = sqlite3_prepare_v2(db, Encoding.UTF8.GetBytes(sql + "\0"), -1, out stmt, IntPtr.Zero);
            if (rc != SqliteOk) throw new Exception("sqlite3_prepare: " + Utf8(sqlite3_errmsg(db)));
            try
            {
                var rows = new List<Dictionary<string, string>>();
                int count = sqlite3_column_count(stmt);
                while (sqlite3_step(stmt) == SqliteRow)
                {
                    var row = new Dictionary<string, string>();
                    for (int i = 0; i < count; i++) row[Utf8(sqlite3_column_name(stmt, i))] = Utf8(sqlite3_column_text(stmt, i));
                    rows.Add(row);
                }
                return rows;
            }
            finally { sqlite3_finalize(stmt); }
        }
        finally { sqlite3_close_v2(db); }
    }
}
'@
}

function Get-FirefoxCookies {
    param([string]$ProfilePath)

    Add-WinSqliteType

    $db = Join-Path $ProfilePath 'cookies.sqlite'
    if (-not (Test-Path -LiteralPath $db)) { throw "cookies.sqlite yok: $db" }

    $temp = Join-Path $env:TEMP ("qff-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        Copy-LockedFile $db (Join-Path $temp 'cookies.sqlite')
        foreach ($suffix in @('-wal', '-shm')) {
            $side = "$db$suffix"
            if (Test-Path -LiteralPath $side) { Copy-LockedFile $side (Join-Path $temp "cookies.sqlite$suffix") }
        }

        $rows = [WinSqliteReader]::Query((Join-Path $temp 'cookies.sqlite'),
            'SELECT name, value, host, path, expiry, isSecure, isHttpOnly FROM moz_cookies')

        $leaf = Split-Path -Leaf $ProfilePath
        return @($rows |
            Where-Object { Test-RobloxDomain $_['host'] } |
            ForEach-Object {
                $expires = $null
                $exp = 0L
                if ([long]::TryParse($_['expiry'], [ref]$exp) -and $exp -gt 0) {
                    $expires = [System.DateTimeOffset]::FromUnixTimeSeconds($exp).LocalDateTime
                }
                [pscustomobject]@{
                    Browser  = 'Firefox'
                    Profile  = $leaf
                    Name     = $_['name']
                    Value    = $_['value']
                    Domain   = $_['host']
                    Path     = $_['path']
                    Expires  = $expires
                    HttpOnly = $_['isHttpOnly'] -eq '1'
                    Secure   = $_['isSecure'] -eq '1'
                }
            })
    }
    finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-FirefoxProfiles {
    $roots = @("$env:AppData\Mozilla\Firefox\Profiles")
    $ini = "$env:AppData\Mozilla\Firefox\profiles.ini"
    $profiles = @()

    if (Test-Path -LiteralPath $ini) {
        $current = @{}
        foreach ($line in Get-Content -LiteralPath $ini) {
            if ($line -match '^\s*\[') {
                if ($current.ContainsKey('Path')) { $profiles += $current }
                $current = @{}
            } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)$') {
                $current[$Matches[1]] = $Matches[2]
            }
        }
        if ($current.ContainsKey('Path')) { $profiles += $current }
    }

    $result = @()
    foreach ($p in $profiles) {
        $path = if ($p['IsRelative'] -eq '0') { $p['Path'] } else { Join-Path "$env:AppData\Mozilla\Firefox" $p['Path'] }
        $path = $path -replace '/', '\'
        if ((Test-Path -LiteralPath (Join-Path $path 'cookies.sqlite'))) {
            $result += [pscustomobject]@{ Name = (Split-Path -Leaf $path); Path = $path }
        }
    }

    if (-not $result) {
        foreach ($root in $roots) {
            if (Test-Path -LiteralPath $root) {
                $result += @(Get-ChildItem -LiteralPath $root -Directory |
                    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'cookies.sqlite') } |
                    ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.FullName } })
            }
        }
    }

    return $result
}

#endregion

#region Tarayici tanimlari ve calisma akisi

$ChromiumBrowsers = @(
    [pscustomobject]@{
        Name = 'Chrome'; Proc = 'chrome.exe'
        Exe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
                "$env:LocalAppData\Google\Chrome\Application\chrome.exe")
        UserData = @("$env:LocalAppData\Google\Chrome\User Data")
    }
    [pscustomobject]@{
        Name = 'Edge'; Proc = 'msedge.exe'
        Exe = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
        UserData = @("$env:LocalAppData\Microsoft\Edge\User Data")
    }
    [pscustomobject]@{
        Name = 'Brave'; Proc = 'brave.exe'
        Exe = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
                "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
                "$env:LocalAppData\BraveSoftware\Brave-Browser\Application\brave.exe")
        UserData = @("$env:LocalAppData\BraveSoftware\Brave-Browser\User Data")
    }
    [pscustomobject]@{
        Name = 'Vivaldi'; Proc = 'vivaldi.exe'
        Exe = @("$env:LocalAppData\Vivaldi\Application\vivaldi.exe",
                "$env:ProgramFiles\Vivaldi\Application\vivaldi.exe")
        UserData = @("$env:LocalAppData\Vivaldi\User Data")
    }
    [pscustomobject]@{
        Name = 'Opera'; Proc = 'opera.exe'
        Exe = @("$env:LocalAppData\Programs\Opera\opera.exe",
                "$env:LocalAppData\Programs\Opera\launcher.exe",
                "$env:ProgramFiles\Opera\opera.exe",
                "$env:ProgramFiles\Opera\launcher.exe")
        UserData = @("$env:AppData\Opera Software\Opera Stable",
                     "$env:AppData\Opera Software\Opera GX Stable",
                     "$env:AppData\Opera Software\Opera Developer")
    }
)

function Get-ChromiumProfiles {
    param([string]$UserDataDir)

    $found = @()
    if (Test-Path -LiteralPath (Join-Path $UserDataDir 'Network\Cookies')) { $found += $UserDataDir }

    $candidates = @(Get-ChildItem -LiteralPath $UserDataDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })

    foreach ($dir in $candidates) {
        $new = Join-Path $dir.FullName 'Network\Cookies'
        $old = Join-Path $dir.FullName 'Cookies'
        if ((Test-Path -LiteralPath $new) -or (Test-Path -LiteralPath $old)) { $found += $dir.FullName }
    }

    return @($found | Select-Object -Unique)
}

$all = @()
$wantFirefox = ($Browser -eq 'Auto' -or $Browser -eq 'Firefox')
$chromiumTargets = if ($Browser -eq 'Auto' -or $Browser -eq 'Firefox') {
    if ($Browser -eq 'Firefox') { @() } else { $ChromiumBrowsers }
} else {
    @($ChromiumBrowsers | Where-Object { $_.Name -eq $Browser })
}

foreach ($definition in $chromiumTargets) {
    $exe = $definition.Exe | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $exe) { continue }

    foreach ($udd in $definition.UserData) {
        if (-not $udd -or -not (Test-Path -LiteralPath $udd)) { continue }

        foreach ($profileDir in (Get-ChromiumProfiles $udd)) {
            $leaf = if ($profileDir.Length -gt $udd.Length) { $profileDir.Substring($udd.Length).Trim('\') } else { $definition.Name }
            if ($ProfileName -and $leaf -ne $ProfileName) { continue }

            Write-Host "[$($definition.Name) / $leaf] DevTools ile okunuyor..." -ForegroundColor DarkCyan
            try {
                $all += @(Get-ChromiumCookies $definition $exe $udd $profileDir)
            } catch {
                Write-Warning "[$($definition.Name) / $leaf] basarisiz: $($_.Exception.Message)"
            }
        }
    }
}

if ($wantFirefox) {
    foreach ($profile in @(Get-FirefoxProfiles)) {
        if ($ProfileName -and $profile.Name -ne $ProfileName) { continue }

        Write-Host "[Firefox / $($profile.Name)] cookies.sqlite okunuyor..." -ForegroundColor DarkCyan
        try {
            $all += @(Get-FirefoxCookies $profile.Path)
        } catch {
            Write-Warning "[Firefox / $($profile.Name)] basarisiz: $($_.Exception.Message)"
        }
    }
}

$all = @($all | Sort-Object Browser, Profile, Domain, Name -Unique)

if (-not $all.Count) {
    Write-Warning 'Hic cerez bulunamadi. Tarayici kurulu degil, profil bos veya Roblox oturumu acilmamis olabilir.'
    return
}

if ($Raw) {
    $token = $all | Where-Object { $_.Name -eq '.ROBLOSECURITY' } | Select-Object -First 1
    if ($token) { Write-Output $token.Value } else { Write-Warning '.ROBLOSECURITY bulunamadi.' }
    return
}

Write-Host ''
$all | Format-Table Browser, Profile, Name, Domain, Expires, HttpOnly, Secure -AutoSize
Write-Host ("Toplam {0} cerez. Degerleri gormek icin: `$all | Format-List Name, Value" -f $all.Count) -ForegroundColor DarkGray

$security = $all | Where-Object { $_.Name -eq '.ROBLOSECURITY' }
if ($security) {
    Write-Host ''
    foreach ($token in $security) {
        $preview = if ($token.Value.Length -gt 24) { $token.Value.Substring(0, 24) + '...' } else { $token.Value }
        Write-Host ("{0} / {1} -> .ROBLOSECURITY = {2}" -f $token.Browser, $token.Profile, $preview) -ForegroundColor Green
    }
}

if ($Save) {
    $all | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Save -Encoding UTF8
    Write-Host "Kaydedildi: $Save" -ForegroundColor Green
}

Write-Host ''
Write-Warning 'Bu cikti bir kimlik bilgisidir. .ROBLOSECURITY hesaba tam erisim saglar; paylasma veya commit etme.'

#endregion
