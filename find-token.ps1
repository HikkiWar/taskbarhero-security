# find-token.ps1  v3 — Taskbar Hero / BACKND SDK security audit
# Method 1: Decrypt backend.dat (AES-128-CBC, key = signatureKey[0:16])
# Method 2: Blind UTF-16 scan of managed .NET heap for 64-char hex tokens
# Validates BACKND access_token against api.thebackend.io

param([switch]$Quick, [switch]$Server)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$dir   = $PSScriptRoot
$qsDll = Join-Path $dir "QuickScan.dll"
$out   = Join-Path $dir "token.txt"
try { Add-Type -Path $qsDll -EA Stop } catch {}

$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"  # from resources.assets
$SDK_VERSION   = "5.18.11"
$BACKEND_DAT   = "C:\Users\Gigabyte\AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat"
$RESOLVE_IP    = "43.200.166.97"
$API_BASE      = "https://api.thebackend.io"
$AES_KEY       = [byte[]]([Text.Encoding]::UTF8.GetBytes($SIGNATURE_KEY)[0..15])

function Step([string]$msg, [string]$col = "Cyan") { Write-Host "  $msg" -ForegroundColor $col }

# ── AES-128 CBC Zeros decryption ─────────────────────────────────────────────
function Decrypt-BackendDat([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try {
        $enc = [IO.File]::ReadAllBytes($path)
        $aes = [Security.Cryptography.RijndaelManaged]::new()
        $aes.KeySize   = 128; $aes.BlockSize = 128
        $aes.Mode      = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [Security.Cryptography.PaddingMode]::Zeros
        $aes.Key = $AES_KEY; $aes.IV = $AES_KEY
        $dec     = $aes.CreateDecryptor()
        $plain   = $dec.TransformFinalBlock($enc, 0, $enc.Length)
        $text    = [Text.Encoding]::ASCII.GetString($plain)
        $matches = [regex]::Matches($text, '[0-9a-f]{64}')
        if ($matches.Count -ge 2) {
            return [PSCustomObject]@{
                AccessToken  = $matches[0].Value
                RefreshToken = $matches[1].Value
                PlainText    = $text
            }
        }
    } catch {}
    return $null
}

# ── Memory scan (UTF-16LE, all readable non-image pages) ─────────────────────
Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class HexScan {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool b, int p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, int s, out int r);
    [DllImport("kernel32.dll")] static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, int s);
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr B, AB; public uint AP, pd; public IntPtr Sz; public uint St, Pr, Ty; }
    static bool Rd(uint p){p&=0xFF;return p==2||p==4||p==0x20||p==0x40||p==8||p==0x80;}
    static bool IsHex(byte b){return(b>=48&&b<=57)||(b>=97&&b<=102)||(b>=65&&b<=70);}
    public static List<string> ScanUtf16(int pid){
        var res = new HashSet<string>();
        IntPtr h = OpenProcess(0x0410, false, pid);
        if(h==IntPtr.Zero) return new List<string>(res);
        const int C=4*1024*1024;
        byte[] buf=new byte[C];
        long addr=0;
        while(addr<0x7FFFFFFFFFFF){
            MBI mi;
            if(VirtualQueryEx(h,(IntPtr)addr,out mi,Marshal.SizeOf(typeof(MBI)))==0) break;
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
                        if(cnt==64){
                            var sb=new StringBuilder();
                            for(int k=0;k<64;k++) sb.Append((char)buf[i+k*2]);
                            res.Add(sb.ToString().ToLower());
                            i+=128;
                        }
                    }
                }
            }
            addr+=rz;
        }
        CloseHandle(h);
        return new List<string>(res);
    }
}
'@ -Language CSharp -EA SilentlyContinue

# ── API test ──────────────────────────────────────────────────────────────────
function Test-BackndToken([string]$tok, [string]$endpoint = "/data/isAliveToken", [string]$method = "GET") {
    $date = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
    $a = @(
        "--resolve", "api.thebackend.io:443:$RESOLVE_IP",
        "--silent", "--max-time", "10", "-X", $method,
        "--header", "Content-Type: application/json",
        "--header", "access_token: $tok",
        "--header", "client_app_id: $CLIENT_APP_ID",
        "--header", "sdk_version: $SDK_VERSION",
        "--header", "client_date: $date",
        "--header", "os_version: Windows 11",
        "--header", "device: PC",
        "--user-agent", "UnityPlayer/6000.0.72f1",
        "--write-out", "`n===CODE:%{http_code}===", "--output", "-",
        "$API_BASE$endpoint"
    )
    $raw  = (& curl.exe @a 2>&1) -join "`n"
    $code = 0; if ($raw -match '===CODE:(\d+)===') { $code = [int]$Matches[1] }
    $body = ($raw -replace '===CODE:\d+===', '').Trim()
    return [PSCustomObject]@{ Code = $code; Body = $body }
}

function Test-AllEndpoints([string]$tok) {
    $endpoints = @(
        [PSCustomObject]@{ Path="/data/isAliveToken";     Method="GET" },
        [PSCustomObject]@{ Path="/data/notice/v2/";       Method="GET" },
        [PSCustomObject]@{ Path="/data/chart/v4/list";    Method="GET" },
        [PSCustomObject]@{ Path="/data/probability/v1/";  Method="GET" },
        [PSCustomObject]@{ Path="/data/property/leaderboard"; Method="GET" },
        [PSCustomObject]@{ Path="/data/user/token";       Method="GET" },
        [PSCustomObject]@{ Path="/data/setting/version/latest"; Method="GET" }
    )
    $results = @()
    foreach ($ep in $endpoints) {
        $r = Test-BackndToken $tok $ep.Path $ep.Method
        $results += [PSCustomObject]@{
            Endpoint = $ep.Path
            Code     = $r.Code
            Body     = $r.Body.Substring(0, [Math]::Min(200, $r.Body.Length))
        }
    }
    return $results
}

# ── WinForms UI ───────────────────────────────────────────────────────────────
function Show-TokenUI {
    param([string]$AccessToken, [string]$RefreshToken, [int]$ApiCode,
          [string]$ApiBody, [string]$Method1Status, [string]$Method2Status,
          [bool]$Confirmed, [array]$EndpointResults)

    $title  = if ($Confirmed) { "ACCESS TOKEN CONFIRMED  —  backend.dat + memory scan agree" } `
              else            { "Token extracted from backend.dat  (API: $ApiCode)" }
    $tColor = switch ($ApiCode) {
        {$_ -ge 200 -and $_ -lt 300} { [Drawing.Color]::LightGreen }
        401 { [Drawing.Color]::OrangeRed }
        default { [Drawing.Color]::Orange }
    }

    $form = New-Object Windows.Forms.Form
    $form.Text = "Taskbar Hero — BACKND Security Audit"
    $form.Width = 860; $form.Height = 580
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [Drawing.Color]::FromArgb(18, 18, 18)
    $form.ForeColor = [Drawing.Color]::White
    $form.Font = New-Object Drawing.Font("Consolas", 9)
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.TopMost = $true

    $y = 10
    function AddLabel($text, $color, $fontSize = 9, $bold = $false) {
        $l = New-Object Windows.Forms.Label
        $l.Text = $text; $l.ForeColor = $color; $l.Width = 830; $l.Height = 22
        $l.Location = [Drawing.Point]::new(12, $y); $script:y += 22
        $l.Font = New-Object Drawing.Font("Consolas", $fontSize, $(if ($bold) { [Drawing.FontStyle]::Bold } else { [Drawing.FontStyle]::Regular }))
        $form.Controls.Add($l)
    }
    function AddBox($text, $color) {
        $tb = New-Object Windows.Forms.TextBox
        $tb.Text = $text; $tb.ForeColor = $color; $tb.BackColor = [Drawing.Color]::FromArgb(35,35,35)
        $tb.ReadOnly = $true; $tb.Width = 820; $tb.Height = 24
        $tb.Location = [Drawing.Point]::new(12, $y); $script:y += 28
        $tb.BorderStyle = "None"; $tb.Font = New-Object Drawing.Font("Consolas", 9)
        $form.Controls.Add($tb)
    }
    function AddSep { $y += 6 }

    AddLabel $title $tColor 11 $true
    $y += 4

    AddLabel "METHOD 1 — backend.dat decryption:" [Drawing.Color]::Cyan 9 $true
    AddLabel "  Key: signatureKey[0:16] = b8f08f21-62e2-11 (from resources.assets, AES-128-CBC)" [Drawing.Color]::Gray
    AddBox   "access_token : $AccessToken" $tColor
    AddBox   "refresh_token: $RefreshToken" [Drawing.Color]::Yellow
    AddSep

    AddLabel "METHOD 2 — Memory scan (UTF-16LE, managed heap):" [Drawing.Color]::Cyan 9 $true
    AddLabel "  $Method2Status" $(if ($Confirmed) {[Drawing.Color]::LightGreen} else {[Drawing.Color]::Gray})
    AddSep

    AddLabel "API VALIDATION — api.thebackend.io/data/isAliveToken:" [Drawing.Color]::Cyan 9 $true
    AddBox   "HTTP $ApiCode : $($ApiBody.Substring(0,[Math]::Min(80,$ApiBody.Length)))" $tColor
    AddSep

    if ($EndpointResults) {
        AddLabel "ENDPOINT SWEEP:" [Drawing.Color]::Cyan 9 $true
        foreach ($ep in $EndpointResults) {
            $c = switch ($ep.Code) {
                {$_ -ge 200 -and $_ -lt 300} { [Drawing.Color]::LightGreen }
                503 { [Drawing.Color]::Gray }
                default { [Drawing.Color]::Orange }
            }
            AddLabel "  HTTP $($ep.Code)  $($ep.Endpoint)" $c
        }
    }
    AddSep

    $btnCopy = New-Object Windows.Forms.Button
    $btnCopy.Text = "Copy token"; $btnCopy.Width = 120; $btnCopy.Height = 28
    $btnCopy.Location = [Drawing.Point]::new(12, $y)
    $btnCopy.BackColor = [Drawing.Color]::FromArgb(40,80,40)
    $btnCopy.ForeColor = [Drawing.Color]::LightGreen
    $btnCopy.Add_Click({ [Windows.Forms.Clipboard]::SetText($AccessToken) })
    $form.Controls.Add($btnCopy)

    $btnClose = New-Object Windows.Forms.Button
    $btnClose.Text = "Close"; $btnClose.Width = 80; $btnClose.Height = 28
    $btnClose.Location = [Drawing.Point]::new(140, $y)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    $form.ShowDialog() | Out-Null
}

# ── MAIN ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Taskbar Hero — BACKND Token Extractor v3" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# — Step 1: Decrypt backend.dat
Step "Step 1: Decrypting backend.dat..."
$datResult = Decrypt-BackendDat $BACKEND_DAT
if ($datResult) {
    Step "  [OK] access_token : $($datResult.AccessToken)" "Green"
    Step "  [OK] refresh_token: $($datResult.RefreshToken)" "Green"
} else {
    Step "  [FAIL] backend.dat not found or decryption failed" "Red"
}

# — Step 2: Memory scan
Step "Step 2: Scanning game memory (UTF-16 hex strings)..."
$proc = Get-Process TaskBarHero -EA SilentlyContinue | Select-Object -First 1
$memTokens = @()
if ($proc) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $memTokens = [HexScan]::ScanUtf16($proc.Id)
    $sw.Stop()
    Step "  Found $($memTokens.Count) candidate(s) in $($sw.ElapsedMilliseconds)ms" "Yellow"
    $memTokens | ForEach-Object { Step "    $_" "Gray" }
} else {
    Step "  Game not running" "Gray"
}

# — Method comparison
$confirmed = $false
$method2Status = "Game not running"
if ($datResult -and $memTokens.Count -gt 0) {
    $accessInMem  = $memTokens -contains $datResult.AccessToken
    $refreshInMem = $memTokens -contains $datResult.RefreshToken
    if ($accessInMem) {
        $confirmed = $true
        $method2Status = "CONFIRMED: access_token found in managed heap UTF-16"
    } elseif ($refreshInMem) {
        $method2Status = "refresh_token found in managed heap UTF-16"
    } else {
        $method2Status = "Tokens not in managed heap (stored in native code)"
    }
} elseif ($datResult) {
    $method2Status = "Extracted from backend.dat (memory scan skipped)"
}

$mainToken = if ($datResult) { $datResult.AccessToken } else { "" }

# — Step 3: API validation
Step "Step 3: Validating token against api.thebackend.io..."
$apiResult = $null
$endpointResults = @()
if ($mainToken) {
    $apiResult = Test-BackndToken $mainToken
    $col = if ($apiResult.Code -ge 200 -and $apiResult.Code -lt 300) { "Green" } else { "Red" }
    Step "  HTTP $($apiResult.Code): $($apiResult.Body.Substring(0,[Math]::Min(100,$apiResult.Body.Length)))" $col

    if ($apiResult.Code -ge 200 -and $apiResult.Code -lt 300) {
        Step "Step 4: Running endpoint sweep..." "Cyan"
        $endpointResults = Test-AllEndpoints $mainToken
        $endpointResults | ForEach-Object {
            $c = if ($_.Code -ge 200 -and $_.Code -lt 300) {"Green"} elseif ($_.Code -eq 503) {"Gray"} else {"Yellow"}
            Step "  $($_.Code) $($_.Endpoint)" $c
        }
    } else {
        Step "  Token expired or invalid — watching backend.dat for refresh..." "Yellow"
        Step "  (Trigger any in-game event to refresh the token)" "Gray"
    }
}

# — Save to file
if ($mainToken) {
    $ts = "[$(Get-Date)]`naccess_token : $mainToken`nrefresh_token: $(if($datResult){$datResult.RefreshToken})`nAPI HTTP: $(if($apiResult){$apiResult.Code})`n"
    $ts | Out-File $out -Encoding UTF8
    Step "Saved to: $out" "Gray"
}

# — Show UI
Write-Host ""
if (-not $Quick) {
    Show-TokenUI `
        -AccessToken   $mainToken `
        -RefreshToken  (if ($datResult) { $datResult.RefreshToken } else { "" }) `
        -ApiCode       (if ($apiResult) { $apiResult.Code } else { 0 }) `
        -ApiBody       (if ($apiResult) { $apiResult.Body } else { "N/A" }) `
        -Method1Status "backend.dat decrypted (AES-128-CBC, key=signatureKey[0:16])" `
        -Method2Status $method2Status `
        -Confirmed     $confirmed `
        -EndpointResults $endpointResults
}

Write-Host "Done." -ForegroundColor Cyan
