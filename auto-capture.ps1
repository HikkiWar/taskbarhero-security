# auto-capture.ps1  — loads pre-compiled DLL, no Add-Type delay
$dir     = $PSScriptRoot
$outFile = "$dir\token.txt"
$logFile = "$dir\capture.log"
$dllPath = "$dir\QuickScan.dll"

function Log($msg) {
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line -ForegroundColor Cyan
    Add-Content $logFile $line -Encoding UTF8
}

"" | Set-Content $logFile -Encoding UTF8
Log "=== Auto Token Capture ==="

# Load pre-compiled assembly (instant, no Roslyn startup)
if (-not (Test-Path $dllPath)) {
    Log "ERROR: QuickScan.dll not found at $dllPath"
    Log "Run once from Claude to rebuild it."
    exit 1
}
Add-Type -Path $dllPath
Log "QuickScan loaded OK"

# Game check
$gameProc = Get-Process TaskbarHero -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $gameProc) {
    Log "TaskbarHero.exe not found! Start the game."
    Read-Host "Press Enter when game is running"
    $gameProc = Get-Process TaskbarHero -ErrorAction SilentlyContinue | Select-Object -First 1
}
Log "Game PID: $($gameProc.Id)"
Log "Scanning every 400ms — do something in-game to trigger API calls"
Log ""

$scanN   = 0
$gamePid = $gameProc.Id

while ($true) {
    $scanN++

    # Re-check PID (game might restart)
    $gp = Get-Process TaskbarHero -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gp) {
        Log "Game not running, waiting..."
        Start-Sleep -Seconds 5
        continue
    }
    if ($gp.Id -ne $gamePid) {
        $gamePid = $gp.Id
        Log "Game restarted, new PID: $gamePid"
    }

    # Memory scan
    try {
        $token = [QuickScan]::ScanForBackndToken($gamePid)
    } catch {
        if ($scanN -le 5) { Log "Scan error: $_" }
        Start-Sleep -Milliseconds 400
        continue
    }

    if ($token -and $token.Length -gt 20) {
        Log ""
        Log "======================================="
        Log "TOKEN CAPTURED on scan #$scanN"
        Log "======================================="
        Log $token
        Log ""

        $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $content = "# Captured: $ts`n# Scan: #$scanN`n# Method: memory`n`n$token"
        [System.IO.File]::WriteAllText($outFile, $content, [System.Text.Encoding]::UTF8)
        Log "Saved to: $outFile"

        # Clipboard
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            [System.Windows.Forms.Clipboard]::SetText($token)
            Log "Copied to clipboard!"
        } catch {}

        # Popup alert
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "TOKEN CAPTURED!`n`n$($token.Substring(0,60))...",
                "THB Token Capture",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        } catch {}

        break
    }

    if ($scanN % 50 -eq 0) {
        Log "Scan #$scanN — still hunting... (PID $gamePid)"
    }

    Start-Sleep -Milliseconds 400
}

Log "Done."
