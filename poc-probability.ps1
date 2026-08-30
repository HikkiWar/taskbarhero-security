# poc-probability.ps1  — шанс кейсов через /data/probability/v1/
# Требует: игра запущена или backend.dat свежий (< 3ч)

param([switch]$Modify)

$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"
$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$SDK_VERSION   = "5.18.11"
$BACKEND_DAT   = "C:\Users\Gigabyte\AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat"

# ── Расшифровать backend.dat ────────────────────────────────────────────
function Get-Token {
    $aes = [Security.Cryptography.RijndaelManaged]::new()
    $aes.KeySize=128; $aes.BlockSize=128
    $aes.Mode   = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding= [Security.Cryptography.PaddingMode]::Zeros
    $aes.Key = [Text.Encoding]::UTF8.GetBytes($SIGNATURE_KEY)[0..15]
    $aes.IV  = $aes.Key
    $enc   = [IO.File]::ReadAllBytes($BACKEND_DAT)
    $plain = [Text.Encoding]::ASCII.GetString(
        $aes.CreateDecryptor().TransformFinalBlock($enc, 0, $enc.Length))
    $m = [regex]::Matches($plain, '[0-9a-f]{64}')
    if ($m.Count -ge 1) { return $m[0].Value }
    throw "Token not found in backend.dat"
}

function Api($url, $method="GET", $body=$null) {
    $h = @{
        "access_token"         = $token
        "client_app_id"        = $CLIENT_APP_ID
        "client_signature_key" = $SIGNATURE_KEY
        "sdk_version"          = $SDK_VERSION
        "client_date"          = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
        "os_version"           = "Windows 11"
        "device"               = "PC"
        "serverstatus"         = "t"
        "Content-Type"         = "application/json"
        "User-Agent"           = "UnityPlayer/6000.0.72f1"
    }
    $params = @{ Uri=$url; Method=$method; Headers=$h; UseBasicParsing=$true }
    if ($body) { $params.Body = ($body | ConvertTo-Json -Depth 10 -Compress) }
    try {
        $r = Invoke-WebRequest @params -EA Stop
        return @{ Code=$r.StatusCode; Body=($r.Content | ConvertFrom-Json -EA SilentlyContinue); Raw=$r.Content }
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        return @{ Code=$code; Body=$null; Raw="$_" }
    }
}

Write-Host "=== PoC: Probability Table ===" -ForegroundColor Cyan
Write-Host ""

$token = Get-Token
$age   = [int]((Get-Date).ToUniversalTime() - (Get-Item $BACKEND_DAT).LastWriteTimeUtc).TotalMinutes
Write-Host "[token] $($token.Substring(0,16))... age: ${age}min" -ForegroundColor $(if ($age -lt 180) {"Green"} else {"Red"})
if ($age -ge 180) { Write-Host "Token expired! Restart game." -ForegroundColor Red; exit 1 }
Write-Host ""

# ── GET /data/probability/v1/ ─────────────────────────────────────────────
Write-Host "[1] GET /data/probability/v1/ ..." -ForegroundColor Yellow
$r = Api "https://api.thebackend.io/data/probability/v1/"
Write-Host "    HTTP $($r.Code)"

if ($r.Code -eq 200) {
    $tables = $r.Body.rows
    Write-Host "    Tables found: $($tables.Count)" -ForegroundColor Green
    Write-Host ""
    foreach ($t in $tables) {
        Write-Host "  ── $($t.fileName) ──" -ForegroundColor Cyan
        $data = $t.fileContent | ConvertFrom-Json -EA SilentlyContinue
        if ($data) {
            foreach ($grp in $data.Groups) {
                Write-Host "    Group: $($grp.GroupName)" -ForegroundColor Yellow
                foreach ($item in $grp.Items) {
                    Write-Host "      [$($item.idx)] $($item.value)  weight=$($item.weight)" -ForegroundColor White
                }
            }
        } else {
            Write-Host "    $($t.fileContent | Select-Object -First 200)"
        }
    }

    # Сохранить сырые данные
    $r.Raw | Out-File "$PSScriptRoot\probability_raw.json" -Encoding UTF8
    Write-Host ""
    Write-Host "    Raw saved: probability_raw.json" -ForegroundColor DarkGray

} elseif ($r.Code -eq 404) {
    Write-Host "    404 — endpoint not found or table empty" -ForegroundColor Red

    # Попробовать альтернативные пути
    Write-Host ""
    Write-Host "[2] Trying alternatives..." -ForegroundColor Yellow
    $alts = @(
        "/data/probability/v1/list",
        "/data/probability/v1/all",
        "/data/probability/getList",
        "/data/probability/list"
    )
    foreach ($alt in $alts) {
        $r2 = Api "https://api.thebackend.io$alt"
        Write-Host "    $alt  => HTTP $($r2.Code)"
    }

} else {
    Write-Host "    $($r.Raw)" -ForegroundColor Red
}

Write-Host ""

# ── Попытка модифицировать вероятности (PUT) ──────────────────────────────
if ($Modify) {
    Write-Host "[!] MODIFY MODE — пытаемся изменить таблицу вероятностей" -ForegroundColor Magenta
    Write-Host ""

    if (-not $tables) {
        Write-Host "    Нет таблицы для модификации. Запустите без -Modify сначала." -ForegroundColor Red
    } else {
        $first = $tables[0]
        $data  = $first.fileContent | ConvertFrom-Json

        # Максимальный вес для всех item
        foreach ($grp in $data.Groups) {
            foreach ($item in $grp.Items) {
                $item.weight = 1000  # взвинтить до максимума у всех
            }
            # Первому — 9999
            $data.Groups[0].Items[0].weight = 9999
        }

        $newContent = $data | ConvertTo-Json -Depth 10 -Compress
        $payload    = @{ fileName=$first.fileName; fileContent=$newContent }

        Write-Host "    PUT /data/probability/v1/ ..." -ForegroundColor Yellow
        $rput = Api "https://api.thebackend.io/data/probability/v1/" "PUT" $payload
        Write-Host "    HTTP $($rput.Code)"

        if ($rput.Code -in 200, 201, 204) {
            Write-Host "    !! PUT ACCEPTED — таблица вероятностей изменена на сервере !!" -ForegroundColor Red -BackgroundColor Yellow
        } elseif ($rput.Code -eq 403) {
            Write-Host "    403 Forbidden — сервер отклонил. Endpoint read-only для user-токена." -ForegroundColor Green
        } elseif ($rput.Code -eq 405) {
            Write-Host "    405 Method Not Allowed — PUT не разрешён." -ForegroundColor Green
        } else {
            Write-Host "    $($rput.Raw)" -ForegroundColor Yellow
        }
    }
}
