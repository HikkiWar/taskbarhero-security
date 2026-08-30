# poc-box-replace.ps1  — подмена типа/награды кейса перед открытием
# Тест 3: "нам выпал синий редкий кейс — за открытие отвечает сам сервер"
#
# Проверяет два сценария:
#  A) Подмена RewardItemId в памяти → до вызова OpenBoxAsync (уже назначена сервером)
#  B) Прямой вызов API открытия ящика с подменёнными параметрами
#
# Требует: Cheat Engine или x64dbg открыт, игра запущена

param(
    [switch]$ApiMode,       # -ApiMode: попробовать API напрямую
    [string]$BoxId = "0"    # -BoxId: уникальный ID конкретного кейса
)

$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"
$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$SDK_VERSION   = "5.18.11"
$BACKEND_DAT   = "C:\Users\Gigabyte\AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat"

# Из box_queue_prediction.json:
# тип 910651 = обычный, тип 920651 = редкий/синий
$BOX_TYPE_NORMAL = 910651
$BOX_TYPE_RARE   = 920651

function Get-Token {
    $aes = [Security.Cryptography.RijndaelManaged]::new()
    $aes.KeySize=128; $aes.BlockSize=128
    $aes.Mode=[Security.Cryptography.CipherMode]::CBC
    $aes.Padding=[Security.Cryptography.PaddingMode]::Zeros
    $aes.Key=$aes.IV=[Text.Encoding]::UTF8.GetBytes($SIGNATURE_KEY)[0..15]
    $plain = [Text.Encoding]::ASCII.GetString(
        $aes.CreateDecryptor().TransformFinalBlock(
            [IO.File]::ReadAllBytes($BACKEND_DAT), 0,
            (Get-Item $BACKEND_DAT).Length))
    ([regex]::Matches($plain, '[0-9a-f]{64}'))[0].Value
}

function Api($url, $method="GET", $body=$null) {
    $h = @{
        "access_token"         = $token
        "client_app_id"        = $CLIENT_APP_ID
        "client_signature_key" = $SIGNATURE_KEY
        "sdk_version"          = $SDK_VERSION
        "client_date"          = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
        "os_version"           = "Windows 11"; "device"="PC"; "serverstatus"="t"
        "Content-Type"         = "application/json"
        "User-Agent"           = "UnityPlayer/6000.0.72f1"
    }
    $p = @{ Uri=$url; Method=$method; Headers=$h; UseBasicParsing=$true }
    if ($body) { $p.Body = ($body | ConvertTo-Json -Compress) }
    try {
        $r = Invoke-WebRequest @p -EA Stop
        return @{ Code=$r.StatusCode; Body=($r.Content | ConvertFrom-Json -EA SilentlyContinue); Raw=$r.Content }
    } catch {
        return @{ Code=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}; Raw="$_" }
    }
}

Write-Host "=== PoC: Box Replacement ===" -ForegroundColor Cyan
Write-Host ""

$token = Get-Token
Write-Host "[token] $($token.Substring(0,16))..." -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
# СЦЕНАРИЙ A: Поиск BoxData в памяти и подмена напрямую через память
# ════════════════════════════════════════════════════════════════════
Write-Host "═══ СЦЕНАРИЙ A: Memory — структура BoxData ═══" -ForegroundColor Yellow
Write-Host ""
Write-Host "Структура BoxData (из F-07/F-08 FINDINGS.md):" -ForegroundColor White
Write-Host ""
Write-Host "  +0x10  ItemId     (Obscured)    — ID кейса (12030, 12084...)" -ForegroundColor White
Write-Host "  +0x20  UniqueKey  (Obscured)    — тип: 910651=обычный / 920651=СИНИЙ" -ForegroundColor White
Write-Host "  +0x28  ClaimableAt(Obscured)    — timestamp" -ForegroundColor White
Write-Host "  +0x30  RewardItemId(Obscured)   — ЧТО ВЫПАДЕТ (главная цель)" -ForegroundColor White
Write-Host "  +0x40  RewardItemUniqueID(Obscured)" -ForegroundColor White
Write-Host "  +0x48  IsGet     (int)          — 0=не открыт, 1=открыт" -ForegroundColor White
Write-Host ""
Write-Host "Формула расшифровки ObscuredInt (F-08):" -ForegroundColor Cyan
Write-Host "  значение = ((шифротекст - ключ) XOR ключ)" -ForegroundColor White
Write-Host "  ключ лежит по смещению +0x08 от начала ObscuredInt-блока (16 байт)" -ForegroundColor White
Write-Host ""

# Прочитать box_queue_prediction.json для справки
$predFile = "$PSScriptRoot\test-results\box_queue_prediction.json"
if (Test-Path $predFile) {
    $pred = Get-Content $predFile | ConvertFrom-Json
    Write-Host "  Из prediction.json (снято $($pred.'снято')):" -ForegroundColor DarkGray
    $pred.очередь.PSObject.Properties | ForEach-Object {
        $boxId = $_.Name
        $r2    = $_.Value.награда
        $addr  = $_.Value.адрес
        Write-Host "    BoxId=$boxId  RewardItemId=$r2  addr=$addr" -ForegroundColor DarkGray
    }
    Write-Host ""
}

Write-Host "  ПЛАН ДЕЙСТВИЙ в Cheat Engine:" -ForegroundColor Magenta
Write-Host "  1. Открыть процесс TaskbarHero.exe" -ForegroundColor White
Write-Host "  2. Value Type = Exact Value, 4 Bytes" -ForegroundColor White
Write-Host "  3. Найти по значению: ItemId известного кейса (напр. 12030)" -ForegroundColor White
Write-Host "     НО: ItemId под ObscuredInt — искать сырой поиск или bypass:" -ForegroundColor White
Write-Host "     Искать hex: расшифровать сначала..." -ForegroundColor White
Write-Host ""
Write-Host "  Быстрый способ найти редкий (синий) кейс:" -ForegroundColor Yellow
Write-Host "  1. Array of Bytes scan: ?? ?? ?? ?? 51 E5 0D 00" -ForegroundColor Cyan
Write-Host "     (910651 в little-endian = 0x0DE551, но под Obscured это зашифровано)" -ForegroundColor White
Write-Host "  2. Лучше: найти BoxData::get_RewardItemId и поставить breakpoint" -ForegroundColor White
Write-Host "     Offset из equip_chain.md: +0xA1E1A0 от GameAssembly.dll base" -ForegroundColor White
Write-Host "     После попадания — EAX = reward, [RCX] = BoxData структура" -ForegroundColor White
Write-Host ""
Write-Host "  ВАЖНО: RewardItemId под защитой ObscuredInt." -ForegroundColor Red
Write-Host "  Варианты обхода (из F-08):" -ForegroundColor Yellow
Write-Host "    A) Перехват геттера на выходе (RAX после get_RewardItemId+0x19)" -ForegroundColor White
Write-Host "       → изменить RAX → все потребители получают подменённый ID" -ForegroundColor White
Write-Host "    B) Расшифровать ключ, применить формулу, переписать шифротекст" -ForegroundColor White
Write-Host ""

# ════════════════════════════════════════════════════════════════════
# СЦЕНАРИЙ B: Попытка открыть ящик через API напрямую
# ════════════════════════════════════════════════════════════════════
if ($ApiMode) {
    Write-Host "═══ СЦЕНАРИЙ B: API — прямой вызов открытия кейса ═══" -ForegroundColor Yellow
    Write-Host ""

    # Перебрать известные endpoint паттерны BACKND для ящиков
    $endpoints = @(
        @{ url="/data/rank/UPDATE/StageBox";           method="PUT"  }
        @{ url="/data/gameInfo/stageBox";              method="PUT"  }
        @{ url="/data/gameInfo/openBox";               method="PUT"  }
        @{ url="/data/gameInfo/StageBox";              method="POST" }
        @{ url="/data/item/box";                       method="POST" }
        @{ url="/data/chart/v4/StageBox";              method="GET"  }
        @{ url="/data/gameInfo";                       method="GET"  }
    )

    foreach ($ep in $endpoints) {
        $r = Api "https://api.thebackend.io$($ep.url)" $ep.method
        $mark = if ($r.Code -in 200,201,204) {"[HIT]"} elseif ($r.Code -eq 404) {"[404]"} else {"[$($r.Code)]"}
        $color = if ($r.Code -in 200,201,204) {"Green"} elseif ($r.Code -eq 404) {"DarkGray"} else {"Yellow"}
        Write-Host "  $mark $($ep.method) $($ep.url)" -ForegroundColor $color
        if ($r.Code -in 200,201,204) {
            Write-Host "  Body: $($r.Raw | Select-Object -First 300)" -ForegroundColor Cyan
        }
    }

    Write-Host ""
    Write-Host "  Запустите игру с MITM прокси (poc-traffic-intercept.ps1)" -ForegroundColor Yellow
    Write-Host "  и откройте кейс — точный endpoint появится в логе intercept.log" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══ ВЫВОД ═══" -ForegroundColor Cyan
Write-Host ""
Write-Host "Синий/редкий кейс (920651) — сервер уже назначил награду до открытия." -ForegroundColor White
Write-Host "Чтобы изменить что выпадет:" -ForegroundColor White
Write-Host ""
Write-Host "  Вариант 1 (быстрее): x64dbg breakpoint на get_RewardItemId" -ForegroundColor Green
Write-Host "    → изменить RAX при открытии → предмет создаётся с чужим ID" -ForegroundColor White
Write-Host "    → НО: из FINDINGS F-08: сервер СНЁС подменённый предмет" -ForegroundColor Red
Write-Host "    → Новый вопрос: снесёт ли он для РЕДКОГО (синего) ящика?" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Вариант 2 (перспективнее): найти API вызов присвоения награды" -ForegroundColor Green
Write-Host "    → Запустить MITM, совершить несколько stage completions" -ForegroundColor White
Write-Host "    → В логе найти POST с box/reward параметрами" -ForegroundColor White
Write-Host "    → Повторить запрос с подменёнными параметрами (replay attack)" -ForegroundColor White
