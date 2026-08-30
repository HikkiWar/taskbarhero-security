# poc-cube-synth.ps1  — тест синтеза куба: отрицательная цена + прямой API
# Аналог F-01 (отрицательная цена начисляет золото) — но для системы крафта

param(
    [switch]$ApiMode,
    [switch]$Discover   # -Discover: найти все gameInfo/chart endpoint-ы
)

$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"
$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$SDK_VERSION   = "5.18.11"
$BACKEND_DAT   = "C:\Users\Gigabyte\AppData\LocalLow\TesseractStudio\TaskbarHero\backend.dat"

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
        return @{ Code=$r.StatusCode; Raw=$r.Content; Body=($r.Content|ConvertFrom-Json -EA SilentlyContinue) }
    } catch {
        return @{ Code=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}; Raw="$_" }
    }
}

Write-Host "=== PoC: Cube Synthesis ===" -ForegroundColor Cyan
Write-Host ""

$token = Get-Token
Write-Host "[token] $($token.Substring(0,16))..." -ForegroundColor Green
Write-Host ""

# ════════════════════════════════════════════════════════════════════
# ЧАСТЬ 1: Инструкция для Cheat Engine (память)
# ════════════════════════════════════════════════════════════════════
Write-Host "═══ ЧАСТЬ 1: Memory — поиск CubeRecipeSaveData ═══" -ForegroundColor Yellow
Write-Host ""
Write-Host "Найденные в коде классы (из phase1_background.txt):" -ForegroundColor White
Write-Host "  TaskbarHero.EasySaveData.CubeLevelSaveData"  -ForegroundColor DarkGray
Write-Host "  TaskbarHero.EasySaveData.CubeRecipeSaveData" -ForegroundColor DarkGray
Write-Host "  TaskbarHero.Log.CubeSynthesisLog"            -ForegroundColor DarkGray
Write-Host "  TaskbarHero.UI.CubeSynthesisAutoFillButton"  -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ШАГ 1 — Найти таблицу рецептов:" -ForegroundColor Magenta
Write-Host "    Cheat Engine → String scan → 'CubeSynthesis' или 'CubeRecipe'" -ForegroundColor White
Write-Host "    Или: Exact Value scan (4 bytes) по ID куба который хочешь крафтить" -ForegroundColor White
Write-Host ""
Write-Host "  ШАГ 2 — Понять структуру рецепта:" -ForegroundColor Magenta
Write-Host "    CubeRecipeSaveData скорее всего содержит:" -ForegroundColor White
Write-Host "    [RecipeId: int] [MaterialId_1: int] [Count_1: int] [MaterialId_2: int] [Count_2: int] ..." -ForegroundColor White
Write-Host "    и [ResultId: int] [Cost_Gold: int]" -ForegroundColor White
Write-Host ""
Write-Host "  ШАГ 3 — ПРОВЕРИТЬ: защищены ли поля ObscuredInt?" -ForegroundColor Magenta
Write-Host "    Если нет Obscured — изменить Count_1 на 0: материалы не нужны" -ForegroundColor Green
Write-Host "    Если нет Obscured — изменить Cost_Gold на -1000: золото добавляется" -ForegroundColor Green
Write-Host "    Если Obscured — использовать формулу F-08:" -ForegroundColor Yellow
Write-Host "    значение = ((шифр - ключ) XOR ключ), ключ на +0x08" -ForegroundColor White
Write-Host ""
Write-Host "  ШАГ 4 — Синтезировать и дождаться автосейва (3 мин):" -ForegroundColor Magenta
Write-Host "    Если Count_1=0 — синтез без материалов" -ForegroundColor White
Write-Host "    Если Cost_Gold=-1000 — золото ДОБАВИТСЯ (как F-01)" -ForegroundColor White
Write-Host ""

# ════════════════════════════════════════════════════════════════════
# ЧАСТЬ 2: Обнаружение API endpoints
# ════════════════════════════════════════════════════════════════════
if ($Discover -or $ApiMode) {
    Write-Host "═══ ЧАСТЬ 2: API endpoint discovery ═══" -ForegroundColor Yellow
    Write-Host ""

    # Сначала получить /data/chart/v4/list — там список таблиц данных игры
    Write-Host "[1] GET /data/chart/v4/list — список всех game tables..." -ForegroundColor White
    $charts = Api "https://api.thebackend.io/data/chart/v4/list"
    Write-Host "    HTTP $($charts.Code)"

    if ($charts.Code -eq 200 -and $charts.Body) {
        Write-Host ""
        Write-Host "    GAME TABLES:" -ForegroundColor Green
        $charts.Body.rows | ForEach-Object {
            Write-Host "    [$($_.chartId)] $($_.chartName)  rows=$($_.rows)" -ForegroundColor White
        }
        $charts.Raw | Out-File "$PSScriptRoot\charts_list.json" -Encoding UTF8
        Write-Host ""
        Write-Host "    Saved: charts_list.json" -ForegroundColor DarkGray

        # Найти куб-связанные таблицы
        $cubeCharts = $charts.Body.rows | Where-Object { $_.chartName -match "cube|synth|craft|recipe" }
        if ($cubeCharts) {
            Write-Host ""
            Write-Host "    CUBE-RELATED TABLES:" -ForegroundColor Cyan
            foreach ($c in $cubeCharts) {
                Write-Host "    → $($c.chartName) (id=$($c.chartId))" -ForegroundColor Cyan
                $cd = Api "https://api.thebackend.io/data/chart/v4/$($c.chartId)"
                if ($cd.Code -eq 200) {
                    Write-Host "      Rows: $($cd.Body.rows.Count)" -ForegroundColor White
                    $cd.Body.rows | Select-Object -First 3 | ForEach-Object {
                        Write-Host "      $($_ | ConvertTo-Json -Compress | Select-Object -First 200)" -ForegroundColor DarkGray
                    }
                }
            }
        }
    } else {
        Write-Host "    $($charts.Raw | Select-Object -First 200)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[2] Поиск gameInfo (сохранения) для куба..." -ForegroundColor White
    $gi = Api "https://api.thebackend.io/data/gameInfo"
    Write-Host "    HTTP $($gi.Code)"
    if ($gi.Code -eq 200 -and $gi.Body) {
        $keys = $gi.Body.PSObject.Properties.Name
        Write-Host "    Keys in gameInfo: $($keys -join ', ')" -ForegroundColor Green
        $cubeKeys = $keys | Where-Object { $_ -match "cube|synth|craft" }
        if ($cubeKeys) {
            Write-Host "    CUBE KEYS: $($cubeKeys -join ', ')" -ForegroundColor Cyan
            foreach ($k in $cubeKeys) {
                Write-Host "    $k = $($gi.Body.$k | ConvertTo-Json -Compress)" -ForegroundColor White
            }
        }
        $gi.Raw | Out-File "$PSScriptRoot\gameinfo_raw.json" -Encoding UTF8
        Write-Host "    Saved: gameinfo_raw.json" -ForegroundColor DarkGray
    }
}

# ════════════════════════════════════════════════════════════════════
# ЧАСТЬ 3: Если нашли endpoint синтеза — тест отрицательной стоимости
# ════════════════════════════════════════════════════════════════════
if ($ApiMode) {
    Write-Host ""
    Write-Host "═══ ЧАСТЬ 3: API — тест подмены тела запроса синтеза ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Это запускается ПОСЛЕ нахождения endpoint-а через MITM." -ForegroundColor White
    Write-Host "  Вставить сюда реальные параметры из intercept.log" -ForegroundColor White
    Write-Host ""

    # ШАБЛОН — заполнить после MITM сессии
    # $synth_endpoint = "/data/gameInfo/cubeSynth"   # <-- реальный endpoint из лога
    # $synth_body = @{
    #     recipeId    = 1001      # ID рецепта
    #     materialIds = @(101, 102)  # материалы
    #     count       = 1         # количество
    #     # Попробуем подмену:
    #     cost        = -9999     # отрицательная цена если поле принимается
    # }
    # $r = Api "https://api.thebackend.io$synth_endpoint" "POST" $synth_body
    # Write-Host "HTTP $($r.Code): $($r.Raw | Select-Object -First 300)"
    Write-Host "  [!] Раскомментировать строки выше после получения endpoint из MITM лога." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "═══ ИТОГ ═══" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Запустить: .\poc-cube-synth.ps1 -Discover" -ForegroundColor Green
Write-Host "  Это получит список всех game tables и gameInfo структуру." -ForegroundColor White
Write-Host ""
Write-Host "  Параллельно: .\poc-traffic-intercept.ps1 + открыть куб-крафт в игре" -ForegroundColor Green
Write-Host "  → intercept.log покажет точный HTTP endpoint и body синтеза." -ForegroundColor White
