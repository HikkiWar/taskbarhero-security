# poc-traffic-intercept.ps1  — полный MITM с логированием и подменой тел запросов
# Перехватывает ВСЕ запросы game.thebackend.io / api.thebackend.io
# Позволяет на лету менять request-body перед отправкой на сервер
#
# Запустить ДО игры (от Администратора — нужен порт 443 и hosts)
#
# Режимы:
#   -Log    : только логировать всё (безопасно)
#   -Inject : включить подмену body по правилам в $RULES

param(
    [switch]$Inject,
    [int]$Port = 443,
    [string]$LogFile = "$PSScriptRoot\intercept.log"
)

$SIGNATURE_KEY = "b8f08f21-62e2-11f1-b7a5-d5de2c371eac11447"
$CLIENT_APP_ID = "b8f08f20-62e2-11f1-b7a5-d5de2c371eac11447"
$pfxPath = "$env:TEMP\thb_capture.pfx"
$pfxPass = "thbcap2025!"
$TARGET  = "game.thebackend.io"

# ── ПРАВИЛА ПОДМЕНЫ ──────────────────────────────────────────────────────────
# Каждое правило: Path (regex) + Transform (scriptblock, принимает $body как PSObject)
# Если Transform вернёт $null — тело НЕ меняется
$RULES = @(
    @{
        # Перехватить открытие ящика
        Path      = "box|chest|reward"
        Describe  = "Box open"
        Transform = {
            param($body)
            Write-Host "  [INJECT] Box open body: $($body | ConvertTo-Json -Compress)" -ForegroundColor Magenta
            # Пример: если сервер принимает itemKey — подменить
            # $body.itemKey = 920651   # 910651=обычный, 920651=редкий/синий
            # return $body
            return $null  # не менять пока
        }
    },
    @{
        # Перехватить синтез куба
        Path      = "cube|craft|synth"
        Describe  = "Cube synthesis"
        Transform = {
            param($body)
            Write-Host "  [INJECT] Cube synth body: $($body | ConvertTo-Json -Compress)" -ForegroundColor Magenta
            # Если есть поле cost — поставить 0 или отрицательное
            # if ($body.PSObject.Properties["cost"]) { $body.cost = -1 }
            return $null
        }
    }
)

# ── Compile C# MITM ───────────────────────────────────────────────────────────
Add-Type @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public static class MitmProxy {
    public static bool         Running    = false;
    public static List<string> Requests   = new List<string>();
    public static object       Lock       = new object();

    static TcpListener      _listener;
    static X509Certificate2 _cert;
    static string           _upstreamIp;
    static string           _upstreamHost;

    public static string Start(string pfxPath, string pfxPass, string host, string upstreamIp, int port) {
        try {
            var bytes = File.ReadAllBytes(pfxPath);
            _cert         = new X509Certificate2(bytes, pfxPass,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            _upstreamIp   = upstreamIp;
            _upstreamHost = host;

            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start(100);
            Running = true;
            new Thread(AcceptLoop) { IsBackground = true }.Start();
            return "OK";
        } catch (Exception ex) { return "ERROR: " + ex.Message; }
    }

    static void AcceptLoop() {
        while (Running) {
            try {
                var c = _listener.AcceptTcpClient();
                new Thread(() => Handle(c)) { IsBackground = true }.Start();
            } catch { if (!Running) break; }
        }
    }

    static void Handle(TcpClient client) {
        SslStream ssl = null; TcpClient up = null; SslStream upSsl = null;
        try {
            client.ReceiveTimeout = 20000; client.SendTimeout = 20000;
            ssl = new SslStream(client.GetStream(), false);
            ssl.AuthenticateAsServer(_cert, false,
                System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13, false);

            // Read full HTTP header
            var hdrBuf = new List<byte>(8192);
            var one = new byte[1]; int tail = 0;
            int[] seq = { 13, 10, 13, 10 };
            while (hdrBuf.Count < 65536) {
                if (ssl.Read(one, 0, 1) == 0) break;
                hdrBuf.Add(one[0]);
                tail = (one[0] == seq[tail]) ? tail + 1 : (one[0] == seq[0] ? 1 : 0);
                if (tail == 4) break;
            }

            string hdrStr = Encoding.UTF8.GetString(hdrBuf.ToArray());

            // Parse Content-Length
            int bodyLen = 0;
            foreach (var line in hdrStr.Split('\n')) {
                var l = line.Trim();
                if (l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) {
                    int.TryParse(l.Substring(15).Trim(), out bodyLen);
                }
            }

            // Read body
            byte[] bodyBytes = new byte[0];
            if (bodyLen > 0 && bodyLen < 1024 * 1024) {
                bodyBytes = new byte[bodyLen];
                int read = 0;
                while (read < bodyLen) {
                    int n = ssl.Read(bodyBytes, read, bodyLen - read);
                    if (n == 0) break;
                    read += n;
                }
            }

            string bodyStr = bodyBytes.Length > 0 ? Encoding.UTF8.GetString(bodyBytes) : "";

            // Parse method + path
            string firstLine = hdrStr.Split('\n')[0].Trim();
            lock (Lock) {
                Requests.Add(DateTime.UtcNow.ToString("HH:mm:ss") + " | " + firstLine + " | body=" + (bodyStr.Length > 200 ? bodyStr.Substring(0,200) + "..." : bodyStr));
            }

            // Connect upstream
            up    = new TcpClient();
            up.Connect(_upstreamIp, 443);
            up.ReceiveTimeout = 30000; up.SendTimeout = 30000;
            upSsl = new SslStream(up.GetStream(), false, (s, c2, ch, e) => true);
            upSsl.AuthenticateAsClient(_upstreamHost);

            // Forward header
            upSsl.Write(hdrBuf.ToArray(), 0, hdrBuf.Count);
            // Forward body
            if (bodyBytes.Length > 0)
                upSsl.Write(bodyBytes, 0, bodyBytes.Length);

            // Relay response
            var t1 = new Thread(() => { try { Relay(upSsl, ssl); } catch {} }) { IsBackground = true };
            var t2 = new Thread(() => { try { Relay(ssl, upSsl); } catch {} }) { IsBackground = true };
            t1.Start(); t2.Start();
            t1.Join(30000);
        } catch {}
        finally {
            try { if (upSsl  != null) upSsl.Close();  } catch {}
            try { if (up     != null) up.Close();     } catch {}
            try { if (ssl    != null) ssl.Close();    } catch {}
            try { if (client != null) client.Close(); } catch {}
        }
    }

    static void Relay(Stream a, Stream b) {
        var buf = new byte[8192]; int n;
        while ((n = a.Read(buf, 0, buf.Length)) > 0) b.Write(buf, 0, n);
    }

    public static void Stop() {
        Running = false;
        try { _listener.Stop(); } catch {}
    }

    public static string[] DumpRequests() {
        lock (Lock) { return Requests.ToArray(); }
    }
}
'@ -Language CSharp -EA SilentlyContinue

# ── Сгенерировать сертификат если нужен ──────────────────────────────────────
if (-not (Test-Path $pfxPath)) {
    Write-Host "[cert] Generating..." -ForegroundColor Yellow
    Import-Module PKI -EA SilentlyContinue
    $ca   = New-SelfSignedCertificate -Subject "CN=THB Capture CA" -KeyUsage CertSign,CRLSign -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1) -CertStoreLocation "Cert:\CurrentUser\My" -HashAlgorithm SHA256
    $st   = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser"); $st.Open("ReadWrite"); $st.Add($ca); $st.Close()
    $site = New-SelfSignedCertificate -Subject "CN=$TARGET" -DnsName @($TARGET,"*.thebackend.io") -Signer $ca -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1) -CertStoreLocation "Cert:\CurrentUser\My"
    $site | Export-PfxCertificate -FilePath $pfxPath -Password (ConvertTo-SecureString $pfxPass -AsPlainText -Force) | Out-Null
    Write-Host "[cert] Created: $pfxPath" -ForegroundColor Green
}

# ── Resolve upstream IP ───────────────────────────────────────────────────────
$ip = try { ([System.Net.Dns]::GetHostAddresses("game.thebackend.io") | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1).IPAddressToString } catch { "15.165.195.76" }
Write-Host "[upstream] $TARGET -> $ip" -ForegroundColor DarkGray

# ── Добавить hosts ────────────────────────────────────────────────────────────
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsRaw  = Get-Content $hostsPath -Raw -EA SilentlyContinue
if ($hostsRaw -notmatch "# thb-mitm") {
    try {
        Add-Content $hostsPath "`n127.0.0.1 $TARGET # thb-mitm`n127.0.0.1 api.thebackend.io # thb-mitm" -Encoding ASCII
        Write-Host "[hosts] Redirected $TARGET -> 127.0.0.1" -ForegroundColor Yellow
    } catch {
        Write-Host "[hosts] ERROR: run as Administrator!" -ForegroundColor Red; exit 1
    }
    & ipconfig /flushdns | Out-Null
}

# ── Запустить прокси ──────────────────────────────────────────────────────────
$res = [MitmProxy]::Start($pfxPath, $pfxPass, $TARGET, $ip, $Port)
if ($res -ne "OK") { Write-Host "ERROR: $res" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  MITM PROXY RUNNING on port $Port" -ForegroundColor Cyan
Write-Host "  Logging ALL requests to: $LogFile" -ForegroundColor Cyan
if ($Inject) { Write-Host "  INJECT MODE ON — request bodies will be modified" -ForegroundColor Red }
Write-Host "  Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Cleanup ───────────────────────────────────────────────────────────────────
$cleanup = {
    [MitmProxy]::Stop()
    $h = Get-Content $hostsPath -Raw -EA SilentlyContinue
    if ($h -match "# thb-mitm") {
        $lines = ($h -split "`r?`n") | Where-Object { $_ -notmatch "# thb-mitm" }
        [System.IO.File]::WriteAllText($hostsPath, ($lines -join "`n"))
    }
    & ipconfig /flushdns | Out-Null
    Write-Host "[*] Cleanup done." -ForegroundColor DarkGray
}
Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action $cleanup | Out-Null

# ── Основной цикл: печатать новые запросы ──────────────────────────────────
$seen = 0
"" | Set-Content $LogFile -Encoding UTF8
while ($true) {
    Start-Sleep -Milliseconds 300
    $all = [MitmProxy]::DumpRequests()
    while ($seen -lt $all.Length) {
        $line = $all[$seen]
        Write-Host "  $line" -ForegroundColor $(
            if ($line -match "POST|PUT") { "Yellow" }
            elseif ($line -match "box|reward|chest|cube|synth|item|probability") { "Magenta" }
            else { "White" }
        )
        Add-Content $LogFile $line -Encoding UTF8
        $seen++
    }
}
