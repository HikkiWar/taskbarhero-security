# capture-token.ps1
# Intercepts the Bearer token from Taskbar Hero's BACKND API calls
# Run BEFORE starting the game (or restart the game after running)

param(
    [int]   $TimeoutSec = 300,
    [string]$OutFile    = "$PSScriptRoot\token.txt",
    [string]$Target     = "game.thebackend.io"
)

$ErrorActionPreference = "Stop"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$pfxPath   = "$env:TEMP\thb_capture.pfx"
$pfxPass   = "thbcap2025!"
$hostsMark = "# thb-capture"

# Cleanup on exit
$cleanup = {
    try {
        $h = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
        if ($h -match [regex]::Escape($hostsMark)) {
            $lines = ($h -split "`r?`n") | Where-Object { $_ -notmatch [regex]::Escape($hostsMark) }
            [System.IO.File]::WriteAllText($hostsPath, ($lines -join "`n"))
            Write-Host "[*] Hosts file restored." -ForegroundColor DarkGray
        }
    } catch {}
    try { [SslTokenCapture]::Stop() } catch {}
    try { & ipconfig /flushdns | Out-Null } catch {}
}

Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action $cleanup | Out-Null

Write-Host ""
Write-Host "=== Taskbar Hero - Token Capture ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Certificate
function New-CaptureCert {
    Import-Module PKI -ErrorAction SilentlyContinue
    Write-Host "[1/4] Generating SSL certificate..." -ForegroundColor Yellow

    $ca = New-SelfSignedCertificate `
        -Subject "CN=THB Capture CA" `
        -KeyUsage CertSign,CRLSign `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(1) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser")
    $store.Open("ReadWrite")
    $store.Add($ca)
    $store.Close()

    $site = New-SelfSignedCertificate `
        -Subject "CN=$Target" `
        -DnsName @($Target, "*.thebackend.io") `
        -Signer $ca `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(1) `
        -CertStoreLocation "Cert:\CurrentUser\My"

    $site | Export-PfxCertificate `
        -FilePath $pfxPath `
        -Password (ConvertTo-SecureString $pfxPass -AsPlainText -Force) | Out-Null

    foreach ($thumb in @($ca.Thumbprint, $site.Thumbprint)) {
        try {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
            $s.Open("ReadWrite")
            $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $thumb }
            foreach ($c in $found) { $s.Remove($c) }
            $s.Close()
        } catch {}
    }

    Write-Host "    CA   : $($ca.Thumbprint)" -ForegroundColor DarkGray
    Write-Host "    Site : $($site.Thumbprint)" -ForegroundColor DarkGray
}

if (Test-Path $pfxPath) {
    Write-Host "[1/4] Reusing cert: $pfxPath" -ForegroundColor DarkGray
} else {
    New-CaptureCert
}

# Step 2: Compile C# interceptor
Write-Host "[2/4] Compiling interceptor..." -ForegroundColor Yellow

$csharp = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public static class SslTokenCapture {
    public static string  Token      = null;
    public static string  CapturedAt = null;
    public static int     Connections = 0;
    public static bool    Running    = false;

    static TcpListener      _listener;
    static X509Certificate2 _cert;
    static string           _upstreamIp;

    static string ResolveDirect(string host) {
        try {
            using (var udp = new UdpClient()) {
                udp.Connect("8.8.8.8", 53);
                var pkt = new List<byte>(new byte[] { 0xAB, 0xCD, 0x01, 0x00,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                foreach (var label in host.Split('.')) {
                    var b = Encoding.ASCII.GetBytes(label);
                    pkt.Add((byte)b.Length);
                    pkt.AddRange(b);
                }
                pkt.AddRange(new byte[] { 0x00, 0x00, 0x01, 0x00, 0x01 });
                udp.Send(pkt.ToArray(), pkt.Count);
                udp.Client.ReceiveTimeout = 3000;
                var ep = new IPEndPoint(IPAddress.Any, 0);
                var r = udp.Receive(ref ep);
                if (r.Length > 12 && r[7] > 0) {
                    int pos = 12;
                    while (pos < r.Length && r[pos] != 0) {
                        if ((r[pos] & 0xC0) == 0xC0) { pos += 2; break; }
                        pos += r[pos] + 1;
                    }
                    if (pos < r.Length && r[pos] == 0) pos++;
                    pos += 4;
                    while (pos + 10 < r.Length) {
                        int rtype  = (r[pos] << 8) | r[pos + 1];
                        int rdlen  = (r[pos + 8] << 8) | r[pos + 9];
                        pos += 10;
                        if (rtype == 1 && rdlen == 4 && pos + 4 <= r.Length)
                            return r[pos] + "." + r[pos+1] + "." + r[pos+2] + "." + r[pos+3];
                        pos += rdlen;
                    }
                }
            }
        } catch {}
        return null;
    }

    static X509Certificate2 LoadPfx(byte[] bytes, string pass) {
        // Try X509CertificateLoader.LoadPkcs12 (required on .NET 9+, available .NET 8.0.1+)
        // Use reflection so the code compiles on .NET Framework too
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies()) {
            var t = asm.GetType("System.Security.Cryptography.X509Certificates.X509CertificateLoader");
            if (t != null) {
                var m = t.GetMethod("LoadPkcs12",
                    System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static,
                    null,
                    new Type[]{ typeof(byte[]), typeof(string), typeof(X509KeyStorageFlags) },
                    null);
                if (m != null)
                    return (X509Certificate2)m.Invoke(null, new object[]{
                        bytes, pass,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet });
            }
        }
        // Fallback for .NET Framework / .NET 8 — called via Activator to bypass compile-time error
        return (X509Certificate2)Activator.CreateInstance(typeof(X509Certificate2),
            new object[]{ bytes, pass,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet });
    }

    public static string Start(string pfxPath, string pfxPass, string host) {
        try {
            var bytes = File.ReadAllBytes(pfxPath);
            _cert = LoadPfx(bytes, pfxPass);

            string ip = ResolveDirect(host);
            if (ip == null) { ip = "15.165.195.76"; }
            _upstreamIp = ip;
            Console.WriteLine("    Upstream: " + ip);

            _listener = new TcpListener(IPAddress.Loopback, 443);
            _listener.Start(50);
            Running = true;
            new Thread(AcceptLoop) { IsBackground = true }.Start();
            return "OK - listening on 127.0.0.1:443";
        } catch (Exception ex) {
            return "ERROR: " + ex.Message;
        }
    }

    static void AcceptLoop() {
        while (Running) {
            try {
                var c = _listener.AcceptTcpClient();
                Interlocked.Increment(ref Connections);
                new Thread(() => Handle(c)) { IsBackground = true }.Start();
            } catch { if (!Running) break; }
        }
    }

    static void Handle(TcpClient client) {
        SslStream ssl = null;
        TcpClient up  = null;
        SslStream upSsl = null;
        try {
            client.ReceiveTimeout = 15000;
            client.SendTimeout    = 15000;

            ssl = new SslStream(client.GetStream(), false);
            ssl.AuthenticateAsServer(_cert, false,
                System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13, false);

            var buf  = new List<byte>(4096);
            var one  = new byte[1];
            int tail = 0;
            int[] seq = new int[] { 13, 10, 13, 10 };
            while (buf.Count < 65536) {
                if (ssl.Read(one, 0, 1) == 0) break;
                buf.Add(one[0]);
                tail = (one[0] == seq[tail]) ? tail + 1 : (one[0] == seq[0] ? 1 : 0);
                if (tail == 4) break;
            }

            string hdrs = Encoding.UTF8.GetString(buf.ToArray());
            foreach (var line in hdrs.Split('\n')) {
                string ln = line.TrimEnd('\r');
                // BACKND uses custom "access_token" header (NOT Authorization: Bearer)
                if (ln.StartsWith("access_token:", StringComparison.OrdinalIgnoreCase)) {
                    string val = ln.Substring(13).Trim();
                    if (val.Length >= 32) {
                        Token      = "access_token: " + val;
                        CapturedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
                        Console.WriteLine("\n    *** TOKEN CAPTURED ***");
                        Console.WriteLine("    " + val.Substring(0, Math.Min(72, val.Length)));
                    }
                }
                // Also catch Authorization: Bearer just in case
                if (ln.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)) {
                    string val = ln.Substring(14).Trim();
                    if (val.Length > 20) {
                        Token      = val;
                        CapturedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
                        Console.WriteLine("\n    *** AUTH HEADER CAPTURED ***");
                        Console.WriteLine("    " + val.Substring(0, Math.Min(72, val.Length)));
                    }
                }
            }

            up    = new TcpClient();
            up.Connect(_upstreamIp, 443);
            up.ReceiveTimeout = 30000;
            up.SendTimeout    = 30000;
            upSsl = new SslStream(up.GetStream(), false, (s, c2, ch, e) => true);
            upSsl.AuthenticateAsClient("game.thebackend.io");

            byte[] raw = buf.ToArray();
            upSsl.Write(raw, 0, raw.Length);

            var t1 = new Thread(() => { try { Relay(ssl, upSsl); } catch {} }) { IsBackground = true };
            var t2 = new Thread(() => { try { Relay(upSsl, ssl); } catch {} }) { IsBackground = true };
            t1.Start(); t2.Start();
            t1.Join(60000);
        } catch {}
        finally {
            try { if (upSsl  != null) upSsl.Close();  } catch {}
            try { if (up     != null) up.Close();     } catch {}
            try { if (ssl    != null) ssl.Close();    } catch {}
            try { if (client != null) client.Close(); } catch {}
        }
    }

    static void Relay(Stream a, Stream b) {
        var buf = new byte[8192];
        int n;
        while ((n = a.Read(buf, 0, buf.Length)) > 0) b.Write(buf, 0, n);
    }

    public static void Stop() {
        Running = false;
        try { if (_listener != null) _listener.Stop(); } catch {}
    }
}
'@

try {
    Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction Stop
    Write-Host "    OK" -ForegroundColor DarkGray
} catch {
    Write-Host "Compile error: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Hosts file
Write-Host "[3/4] Setting DNS redirect..." -ForegroundColor Yellow

$hostsRaw = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
$entry    = "127.0.0.1 $Target $hostsMark"

if ($hostsRaw -notmatch [regex]::Escape($hostsMark)) {
    try {
        Add-Content -Path $hostsPath -Value ("`n" + $entry) -Encoding ASCII
        Write-Host "    Added: $entry" -ForegroundColor DarkGray
    } catch {
        Write-Host "    WARNING: cannot write hosts file - $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "    Already present: $Target -> 127.0.0.1" -ForegroundColor DarkGray
}

& ipconfig /flushdns | Out-Null
$resolved = [System.Net.Dns]::GetHostAddresses($Target) | Select-Object -First 1
Write-Host "    $Target -> $($resolved.IPAddressToString)" -ForegroundColor DarkGray

# Step 4: Start and wait
Write-Host "[4/4] Starting SSL interceptor on port 443..." -ForegroundColor Yellow

$startResult = [SslTokenCapture]::Start($pfxPath, $pfxPass, $Target)
if ($startResult -like "ERROR:*") {
    Write-Host "Failed: $startResult" -ForegroundColor Red
    & $cleanup
    exit 1
}
Write-Host "    $startResult" -ForegroundColor DarkGray

Write-Host ""
Write-Host "+-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|  Waiting for Bearer token...                        |" -ForegroundColor Cyan
Write-Host "|                                                     |" -ForegroundColor Cyan
Write-Host "|  >> RESTART THE GAME now                           |" -ForegroundColor Cyan
Write-Host "|  >> Token will be saved to: token.txt              |" -ForegroundColor Cyan
Write-Host "|  >> Press Ctrl+C to stop                           |" -ForegroundColor Cyan
Write-Host "+-----------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

$deadline  = (Get-Date).AddSeconds($TimeoutSec)
$lastConn  = 0

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500

    $tok  = [SslTokenCapture]::Token
    $conn = [SslTokenCapture]::Connections

    if ($conn -ne $lastConn) {
        $lastConn = $conn
        Write-Host "  [+] Connection #$conn received" -ForegroundColor Yellow
    }

    if ($tok) {
        Write-Host ""
        Write-Host "=====================================================" -ForegroundColor Green
        Write-Host "  TOKEN CAPTURED!" -ForegroundColor Green
        Write-Host "=====================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host $tok -ForegroundColor Cyan
        Write-Host ""

        $ts = [SslTokenCapture]::CapturedAt
        $content = "# Captured: $ts`n# Game: Taskbar Hero (BACKND)`n`n$tok"
        [System.IO.File]::WriteAllText($OutFile, $content, [System.Text.Encoding]::UTF8)
        Write-Host "  Saved: $OutFile" -ForegroundColor Green

        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            [System.Windows.Forms.Clipboard]::SetText($tok)
            Write-Host "  Copied to clipboard!" -ForegroundColor Green
        } catch {}

        Write-Host ""
        break
    }

    $remaining = [int]($deadline - (Get-Date)).TotalSeconds
    if ($remaining % 10 -eq 0 -and $remaining -gt 0) {
        Write-Host "  Waiting... ${remaining}s left  (connections so far: $conn)" -ForegroundColor DarkGray
    }
}

if (-not [SslTokenCapture]::Token) {
    Write-Host ""
    Write-Host "  Timeout - no token in ${TimeoutSec}s." -ForegroundColor Red
    Write-Host "  Make sure the game is running and was restarted AFTER this script." -ForegroundColor Yellow
}

& $cleanup
