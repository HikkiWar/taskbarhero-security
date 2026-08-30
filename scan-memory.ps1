# scan-memory.ps1
# Scans game process memory for Bearer tokens (both ASCII and UTF-16LE)
# Run while the game is active and making API calls

param(
    [string]$ProcessName = "TaskbarHero",
    [int]   $IntervalMs  = 300,
    [string]$OutFile     = "$PSScriptRoot\token.txt"
)

Add-Type @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class MemScan {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32.dll")] static extern bool  CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool  ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int sz, out int read);
    [DllImport("kernel32.dll")] static extern int   VirtualQueryEx(IntPtr h, IntPtr addr, out MEMINFO mi, int sz);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMINFO {
        public IntPtr BaseAddress, AllocationBase;
        public uint   AllocationProtect, __pad;
        public IntPtr RegionSize;
        public uint   State, Protect, Type;
    }

    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY   = 0x0400;
    const uint MEM_COMMIT      = 0x1000;
    // Readable pages: PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
    static bool Readable(uint p) {
        p &= 0xFF;
        return p == 0x02 || p == 0x04 || p == 0x20 || p == 0x40;
    }

    // Search needle in haystack, return all offsets
    static List<int> Find(byte[] hay, byte[] needle) {
        var hits = new List<int>();
        int last = hay.Length - needle.Length;
        for (int i = 0; i <= last; i++) {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) {
                if (hay[i+j] != needle[j]) { ok = false; break; }
            }
            if (ok) hits.Add(i);
        }
        return hits;
    }

    // Extract printable ASCII string starting at offset (max len)
    static string ExtractAscii(byte[] buf, int start, int max) {
        var sb = new StringBuilder();
        for (int i = start; i < buf.Length && i < start+max; i++) {
            byte b = buf[i];
            if (b == 0) break;
            if (b >= 0x20 && b < 0x7F) sb.Append((char)b); else break;
        }
        return sb.ToString();
    }

    // Extract UTF-16LE string starting at offset
    static string ExtractUtf16(byte[] buf, int start, int max) {
        var chars = new List<char>();
        for (int i = start; i+1 < buf.Length && chars.Count < max; i += 2) {
            ushort ch = (ushort)(buf[i] | (buf[i+1] << 8));
            if (ch == 0) break;
            if (ch >= 0x20 && ch < 0x7F) chars.Add((char)ch);
            else if (ch > 0x7F) chars.Add('?');  // non-ASCII UTF-16
            else break;
        }
        return new string(chars.ToArray());
    }

    public static List<string> ScanPid(int pid) {
        var results = new List<string>();
        var seen    = new System.Collections.Generic.HashSet<string>();

        IntPtr hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY, false, pid);
        if (hProc == IntPtr.Zero) { results.Add("ERROR:OpenProcess failed"); return results; }

        // Patterns to find
        // ASCII "Bearer eyJ"
        byte[] patBearerA = Encoding.ASCII.GetBytes("Bearer eyJ");
        // UTF-16LE "Bearer eyJ"
        byte[] patBearerU = Encoding.Unicode.GetBytes("Bearer eyJ");
        // ASCII "eyJ" alone (fallback)
        byte[] patEyjA    = Encoding.ASCII.GetBytes("eyJ");
        // UTF-16LE "eyJ"
        byte[] patEyjU    = Encoding.Unicode.GetBytes("eyJ");
        // ASCII thebackend token prefix
        byte[] patBackA   = Encoding.ASCII.GetBytes("thebackend.io");

        const int CHUNK = 1024 * 1024; // 1MB chunks
        byte[] buf = new byte[CHUNK];
        long addr = 0;

        while (addr < 0x7FFFFFFFFFFF) {
            MEMINFO mi;
            int qr = VirtualQueryEx(hProc, (IntPtr)addr, out mi, Marshal.SizeOf(typeof(MEMINFO)));
            if (qr == 0) break;

            long regionSize = mi.RegionSize.ToInt64();
            if (regionSize <= 0) break;

            if (mi.State == MEM_COMMIT && Readable(mi.Protect)) {
                long regionBase = mi.BaseAddress.ToInt64();
                long regionEnd  = regionBase + regionSize;

                for (long pos = regionBase; pos < regionEnd; pos += CHUNK - 32) {
                    int toRead = (int)Math.Min(CHUNK, regionEnd - pos);
                    int nRead  = 0;
                    if (!ReadProcessMemory(hProc, (IntPtr)pos, buf, toRead, out nRead) || nRead < 10)
                        continue;

                    // Search for "Bearer eyJ" ASCII
                    foreach (int off in Find(buf, patBearerA)) {
                        string s = ExtractAscii(buf, off, 512);
                        if (s.Length > 30 && !seen.Contains(s)) {
                            seen.Add(s); results.Add("ASCII:" + s);
                        }
                    }

                    // Search for "Bearer eyJ" UTF-16
                    foreach (int off in Find(buf, patBearerU)) {
                        string s = ExtractUtf16(buf, off, 512);
                        if (s.Length > 30 && !seen.Contains(s)) {
                            seen.Add(s); results.Add("UTF16:" + s);
                        }
                    }

                    // Search for standalone "eyJ" ASCII (longer hits only)
                    foreach (int off in Find(buf, patEyjA)) {
                        string s = ExtractAscii(buf, off, 512);
                        // Must look like a JWT: has 2+ dots, long enough
                        if (s.Length > 80 && s.Contains(".") && !seen.Contains(s)) {
                            // Count dots
                            int dots = 0; foreach (char c in s) if (c == '.') dots++;
                            if (dots >= 2) { seen.Add(s); results.Add("JWTA:" + s); }
                        }
                    }

                    // Search for standalone "eyJ" UTF-16
                    foreach (int off in Find(buf, patEyjU)) {
                        string s = ExtractUtf16(buf, off, 512);
                        if (s.Length > 80 && s.Contains(".") && !seen.Contains(s)) {
                            int dots = 0; foreach (char c in s) if (c == '.') dots++;
                            if (dots >= 2) { seen.Add(s); results.Add("JWTU:" + s); }
                        }
                    }
                }
            }

            addr += regionSize;
        }

        CloseHandle(hProc);
        return results;
    }
}
'@ -Language CSharp

$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    Write-Host "Process '$ProcessName' not found. Start the game first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Memory Token Scanner ===" -ForegroundColor Cyan
Write-Host "  Target : $ProcessName (PID $($proc.Id))" -ForegroundColor DarkGray
Write-Host "  Scan   : every ${IntervalMs}ms, all readable regions" -ForegroundColor DarkGray
Write-Host "  Search : 'Bearer eyJ' ASCII + UTF-16, standalone JWT patterns" -ForegroundColor DarkGray
Write-Host "  Output : $OutFile" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Do something in the game (login, menu, match start) to trigger API calls." -ForegroundColor Yellow
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

$found = @{}
$scanCount = 0

while ($true) {
    $scanCount++
    $results = [MemScan]::ScanPid($proc.Id)

    foreach ($r in $results) {
        if ($r.StartsWith("ERROR:")) {
            Write-Host "  [!] $r" -ForegroundColor Red; break
        }
        $key = $r.Substring(0, [Math]::Min(40, $r.Length))
        if (-not $found.ContainsKey($key)) {
            $found[$key] = $r
            $tag  = $r.Substring(0,5)
            $data = $r.Substring(6)

            Write-Host ""
            Write-Host "  [$tag] FOUND at scan #$scanCount" -ForegroundColor Green
            Write-Host "  $($data.Substring(0, [Math]::Min(120, $data.Length)))" -ForegroundColor Cyan

            # Write all to file
            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $OutFile -Value "[$ts][$tag] $data"

            # If it looks like a full Bearer token, also copy to clipboard
            if ($data -like "Bearer eyJ*" -and $data.Length -gt 50) {
                try {
                    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                    [System.Windows.Forms.Clipboard]::SetText($data)
                    Write-Host "  → Copied to clipboard!" -ForegroundColor Green
                } catch {}
            }
        }
    }

    if ($scanCount % 20 -eq 0) {
        Write-Host "  scan #$scanCount  found so far: $($found.Count)" -ForegroundColor DarkGray
    }

    Start-Sleep -Milliseconds $IntervalMs
}
