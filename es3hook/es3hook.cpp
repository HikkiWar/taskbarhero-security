// es3hook.cpp - captures ES3 encryption password via hardware breakpoint on PBKDF2 call
// Searches GameAssembly.dll for MOV R9D/R8D, 1000 (PBKDF2 iteration count)
// Sets hardware BP on the function entry, reads password string from registers/stack
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

static FILE*   g_log = NULL;
static LPVOID  g_BpAddr[8] = {};
static BYTE    g_OrigByte[8] = {};
static int     g_BpCount = 0;
static volatile LONG g_Captured = 0;

#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
    OutputDebugStringA(("[ES3HOOK] " fmt "\n")); } while(0)

// Read a System.String from IL2CPP memory
// Layout: [vtable:8][MonitorData:8][Length:4][chars:Length*2 UTF-16LE]
static void ReadIL2CppString(LPCVOID ptr, char* out, int outlen) {
    __try {
        const char* p = (const char*)ptr;
        int len = *(int*)(p + 0x14);
        if (len <= 0 || len > 512) {
            sprintf_s(out, outlen, "[badlen:%d]", len);
            return;
        }
        const wchar_t* chars = (const wchar_t*)(p + 0x18);
        int out_i = 0;
        for (int i = 0; i < len && out_i < outlen - 1; i++) {
            wchar_t c = chars[i];
            if (c >= 0x20 && c < 0x80) {
                out[out_i++] = (char)c;
            } else if (c < 0x20) {
                out[out_i++] = '?';
            } else {
                // encode multi-byte as hex escape
                if (out_i + 7 < outlen) {
                    sprintf_s(out + out_i, outlen - out_i, "\\u%04X", (unsigned)c);
                    out_i += 6;
                }
            }
        }
        out[out_i] = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        sprintf_s(out, outlen, "[AV]");
    }
}

// Read byte[] from IL2CPP (System_Byte_Array)
// Layout: [vtable:8][monitor:8][bounds_ptr:8][max_length:8][data:N bytes]
static void ReadIL2CppByteArray(LPCVOID ptr, char* out, int outlen) {
    __try {
        const char* p = (const char*)ptr;
        int len = *(int*)(p + 0x18);  // array length
        if (len <= 0 || len > 256) {
            sprintf_s(out, outlen, "[arr len %d]", len);
            return;
        }
        const BYTE* data = (const BYTE*)(p + 0x20);
        int out_i = 0;
        for (int i = 0; i < len && out_i + 3 < outlen; i++) {
            sprintf_s(out + out_i, outlen - out_i, "%02X", data[i]);
            out_i += 2;
        }
        out[out_i] = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        sprintf_s(out, outlen, "[AV]");
    }
}

// Probe whether a pointer looks like a valid IL2CPP string (rough check)
static bool LooksLikeIL2CppString(LPCVOID ptr) {
    __try {
        const char* p = (const char*)ptr;
        // vtable pointer should be non-null and look like a code address
        ULONG_PTR vtable = *(ULONG_PTR*)p;
        if (vtable < 0x100000000ULL) return false;
        int len = *(int*)(p + 0x14);
        if (len < 0 || len > 1024) return false;
        // check first char
        wchar_t c0 = *(wchar_t*)(p + 0x18);
        return (c0 >= 0x20 && c0 < 0x200);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// VEH handler - fires when our software breakpoint (INT3) is hit
static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    LPVOID addr = ep->ExceptionRecord->ExceptionAddress;

    for (int i = 0; i < g_BpCount; i++) {
        if (addr != g_BpAddr[i]) continue;

        // Restore original byte
        DWORD old = 0;
        VirtualProtect(g_BpAddr[i], 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)g_BpAddr[i] = g_OrigByte[i];
        VirtualProtect(g_BpAddr[i], 1, old, &old);
        // Step back so restored instruction runs
        ep->ContextRecord->Rip = (ULONG_PTR)g_BpAddr[i];

        CONTEXT* ctx = ep->ContextRecord;
        LOG("=== PBKDF2 BREAKPOINT HIT at 0x%llX ===", (ULONG_PTR)addr);
        LOG("RCX=0x%llX RDX=0x%llX R8=0x%llX R9=0x%llX",
            ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9);
        LOG("RSP=0x%llX RBP=0x%llX", ctx->Rsp, ctx->Rbp);

        // Log stack values (16 QWORDS)
        LOG("Stack dump:");
        for (int s = 0; s < 16; s++) {
            ULONG_PTR sv = 0;
            __try { sv = *(ULONG_PTR*)(ctx->Rsp + s * 8); } __except(1){}
            LOG("  [RSP+%02X] = 0x%llX", s*8, sv);
        }

        // Try to decode RCX, RDX, R8, R9 as strings
        char buf[512];
        ULONG_PTR regs[4] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9 };
        const char* reg_names[4] = { "RCX", "RDX", "R8", "R9" };
        for (int r = 0; r < 4; r++) {
            if (LooksLikeIL2CppString((LPCVOID)regs[r])) {
                ReadIL2CppString((LPCVOID)regs[r], buf, sizeof(buf));
                LOG("  %s as String: \"%s\"", reg_names[r], buf);
            }
            // Also try as byte array
            if (regs[r] > 0x100000000ULL) {
                ReadIL2CppByteArray((LPCVOID)regs[r], buf, sizeof(buf));
                if (strlen(buf) > 0 && strlen(buf) < 100)
                    LOG("  %s as byte[]: %s", reg_names[r], buf);
            }
        }

        // Also check stack-passed args: [RSP+0x20], [RSP+0x28], [RSP+0x30], [RSP+0x38]
        for (int s = 4; s < 12; s++) {
            ULONG_PTR sv = 0;
            __try { sv = *(ULONG_PTR*)(ctx->Rsp + s * 8); } __except(1){}
            if (sv > 0x100000000ULL && LooksLikeIL2CppString((LPCVOID)sv)) {
                ReadIL2CppString((LPCVOID)sv, buf, sizeof(buf));
                LOG("  [RSP+0x%02X] as String: \"%s\"", s*8, buf);
            }
        }

        InterlockedIncrement(&g_Captured);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Find function start by scanning backwards for common x64 prologue
static LPVOID FindFunctionStart(BYTE* addr, BYTE* base) {
    for (int i = 1; i < 512 && addr - i >= base; i++) {
        BYTE* p = addr - i;
        // SUB RSP, imm8: 48 83 EC xx
        if (p[0]==0x48 && p[1]==0x83 && p[2]==0xEC) return p;
        // SUB RSP, imm32: 48 81 EC
        if (p[0]==0x48 && p[1]==0x81 && p[2]==0xEC) return p;
        // Common: 4? 89 5C 24 XX (MOV [RSP+xx], RBX) as first prologue save
        // also look for cc cc cc cc (function padding)
        if (i >= 4) {
            if (p[-1]==0xCC && p[0]!=0xCC) return p;
            if (p[-1]==0x90 && p[-2]==0x90 && p[0]!=0x90) return p;
        }
    }
    return addr; // fallback: break at the found pattern itself
}

static void SetSoftwareBP(LPVOID addr) {
    if (g_BpCount >= 8) return;
    DWORD old = 0;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        LOG("VirtualProtect FAILED for 0x%llX", (ULONG_PTR)addr);
        return;
    }
    g_OrigByte[g_BpCount] = *(BYTE*)addr;
    *(BYTE*)addr = 0xCC; // INT3
    VirtualProtect(addr, 1, old, &old);
    g_BpAddr[g_BpCount] = addr;
    g_BpCount++;
    LOG("Software BP set at 0x%llX (orig byte 0x%02X)", (ULONG_PTR)addr, g_OrigByte[g_BpCount-1]);
}

static DWORD WINAPI WorkerThread(LPVOID) {
    Sleep(2000); // wait for game to fully load

    g_log = fopen("C:\\ES3_PASSWORD.txt", "a");
    if (!g_log) g_log = fopen("D:\\ES3_PASSWORD.txt", "a");
    LOG("=== ES3Hook loaded, searching for PBKDF2 patterns ===");

    // Get GameAssembly.dll info
    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("GameAssembly.dll NOT FOUND"); return 0; }

    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hGA, &mi, sizeof(mi));
    BYTE* base = (BYTE*)mi.lpBaseOfDll;
    SIZE_T size = mi.SizeOfImage;
    LOG("GameAssembly.dll base=0x%llX size=0x%zX", (ULONG_PTR)base, size);

    // Register VEH
    AddVectoredExceptionHandler(1, VehHandler);
    LOG("VEH registered");

    // Pattern 1: MOV R9D, 1000 = 41 B9 E8 03 00 00 (4th arg = iterations)
    // Pattern 2: MOV R8D, 1000 = 41 B8 E8 03 00 00 (3rd arg = iterations)
    BYTE pat1[] = {0x41, 0xB9, 0xE8, 0x03, 0x00, 0x00};
    BYTE pat2[] = {0x41, 0xB8, 0xE8, 0x03, 0x00, 0x00};

    int found = 0;
    for (SIZE_T i = 512; i < size - 6; i++) {
        bool m1 = memcmp(base+i, pat1, 6) == 0;
        bool m2 = memcmp(base+i, pat2, 6) == 0;
        if (!m1 && !m2) continue;

        BYTE* hit = base + i;
        LOG("Pattern %s found at 0x%llX (offset 0x%zX)", m1?"R9D":"R8D", (ULONG_PTR)hit, i);

        // Find function start
        BYTE* fn_start = (BYTE*)FindFunctionStart(hit, base);
        LOG("  -> function start estimated at 0x%llX", (ULONG_PTR)fn_start);

        // Set breakpoint at function start
        SetSoftwareBP(fn_start);
        found++;
        if (found >= 6) break; // limit to first 6 hits
    }

    LOG("Setup done: %d breakpoints set. Waiting for ES3 save...", found);

    // Wait up to 30 minutes for capture
    for (int t = 0; t < 1800 && g_Captured == 0; t++) {
        Sleep(1000);
    }

    if (g_Captured > 0) {
        LOG("=== CAPTURE COMPLETE - check log above for password ===");
    } else {
        LOG("=== TIMEOUT: no PBKDF2 call captured ===");
    }
    if (g_log) fclose(g_log);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
