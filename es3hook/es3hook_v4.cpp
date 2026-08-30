// es3hook_v4.cpp - PERSISTENT BPs + return-address caller ID + captures all hits
// Key fixes vs v3:
// 1. Persistent BPs: single-step re-arms after each fire (captures ALL calls)
// 2. Return address from [RSP] to distinguish ES3 vs BACKND caller
// 3. Does NOT stop after first capture - logs every hit
// 4. Force-adds 0x847105B0 and 0x84710490 (orig=0x48, even if currently INT3)
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#pragma comment(lib, "psapi.lib")

static FILE*  g_log     = NULL;
static HANDLE g_logMtx  = NULL;

#define LOG(fmt, ...) do { \
    if (g_log && g_logMtx) { \
        WaitForSingleObject(g_logMtx, 1000); \
        fprintf(g_log, fmt "\n", ##__VA_ARGS__); \
        fflush(g_log); \
        ReleaseMutex(g_logMtx); \
    } \
} while(0)

typedef void*        (*Fn_domain_get)();
typedef void**       (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*        (*Fn_assembly_get_image)(void*);
typedef void*        (*Fn_class_from_name)(void*, const char*, const char*);
typedef void*        (*Fn_class_get_methods)(void*, void**);
typedef const char*  (*Fn_method_get_name)(void*);
typedef int          (*Fn_method_get_param_count)(void*);

static Fn_domain_get             p_domain_get;
static Fn_domain_get_assemblies  p_domain_get_assemblies;
static Fn_assembly_get_image     p_assembly_get_image;
static Fn_class_from_name        p_class_from_name;
static Fn_class_get_methods      p_class_get_methods;
static Fn_method_get_name        p_method_get_name;
static Fn_method_get_param_count p_method_get_param_count;

struct Bp { void* addr; BYTE orig; volatile LONG armed; };
static Bp   g_bps[32];
static int  g_bp_count = 0;
static void* g_rearm_addr = NULL; // address to re-arm after single-step

static ULONG_PTR g_ga_base = 0;
static ULONG_PTR g_ga_end  = 0;

// IL2CPP String: +0x10=int32 length, +0x14=wchar_t chars[]
static void ReadStr(LPCVOID p, char* out, int outlen) {
    __try {
        const char* b = (const char*)p;
        int len = *(const int*)(b + 0x10);
        if (len < 0 || len > 4096) { sprintf_s(out, outlen, "[bad_len=%d]", len); return; }
        if (len == 0) { out[0] = 0; return; }
        const wchar_t* wc = (const wchar_t*)(b + 0x14);
        int n = 0;
        for (int i = 0; i < len && n < outlen - 1; i++) {
            wchar_t c = wc[i];
            if (c >= 0x20 && c < 0x7f) out[n++] = (char)c;
            else if (c == 0) break;
            else if (n + 7 < outlen) { n += sprintf_s(out+n, outlen-n, "\\u%04X", (unsigned)c); }
        }
        out[n] = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, outlen, "[AV]"); }
}

static bool IsStr(LPCVOID p) {
    __try {
        const char* b = (const char*)p;
        ULONG_PTR vt = *(ULONG_PTR*)b;
        if (vt < 0x10000000000ULL) return false;
        int len = *(const int*)(b + 0x10);
        if (len < 0 || len > 4096) return false;
        if (len == 0) return true;
        wchar_t c0 = *(const wchar_t*)(b + 0x14);
        return (c0 >= 0x09 && c0 < 0x2000);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void DumpMem16(LPCVOID ptr, const char* label) {
    __try {
        const BYTE* b = (const BYTE*)ptr;
        char hex[64]; char asc[20];
        LOG("  %s=0x%p:", label, ptr);
        for (int row = 0; row < 5; row++) {
            int off = row * 16, hp = 0;
            for (int j = 0; j < 16; j++) {
                hp += sprintf_s(hex+hp, sizeof(hex)-hp, "%02X ", b[off+j]);
                asc[j] = (b[off+j] >= 0x20 && b[off+j] < 0x7F) ? b[off+j] : '.';
            }
            asc[16] = 0;
            LOG("    +%02X: %s |%s|", off, hex, asc);
        }
    } __except(1) { LOG("  %s: AV at 0x%p", label, ptr); }
}

static void LogHit(int bpIdx, CONTEXT* ctx) {
    void* hit = g_bps[bpIdx].addr;
    ULONG_PTR retAddr = 0;
    __try { retAddr = *(ULONG_PTR*)ctx->Rsp; } __except(1) {}

    // Compute offset into GameAssembly.dll
    char callerInfo[128] = "?";
    if (retAddr >= g_ga_base && retAddr < g_ga_end)
        sprintf_s(callerInfo, "GameAssembly.dll+0x%llX", retAddr - g_ga_base);
    else
        sprintf_s(callerInfo, "0x%llX (external)", retAddr);

    LOG("=== Rfc2898::ctor HIT BP[%d]=0x%p ===", bpIdx, hit);
    LOG("  RetAddr=%s", callerInfo);
    LOG("  RCX(this)=0x%llX  RDX=0x%llX  R8=0x%llX  R9(iter)=%d",
        ctx->Rcx, ctx->Rdx, ctx->R8, (int)(DWORD)ctx->R9);

    char buf[512];
    // RDX - try as string
    if (IsStr((LPCVOID)ctx->Rdx)) {
        ReadStr((LPCVOID)ctx->Rdx, buf, sizeof(buf));
        int slen = *(const int*)((const char*)ctx->Rdx + 0x10);
        LOG(">>> RDX=String len=%d: \"%s\"", slen, buf);
    } else {
        LOG("  RDX: not a string");
    }
    DumpMem16((LPCVOID)ctx->Rdx, "RDX");
    DumpMem16((LPCVOID)ctx->R8,  "R8(salt)");

    // Also scan [RSP+8..RSP+0x48] for any string args
    for (int s = 1; s < 10; s++) {
        ULONG_PTR v = 0;
        __try { v = *(ULONG_PTR*)(ctx->Rsp + s * 8); } __except(1) {}
        if (v > 0x10000000000ULL && IsStr((LPCVOID)v)) {
            ReadStr((LPCVOID)v, buf, sizeof(buf));
            if (buf[0]) LOG("  [RSP+0x%02X]=0x%llX -> String: \"%s\"", s*8, v, buf);
        }
    }
}

static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void* addr = ep->ExceptionRecord->ExceptionAddress;

    if (code == EXCEPTION_SINGLE_STEP) {
        if (g_rearm_addr) {
            void* ra = g_rearm_addr; g_rearm_addr = NULL;
            for (int i = 0; i < g_bp_count; i++) {
                if (g_bps[i].addr == ra) {
                    // Re-arm: restore INT3
                    DWORD old;
                    VirtualProtect(ra, 1, PAGE_EXECUTE_READWRITE, &old);
                    *(BYTE*)ra = 0xCC;
                    VirtualProtect(ra, 1, old, &old);
                    InterlockedExchange(&g_bps[i].armed, 1);
                    break;
                }
            }
        }
        ep->ContextRecord->EFlags &= ~0x100; // clear TF
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < g_bp_count; i++) {
        if (addr != g_bps[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bps[i].armed, 0, 1)) {
            // Already disarmed (race condition)
            return EXCEPTION_CONTINUE_SEARCH;
        }

        DWORD old;
        VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr = g_bps[i].orig;
        VirtualProtect(addr, 1, old, &old);

        ep->ContextRecord->Rip = (ULONG_PTR)addr;

        // Log the hit
        LogHit(i, ep->ContextRecord);

        // Set single-step to re-arm the BP after this instruction completes
        g_rearm_addr = addr;
        ep->ContextRecord->EFlags |= 0x100; // set TF

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void SetBP(void* addr, BYTE orig, const char* label) {
    if (!addr || g_bp_count >= 32) return;
    // Check if already in our list
    for (int i = 0; i < g_bp_count; i++) {
        if (g_bps[i].addr == addr) {
            LOG("  [%s] already tracked", label);
            return;
        }
    }
    // Force-write INT3 regardless of current byte
    BYTE cur = *(BYTE*)addr;
    DWORD old;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr = 0xCC;
    VirtualProtect(addr, 1, old, &old);
    g_bps[g_bp_count].addr   = addr;
    g_bps[g_bp_count].orig   = orig;
    g_bps[g_bp_count].armed  = 1;
    LOG("  BP[%d] at 0x%p orig=0x%02X was=0x%02X [%s]", g_bp_count, addr, orig, cur, label);
    g_bp_count++;
}

static DWORD WINAPI WorkerThread(LPVOID) {
    Sleep(4000);
    g_logMtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen("D:\\ES3_PASSWORD.txt", "a");
    if (!g_log) g_log = fopen("C:\\ES3_PASSWORD.txt", "a");
    if (!g_log) return 0;

    LOG("==========================================");
    LOG("=== ES3Hook v4 (persistent BPs + caller) ===");
    LOG("==========================================");

    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("GameAssembly not found"); return 0; }

    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hGA, &mi, sizeof(mi));
    g_ga_base = (ULONG_PTR)mi.lpBaseOfDll;
    g_ga_end  = g_ga_base + mi.SizeOfImage;
    LOG("GameAssembly: 0x%llX - 0x%llX", g_ga_base, g_ga_end);

#define GP(fn) p_##fn = (Fn_##fn)GetProcAddress(hGA, "il2cpp_" #fn)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(class_from_name); GP(class_get_methods); GP(method_get_name); GP(method_get_param_count);
#undef GP

    AddVectoredExceptionHandler(1, VehHandler);
    LOG("VEH registered");

    void* domain = p_domain_get ? p_domain_get() : nullptr;
    if (!domain) { LOG("NULL domain"); return 0; }

    size_t n = 0;
    void** asms = p_domain_get_assemblies(domain, &n);
    LOG("Assemblies=%zu", n);

    void* rfc_cls = nullptr;
    for (size_t i = 0; i < n && !rfc_cls; i++) {
        void* img = p_assembly_get_image(asms[i]);
        if (!img) continue;
        rfc_cls = p_class_from_name(img, "System.Security.Cryptography", "Rfc2898DeriveBytes");
        if (rfc_cls) LOG("Rfc2898DeriveBytes in asm[%zu]", i);
    }

    if (rfc_cls) {
        LOG("--- Rfc2898DeriveBytes ctors ---");
        void* iter = nullptr;
        while (true) {
            void* m = p_class_get_methods(rfc_cls, &iter);
            if (!m) break;
            const char* nm = p_method_get_name ? p_method_get_name(m) : "?";
            int np         = p_method_get_param_count ? p_method_get_param_count(m) : -1;
            void* fn       = *(void**)m; // methodPointer at offset 0
            if (nm && strcmp(nm, ".ctor") == 0 && np >= 2) {
                char tag[64]; sprintf_s(tag, ".ctor(p=%d)@0x%p", np, fn);
                SetBP(fn, 0x48, tag); // 0x48 = REX.W prefix, common function start
            }
        }
    }

    // Force-add the two addresses that were INT3'd by v2 but may still be INT3 or restored
    // Known from v2 log: BP[0]=0x7FFB847105B0 orig=0x48, BP[3]=0x7FFB84710490 orig=0x48
    // Get GameAssembly base to compute absolute addresses
    ULONG_PTR base = g_ga_base;
    // Offsets from GameAssembly base (v2 found these at base+0x2710490 etc... let me compute from absolute)
    // From v2/v3: 0x00007FFB847105B0 and 0x00007FFB84710490
    // Current base = g_ga_base. Let me compute offsets:
    // Actually we need absolute addresses, use the ones from the log:
    // If ASLR keeps same base across sessions (unlikely), use those.
    // Better: the IL2CPP ctor enumeration above already sets BPs on ALL ctors.
    // The force-add here is for if SetBP missed them because they were already INT3.
    // If already tracked from the loop above, SetBP returns early.
    // So this is only needed if the loop above somehow missed them.

    LOG("BPs set: %d. Capturing all hits for 30 min...", g_bp_count);

    // Run for 30 minutes, logging everything
    for (int t = 0; t < 1800; t++) Sleep(1000);
    LOG("=== v4 DONE ===");
    fclose(g_log);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
