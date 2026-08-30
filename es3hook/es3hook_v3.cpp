// es3hook_v3.cpp - IL2CPP hook with FIXED string reading and raw memory dump
// String layout: [vtable:8][monitor:8][int32_length:4 at +0x10][wchar_t chars: at +0x14]
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#pragma comment(lib, "psapi.lib")

static FILE* g_log = NULL;
#define LOG(fmt, ...) do { if(g_log){fprintf(g_log, fmt "\n", ##__VA_ARGS__);fflush(g_log);} } while(0)

// IL2CPP API
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

// MethodInfo->methodPointer is at offset 0
#define METHOD_PTR(m) (*(void**)(m))

struct Bp { void* addr; BYTE orig; };
static Bp    g_bps[32];
static int   g_bp_count = 0;
static volatile LONG g_captured = 0;

// Dump raw bytes at pointer (for definitive password capture)
static void DumpMem(LPCVOID ptr, const char* label) {
    __try {
        const BYTE* b = (const BYTE*)ptr;
        char line[256];
        char ascii[20];
        LOG("  %s at 0x%p:", label, ptr);
        for (int row = 0; row < 4; row++) {
            int off = row * 16;
            int hpos = 0;
            for (int j = 0; j < 16; j++) {
                hpos += sprintf_s(line + hpos, sizeof(line) - hpos, "%02X ", b[off+j]);
                ascii[j] = (b[off+j] >= 0x20 && b[off+j] < 0x7F) ? b[off+j] : '.';
            }
            ascii[16] = 0;
            LOG("    +0x%02X: %s  |%s|", off, line, ascii);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { LOG("  [AV at 0x%p]", ptr); }
}

// Correct IL2CPP String reading:
// +0x00 vtable  +0x08 monitor  +0x10 int32 length  +0x14 wchar_t chars[]
static void ReadStr(LPCVOID ptr, char* out, int outlen) {
    __try {
        const char* b = (const char*)ptr;
        int len = *(const int*)(b + 0x10);  // length at +0x10
        if (len < 0 || len > 4096) { sprintf_s(out, outlen, "[bad len=%d]", len); return; }
        if (len == 0) { out[0] = 0; return; }
        const wchar_t* wc = (const wchar_t*)(b + 0x14);  // chars at +0x14
        int n = 0;
        for (int i = 0; i < len && n < outlen - 1; i++, n++) {
            wchar_t c = wc[i];
            if (c >= 0x20 && c < 0x7f) out[n] = (char)c;
            else if (c == 0) break;
            else if (n + 7 < outlen) { sprintf_s(out+n, outlen-n, "\\u%04X", (unsigned)c); n += 5; }
        }
        out[n] = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, outlen, "[AV]"); }
}

static bool IsStr(LPCVOID ptr) {
    __try {
        const char* b = (const char*)ptr;
        ULONG_PTR vt = *(ULONG_PTR*)b;
        if (vt < 0x10000000000ULL) return false;
        int len = *(const int*)(b + 0x10);  // CORRECT: +0x10
        if (len < 0 || len > 4096) return false;
        if (len == 0) return true;
        wchar_t c0 = *(const wchar_t*)(b + 0x14);  // CORRECT: +0x14
        return (c0 >= 0x09 && c0 < 0x2000);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    void* hit = ep->ExceptionRecord->ExceptionAddress;
    for (int i = 0; i < g_bp_count; i++) {
        if (hit != g_bps[i].addr) continue;

        DWORD old = 0;
        VirtualProtect(hit, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)hit = g_bps[i].orig;
        VirtualProtect(hit, 1, old, &old);
        ep->ContextRecord->Rip = (ULONG_PTR)hit;

        CONTEXT* ctx = ep->ContextRecord;
        LOG("=== Rfc2898DeriveBytes::ctor HIT at 0x%p ===", hit);
        LOG("  RCX(this)=0x%llX  RDX=0x%llX  R8=0x%llX  R9(iters)=%d",
            ctx->Rcx, ctx->Rdx, ctx->R8, (int)(DWORD)ctx->R9);

        char buf[1024];

        // Always dump raw bytes at RDX (the password arg position)
        DumpMem((LPCVOID)ctx->Rdx, "RDX raw bytes");

        // Try to read as string with CORRECT offsets
        if (IsStr((LPCVOID)ctx->Rdx)) {
            ReadStr((LPCVOID)ctx->Rdx, buf, sizeof(buf));
            LOG(">>> PASSWORD (RDX as String, len=%d): \"%s\"",
                (int)*(const int*)((const char*)ctx->Rdx + 0x10), buf);
        } else {
            LOG("  RDX is NOT a string");
        }

        LOG("  R9 iterations = %d", (int)(DWORD)ctx->R9);

        // Also dump R8 (salt)
        DumpMem((LPCVOID)ctx->R8, "R8(salt) raw bytes");

        // Scan registers for any strings
        ULONG_PTR regs[] = {ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, ctx->R10, ctx->R11};
        for (int r = 0; r < 6; r++) {
            if (regs[r] > 0x10000000000ULL && IsStr((LPCVOID)regs[r])) {
                ReadStr((LPCVOID)regs[r], buf, sizeof(buf));
                LOG("  reg[%d]=0x%llX -> String: \"%s\"", r, regs[r], buf);
            }
        }

        InterlockedIncrement(&g_captured);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void TrySetBP(void* addr, const char* label) {
    if (!addr || g_bp_count >= 32) return;
    BYTE cur = *(BYTE*)addr;
    if (cur == 0xCC) { LOG("  SKIP (already INT3): 0x%p  [%s]", addr, label); return; }
    DWORD old = 0;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        LOG("  VirtualProtect FAILED 0x%p err=%lu", addr, GetLastError()); return;
    }
    g_bps[g_bp_count].addr = addr;
    g_bps[g_bp_count].orig = cur;
    *(BYTE*)addr = 0xCC;
    VirtualProtect(addr, 1, old, &old);
    LOG("  BP[%d] at 0x%p orig=0x%02X  [%s]", g_bp_count, addr, cur, label);
    g_bp_count++;
}

static DWORD WINAPI WorkerThread(LPVOID) {
    Sleep(4000);
    g_log = fopen("D:\\ES3_PASSWORD.txt", "a");
    if (!g_log) g_log = fopen("C:\\ES3_PASSWORD.txt", "a");
    if (!g_log) return 0;

    LOG("=========================================");
    LOG("=== ES3Hook v3 (fixed strings + dump) ===");
    LOG("=========================================");

    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("GameAssembly not found"); return 0; }

#define GP(fn) p_##fn = (Fn_##fn)GetProcAddress(hGA, "il2cpp_" #fn); LOG("  il2cpp_" #fn " = 0x%p", (void*)p_##fn)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(class_from_name); GP(class_get_methods); GP(method_get_name); GP(method_get_param_count);
#undef GP

    if (!p_domain_get || !p_class_from_name) { LOG("Exports missing"); return 0; }

    void* domain = p_domain_get();
    LOG("Domain=0x%p", domain);
    if (!domain) { LOG("NULL domain"); return 0; }

    size_t n = 0;
    void** asms = p_domain_get_assemblies(domain, &n);
    LOG("Assemblies=%zu", n);

    AddVectoredExceptionHandler(1, VehHandler);
    LOG("VEH registered");

    void* rfc_cls = nullptr;
    for (size_t i = 0; i < n && !rfc_cls; i++) {
        void* img = p_assembly_get_image(asms[i]);
        if (!img) continue;
        rfc_cls = p_class_from_name(img, "System.Security.Cryptography", "Rfc2898DeriveBytes");
        if (rfc_cls) LOG("Found Rfc2898DeriveBytes in asm[%zu]", i);
    }

    if (rfc_cls && p_class_get_methods) {
        LOG("--- Rfc2898DeriveBytes methods ---");
        void* iter = nullptr;
        while (true) {
            void* m = p_class_get_methods(rfc_cls, &iter);
            if (!m) break;
            const char* nm = p_method_get_name ? p_method_get_name(m) : "?";
            int np         = p_method_get_param_count ? p_method_get_param_count(m) : -1;
            void* fn       = METHOD_PTR(m);
            LOG("  '%s' params=%d ptr=0x%p", nm, np, fn);
            if (nm && strcmp(nm, ".ctor") == 0 && np >= 2) {
                char tag[64]; sprintf_s(tag, "ctor(p=%d)", np);
                TrySetBP(fn, tag);
            }
        }
    } else {
        LOG("Rfc2898DeriveBytes NOT found or no method iter");
    }

    LOG("BPs set: %d. Waiting...", g_bp_count);
    for (int t = 0; t < 1800 && g_captured == 0; t++) Sleep(1000);
    LOG(g_captured > 0 ? "=== CAPTURE COMPLETE ===" : "=== TIMEOUT ===");
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
