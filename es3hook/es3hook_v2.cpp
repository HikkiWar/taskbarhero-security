// es3hook_v2.cpp - IL2CPP API approach
// Finds Rfc2898DeriveBytes::ctor at runtime via il2cpp_class_from_name
// il2cpp_method_get_pointer is NOT exported; use MethodInfo->methodPointer (offset 0)
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "psapi.lib")

static FILE* g_log = NULL;
#define LOG(fmt, ...) do { \
    if (g_log) { fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log); } \
} while(0)

// IL2CPP API – all confirmed exported in this build
typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef void*       (*Fn_class_from_name)(void*, const char*, const char*);
typedef void*       (*Fn_class_get_methods)(void*, void**);
typedef const char* (*Fn_method_get_name)(void*);
typedef int         (*Fn_method_get_param_count)(void*);
typedef const char* (*Fn_class_get_name)(void*);

static Fn_domain_get          p_domain_get;
static Fn_domain_get_assemblies p_domain_get_assemblies;
static Fn_assembly_get_image  p_assembly_get_image;
static Fn_class_from_name     p_class_from_name;
static Fn_class_get_methods   p_class_get_methods;
static Fn_method_get_name     p_method_get_name;
static Fn_method_get_param_count p_method_get_param_count;

// Il2CppMethodInfo layout (IL2CPP ~v27+):
// offset 0  : methodPointer (function ptr)
// offset 8  : invoker_method
// offset 16 : name (const char*)
// ...
static inline void* GetMethodFnPtr(void* methodInfo) {
    if (!methodInfo) return nullptr;
    return *(void**)methodInfo; // methodPointer at offset 0
}

// Breakpoints
struct BpSlot { void* addr; BYTE orig; };
static BpSlot g_bps[32];
static int    g_bp_count = 0;
static volatile LONG g_captured = 0;

// Read IL2CPP System.String
// IL2CPP String layout (Unity 6, 64-bit):
//   +0x00..+0x07  vtable/klass ptr
//   +0x08..+0x0F  MonitorData*
//   +0x10..+0x13  int32_t _stringLength
//   +0x14..       wchar_t _firstChar[]  (UTF-16LE, null-terminated)
static void ReadStr(LPCVOID p, char* out, int outlen) {
    __try {
        const char* b = (const char*)p;
        int len = *(int*)(b + 0x10);  // CORRECT: length at +0x10
        if (len < 0 || len > 2048) { sprintf_s(out, outlen, "[bad len=%d]", len); return; }
        const wchar_t* wc = (const wchar_t*)(b + 0x14);  // CORRECT: chars at +0x14
        int n = 0;
        for (int i = 0; i < len && n < outlen - 1; i++, n++) {
            wchar_t c = wc[i];
            if (c >= 0x20 && c < 0x7f) out[n] = (char)c;
            else if (c == 0) break;
            else {
                if (n + 7 < outlen) { sprintf_s(out + n, outlen - n, "\\u%04X", (unsigned)c); n += 5; }
            }
        }
        out[n] = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, outlen, "[AV]"); }
}

static bool IsStr(LPCVOID p) {
    __try {
        const char* b = (const char*)p;
        ULONG_PTR vt = *(ULONG_PTR*)b;
        if (vt < 0x10000000000ULL) return false;
        int len = *(int*)(b + 0x10);  // CORRECT: length at +0x10
        if (len < 0 || len > 4096) return false;
        if (len == 0) return true;
        wchar_t c0 = *(wchar_t*)(b + 0x14);  // CORRECT: first char at +0x14
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
        LOG("=== PBKDF2 .ctor HIT at 0x%p ===", hit);
        LOG("  RCX(this)=0x%llX  RDX(pwd)=0x%llX  R8(salt)=0x%llX  R9(iters)=%d",
            ctx->Rcx, ctx->Rdx, ctx->R8, (int)ctx->R9);

        char buf[1024];
        // RDX = password string
        if (IsStr((LPCVOID)ctx->Rdx)) {
            ReadStr((LPCVOID)ctx->Rdx, buf, sizeof(buf));
            LOG(">>> PASSWORD (RDX): \"%s\" <<<", buf);
        } else {
            LOG("  RDX is NOT a string (0x%llX)", ctx->Rdx);
            // Scan registers and stack
            ULONG_PTR regs[] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, ctx->R10, ctx->R11 };
            for (int r = 0; r < 6; r++) {
                if (regs[r] > 0x10000000000ULL && IsStr((LPCVOID)regs[r])) {
                    ReadStr((LPCVOID)regs[r], buf, sizeof(buf));
                    LOG("  reg[%d]=0x%llX -> String: \"%s\"", r, regs[r], buf);
                }
            }
            for (int s = 0; s < 32; s++) {
                ULONG_PTR sv = 0;
                __try { sv = *(ULONG_PTR*)(ctx->Rsp + s * 8); } __except(1) {}
                if (sv > 0x10000000000ULL && IsStr((LPCVOID)sv)) {
                    ReadStr((LPCVOID)sv, buf, sizeof(buf));
                    LOG("  [RSP+0x%02X]=0x%llX -> String: \"%s\"", s*8, sv, buf);
                }
            }
        }
        InterlockedIncrement(&g_captured);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void TrySetBP(void* addr, const char* label) {
    if (!addr || g_bp_count >= 32) return;
    // Don't double-BP: skip if already INT3
    BYTE cur = *(BYTE*)addr;
    if (cur == 0xCC) {
        LOG("  SKIP: 0x%p already INT3 (%s)", addr, label);
        return;
    }
    DWORD old = 0;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        LOG("  VirtualProtect FAILED 0x%p err=%lu", addr, GetLastError());
        return;
    }
    g_bps[g_bp_count].addr = addr;
    g_bps[g_bp_count].orig = cur;
    *(BYTE*)addr = 0xCC;
    VirtualProtect(addr, 1, old, &old);
    LOG("  BP[%d] set at 0x%p orig=0x%02X  (%s)", g_bp_count, addr, cur, label);
    g_bp_count++;
}

static DWORD WINAPI WorkerThread(LPVOID) {
    Sleep(4000);

    g_log = fopen("D:\\ES3_PASSWORD.txt", "a");
    if (!g_log) g_log = fopen("C:\\ES3_PASSWORD.txt", "a");
    if (!g_log) return 0;

    LOG("=========================================");
    LOG("=== ES3Hook v2 (IL2CPP API)  START    ===");
    LOG("=========================================");

    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("GameAssembly.dll NOT found!"); fclose(g_log); return 0; }

#define GP(fn) p_##fn = (Fn_##fn)GetProcAddress(hGA, "il2cpp_" #fn); \
    LOG("  il2cpp_" #fn " = 0x%p %s", (void*)p_##fn, p_##fn ? "OK" : "MISSING")
    GP(domain_get);
    GP(domain_get_assemblies);
    GP(assembly_get_image);
    GP(class_from_name);
    GP(class_get_methods);
    GP(method_get_name);
    GP(method_get_param_count);
#undef GP

    if (!p_domain_get || !p_class_from_name || !p_class_get_methods) {
        LOG("Required exports missing - aborting IL2CPP path");
        goto fallback;
    }

    {
        void* domain = p_domain_get();
        LOG("Domain = 0x%p", domain);
        if (!domain) { LOG("NULL domain!"); goto fallback; }

        size_t n = 0;
        void** asms = p_domain_get_assemblies(domain, &n);
        LOG("Assembly count = %zu", n);

        AddVectoredExceptionHandler(1, VehHandler);
        LOG("VEH registered");

        void* rfc_cls = nullptr;
        void* es3_cls = nullptr;

        for (size_t i = 0; i < n; i++) {
            void* img = p_assembly_get_image(asms[i]);
            if (!img) continue;
            if (!rfc_cls) {
                rfc_cls = p_class_from_name(img, "System.Security.Cryptography", "Rfc2898DeriveBytes");
                if (rfc_cls) LOG("  Rfc2898DeriveBytes found in asm[%zu]", i);
            }
            if (!es3_cls) {
                es3_cls = p_class_from_name(img, "", "ES3Settings");
                if (es3_cls) LOG("  ES3Settings found in asm[%zu]", i);
            }
            if (rfc_cls && es3_cls) break;
        }

        if (rfc_cls) {
            LOG("--- Rfc2898DeriveBytes methods ---");
            void* iter = nullptr;
            while (true) {
                void* m = p_class_get_methods(rfc_cls, &iter);
                if (!m) break;
                const char* nm = p_method_get_name ? p_method_get_name(m) : "?";
                int np         = p_method_get_param_count ? p_method_get_param_count(m) : -1;
                void* fnptr    = GetMethodFnPtr(m);
                LOG("  '%s' params=%d ptr=0x%p", nm, np, fnptr);
                if (nm && strcmp(nm, ".ctor") == 0 && np >= 3) {
                    char tag[64];
                    sprintf_s(tag, "Rfc2898..ctor(p=%d)", np);
                    TrySetBP(fnptr, tag);
                }
            }
        } else {
            LOG("Rfc2898DeriveBytes NOT FOUND in any assembly!");
        }

        if (es3_cls) {
            LOG("--- ES3Settings methods ---");
            void* iter = nullptr;
            while (true) {
                void* m = p_class_get_methods(es3_cls, &iter);
                if (!m) break;
                const char* nm = p_method_get_name ? p_method_get_name(m) : "?";
                int np         = p_method_get_param_count ? p_method_get_param_count(m) : -1;
                void* fnptr    = GetMethodFnPtr(m);
                LOG("  ES3Settings '%s' params=%d ptr=0x%p", nm, np, fnptr);
            }
        } else {
            LOG("ES3Settings NOT found in any assembly!");
        }
    }

fallback:
    if (g_bp_count == 0) {
        LOG("=== FALLBACK: using static offsets from previous analysis ===");
        MODULEINFO mi = {};
        GetModuleInformation(GetCurrentProcess(), hGA, &mi, sizeof(mi));
        BYTE* base = (BYTE*)mi.lpBaseOfDll;

        // Candidates from previous MOV R9D/R8D,1000 pattern search:
        // offset 0x9355E0 (MOV R9D,1000 was at 0x9356A9)
        // offset 0x488902 (MOV R8D,1000 was at 0x488949)
        // Also try: search for CALL to the 0x935... region = Rfc2898DeriveBytes area
        // The IL2CPP ctor cluster is near 0x93...:
        // Try offsets 0x935580, 0x935600, 0x935640, 0x935700, 0x935780 (just before the patterns)
        ULONG_PTR offsets[] = {
            0x9355E0, 0x935580, 0x935500, 0x935460,
            0x488900, 0x488902, 0x488880
        };
        for (auto off : offsets) {
            void* addr = base + off;
            char tag[64];
            sprintf_s(tag, "static offset 0x%llX", (ULONG_PTR)off);
            TrySetBP(addr, tag);
        }
        if (!AddVectoredExceptionHandler(1, VehHandler))
            LOG("VEH already registered or failed");
    }

    LOG("Total BPs: %d. Waiting (up to 30 min)...", g_bp_count);

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
