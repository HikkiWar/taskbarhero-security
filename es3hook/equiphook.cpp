// equiphook.cpp — найти метод экипировки и поймать момент вызова.
//
// Задача: узнать, каким кодом игра меняет экипировку. Прямая запись массива
// equippedItemIds затирается при сохранении, значит источник истины другой.
//
// План:
//   1. перебрать все классы всех сборок через экспортируемый IL2CPP API
//   2. отобрать методы, в имени которых есть Equip
//   3. поставить на них INT3 и логировать срабатывания с аргументами
//
// Точки останова persistent: после срабатывания байт восстанавливается,
// ставится флаг одиночного шага, и на следующем шаге INT3 возвращается —
// иначе увидим только первый вызов.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#pragma comment(lib, "psapi.lib")

static FILE*  g_log    = NULL;
static HANDLE g_logMtx = NULL;

#define LOG(fmt, ...) do {                                   \
    if (g_log && g_logMtx) {                                 \
        WaitForSingleObject(g_logMtx, 1000);                 \
        fprintf(g_log, fmt "\n", ##__VA_ARGS__);             \
        fflush(g_log);                                       \
        ReleaseMutex(g_logMtx);                              \
    }                                                        \
} while (0)

typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef size_t      (*Fn_image_get_class_count)(void*);
typedef void*       (*Fn_image_get_class)(void*, size_t);
typedef const char* (*Fn_class_get_name)(void*);
typedef const char* (*Fn_class_get_namespace)(void*);
typedef void*       (*Fn_class_get_methods)(void*, void**);
typedef const char* (*Fn_method_get_name)(void*);
typedef int         (*Fn_method_get_param_count)(void*);

static Fn_domain_get            p_domain_get;
static Fn_domain_get_assemblies p_domain_get_assemblies;
static Fn_assembly_get_image    p_assembly_get_image;
static Fn_image_get_class_count p_image_get_class_count;
static Fn_image_get_class       p_image_get_class;
static Fn_class_get_name        p_class_get_name;
static Fn_class_get_namespace   p_class_get_namespace;
static Fn_class_get_methods     p_class_get_methods;
static Fn_method_get_name       p_method_get_name;
static Fn_method_get_param_count p_method_get_param_count;

struct Bp {
    void*  addr;
    BYTE   orig;
    char   name[192];
    volatile LONG armed;
    volatile LONG hits;
};
static Bp    g_bps[64];
static int   g_bp_count = 0;
static void* g_rearm = NULL;
static ULONG_PTR g_base = 0, g_end = 0;

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void* addr = ep->ExceptionRecord->ExceptionAddress;

    if (code == EXCEPTION_SINGLE_STEP) {
        if (g_rearm) {
            void* ra = g_rearm; g_rearm = NULL;
            for (int i = 0; i < g_bp_count; i++) {
                if (g_bps[i].addr == ra) {
                    DWORD old;
                    VirtualProtect(ra, 1, PAGE_EXECUTE_READWRITE, &old);
                    *(BYTE*)ra = 0xCC;
                    VirtualProtect(ra, 1, old, &old);
                    InterlockedExchange(&g_bps[i].armed, 1);
                    break;
                }
            }
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < g_bp_count; i++) {
        if (addr != g_bps[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bps[i].armed, 0, 1))
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD old;
        VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr = g_bps[i].orig;
        VirtualProtect(addr, 1, old, &old);
        ep->ContextRecord->Rip = (ULONG_PTR)addr;

        LONG n = InterlockedIncrement(&g_bps[i].hits);
        ULONG_PTR ret = 0;
        __try { ret = *(ULONG_PTR*)ep->ContextRecord->Rsp; } __except (1) {}

        LOG(">>> ВЫЗОВ #%ld  %s", n, g_bps[i].name);
        LOG("      RCX=%llX  RDX=%llX  R8=%llX  R9=%llX",
            ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
            ep->ContextRecord->R8,  ep->ContextRecord->R9);
        if (ret >= g_base && ret < g_end)
            LOG("      возврат в GameAssembly.dll+0x%llX", ret - g_base);
        // аргументы на стеке — там обычно лежат слот и индексы
        for (int s = 1; s <= 6; s++) {
            ULONG_PTR v = 0;
            __try { v = *(ULONG_PTR*)(ep->ContextRecord->Rsp + s * 8); } __except (1) {}
            if (v && v < 0x100000) LOG("      [RSP+%02X]=%llu", s * 8, v);
        }

        g_rearm = addr;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void SetBp(void* fn, const char* label)
{
    if (!fn || g_bp_count >= 64) return;
    for (int i = 0; i < g_bp_count; i++)
        if (g_bps[i].addr == fn) return;

    Bp& b = g_bps[g_bp_count];
    b.addr = fn;
    b.orig = *(BYTE*)fn;
    b.armed = 1;
    b.hits = 0;
    strncpy_s(b.name, label, _TRUNCATE);

    DWORD old;
    VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)fn = 0xCC;
    VirtualProtect(fn, 1, old, &old);
    LOG("  BP[%d] 0x%p orig=%02X  %s", g_bp_count, fn, b.orig, label);
    g_bp_count++;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(3000);
    g_logMtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen("C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\equip_hook.log", "w");
    if (!g_log) return 0;

    LOG("=== equiphook: поиск метода экипировки ===");

    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("GameAssembly не найден"); return 0; }
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hGA, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll;
    g_end  = g_base + mi.SizeOfImage;
    LOG("GameAssembly: 0x%llX - 0x%llX", g_base, g_end);

#define GP(f) p_##f = (Fn_##f)GetProcAddress(hGA, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(image_get_class_count); GP(image_get_class);
    GP(class_get_name); GP(class_get_namespace); GP(class_get_methods);
    GP(method_get_name); GP(method_get_param_count);
#undef GP
    if (!p_domain_get || !p_image_get_class) { LOG("нет нужных экспортов"); return 0; }

    AddVectoredExceptionHandler(1, Veh);

    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);
    LOG("сборок: %zu", nasm);

    int scanned = 0, found = 0;
    for (size_t a = 0; a < nasm; a++) {
        void* img = p_assembly_get_image(asms[a]);
        if (!img) continue;
        size_t ncls = p_image_get_class_count(img);
        for (size_t c = 0; c < ncls; c++) {
            void* cls = p_image_get_class(img, c);
            if (!cls) continue;
            const char* cname = p_class_get_name(cls);
            const char* cns   = p_class_get_namespace(cls);
            if (!cname) continue;
            scanned++;

            void* iter = NULL;
            while (true) {
                void* m = p_class_get_methods(cls, &iter);
                if (!m) break;
                const char* mn = p_method_get_name(m);
                if (!mn) continue;
                if (!strstr(mn, "Equip") && !strstr(mn, "equip")) continue;

                void* fn = *(void**)m;   // methodPointer в начале структуры
                int np = p_method_get_param_count ? p_method_get_param_count(m) : -1;
                char label[192];
                sprintf_s(label, "%s%s%s::%s(p=%d)",
                          cns && *cns ? cns : "", cns && *cns ? "." : "",
                          cname, mn, np);
                LOG("найден  %s -> 0x%p", label, fn);
                found++;
                if (fn && (ULONG_PTR)fn >= g_base && (ULONG_PTR)fn < g_end)
                    SetBp(fn, label);
            }
        }
    }
    LOG("классов просмотрено: %d, методов с Equip: %d, точек останова: %d",
        scanned, found, g_bp_count);
    LOG("=== ЖДУ ДЕЙСТВИЙ ИГРОКА — переодень героя ===");

    for (int t = 0; t < 1200; t++) {
        Sleep(1000);
        if (t % 60 == 59) {
            LOG("-- %d мин, срабатываний: --", (t + 1) / 60);
            for (int i = 0; i < g_bp_count; i++)
                if (g_bps[i].hits) LOG("     %ld x %s", g_bps[i].hits, g_bps[i].name);
        }
    }
    LOG("=== ГОТОВО ===");
    fclose(g_log);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, Worker, NULL, 0, NULL);
    }
    return TRUE;
}
