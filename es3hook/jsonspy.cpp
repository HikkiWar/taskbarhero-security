// jsonspy.cpp — читать переписку с сервером открытым текстом.
//
// Правка клиентских таблиц выпадения ничего не дала: шанс 10000 на всех
// стадиях за шесть минут не дал ни одного сундука, а страж запросов
// (StageBoxRequestAbuseGuard) показал всего два обращения за пять минут.
// Значит решение принимает сервер, и надо смотреть, что он присылает.
//
// Трогать TCP бессмысленно — там шифрование. Зато весь разбор ответов идёт
// через JSON, и туда строка приходит уже расшифрованной:
//
//   BackEnd.BackndLitJson.JsonMapper::ToObject(String)
//   BackEnd.BackndNewtonsoft.Json.Linq.JObject::Parse(String)
//
// Адреса ищем через il2cpp по ИМЕНАМ классов и методов — они у SDK не
// обфусцированы, поэтому хук переживёт и перезапуск, и обновление игры.
//
// Точки останова постоянные, с перевзводом через одиночный шаг. Чтобы не
// утонуть в потоке, одинаковые строки не повторяем.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\jsonspy6.log"
#define MAXBP 8
#define SEEN  4096
#define CUT   16000       // сколько символов строки писать

typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef size_t      (*Fn_image_get_class_count)(void*);
typedef void*       (*Fn_image_get_class)(void*, size_t);
typedef const char* (*Fn_class_get_name)(void*);
typedef const char* (*Fn_class_get_namespace)(void*);
typedef void*       (*Fn_class_get_methods)(void*, void**);
typedef const char* (*Fn_method_get_name)(void*);
typedef uint32_t    (*Fn_method_get_param_count)(void*);

static Fn_domain_get             p_domain_get;
static Fn_domain_get_assemblies  p_domain_get_assemblies;
static Fn_assembly_get_image     p_assembly_get_image;
static Fn_image_get_class_count  p_image_get_class_count;
static Fn_image_get_class        p_image_get_class;
static Fn_class_get_name         p_class_get_name;
static Fn_class_get_namespace    p_class_get_namespace;
static Fn_class_get_methods      p_class_get_methods;
static Fn_method_get_name        p_method_get_name;
static Fn_method_get_param_count p_method_get_param_count;

struct Bp { ULONG_PTR addr; BYTE orig; char name[96]; volatile LONG armed; volatile LONG n; };
static Bp g_bp[MAXBP];
static int g_c = 0;
static void* g_rearm;
static ULONG_PTR g_base, g_end;
static FILE* g_log;
static FILE* g_log2;   // только removed/added (боссовые сундуки)
static HANDLE g_mtx;
static unsigned g_seen[SEEN];
static volatile LONG g_seen_n = 0;

#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx, 800); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx); } } while (0)
#define LOG2(f_, ...) do { if (g_log2 && g_mtx) { WaitForSingleObject(g_mtx, 800); \
    fprintf(g_log2, f_ "\n", ##__VA_ARGS__); fflush(g_log2); ReleaseMutex(g_mtx); } } while (0)

// строка IL2CPP: +0x10 длина, +0x14 символы UTF-16
static int ReadStr(ULONG_PTR s, char* out, int cap, int* full)
{
    if (s < 0x10000 || s > 0x7FFFFFFFFFFF) return 0;
    int n = 0;
    __try { n = *(int*)(s + 0x10); } __except (1) { return 0; }
    if (n <= 0 || n > (1 << 22)) return 0;
    *full = n;
    const wchar_t* w = (const wchar_t*)(s + 0x14);
    int lim = n < cap - 1 ? n : cap - 1;
    int k = 0;
    __try {
        for (int i = 0; i < lim; i++) {
            wchar_t c = w[i];
            out[k++] = (c < 0x20 || c > 0x7E) ? (c > 0xFF ? '?' : '.') : (char)c;
        }
    } __except (1) { return 0; }
    out[k] = 0;
    return k;
}

static bool Fresh(const char* s, int len)
{
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    LONG n = g_seen_n;
    for (LONG i = 0; i < n && i < SEEN; i++)
        if (g_seen[i] == h) return false;
    if (n < SEEN) { g_seen[n] = h; InterlockedIncrement(&g_seen_n); }
    return true;
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (g_rearm) {
            for (int i = 0; i < g_c; i++)
                if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                    DWORD o; VirtualProtect((void*)g_bp[i].addr, 1, PAGE_EXECUTE_READWRITE, &o);
                    *(BYTE*)g_bp[i].addr = 0xCC;
                    VirtualProtect((void*)g_bp[i].addr, 1, o, &o);
                    InterlockedExchange(&g_bp[i].armed, 1);
                    break;
                }
            g_rearm = NULL;
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < g_c; i++) {
        if (a != g_bp[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bp[i].armed, 0, 1))
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
        *(BYTE*)a = g_bp[i].orig;
        VirtualProtect((void*)a, 1, o, &o);
        ep->ContextRecord->Rip = a;

        // Пробуем все регистры: для instance-методов RCX=this, строки в RDX/R8/R9
        // Для SendQueue::Enqueue нужны RDX и R8.
        static const char* rnames[] = { "RCX", "RDX", "R8", "R9" };
        ULONG_PTR regs[] = {
            ep->ContextRecord->Rcx,
            ep->ContextRecord->Rdx,
            ep->ContextRecord->R8,
            ep->ContextRecord->R9,
        };
        bool logged = false;
        for (int r = 0; r < 4; r++) {
            char buf[CUT + 8];   // на стеке, не static — иначе гонка потоков
            int full = 0;
            int len = ReadStr(regs[r], buf, sizeof(buf), &full);
            if (len < 4) continue;
            if (buf[0] != '{' && buf[0] != '[' && buf[0] != '"') continue;
            if (!Fresh(buf, len)) continue;
            if (!logged) {
                LONG n = InterlockedIncrement(&g_bp[i].n);
                LOG("");
                LOG("--- %s  #%ld  длина %d ---", g_bp[i].name, n, full);
                logged = true;
            }
            LOG("  [%s] %s%s", rnames[r], buf, full > len ? "  …обрезано" : "");
            // если это removed/added — дублируем + стек вызовов
            if (strstr(buf, "\"removed\"") && strstr(buf, "\"added\"")) {
                LOG2("");
                LOG2("=== removed/added  длина %d ===", full);
                LOG2("%s%s", buf, full > len ? "  …обрезано" : "");
                // читаем стек: ищем адреса внутри GameAssembly (это игровые функции)
                LOG2("--- call stack ---");
                ULONG_PTR* rsp = (ULONG_PTR*)ep->ContextRecord->Rsp;
                int found = 0;
                __try {
                    for (int s = 0; s < 64 && found < 16; s++) {
                        ULONG_PTR addr = rsp[s];
                        if (addr >= g_base && addr < g_end) {
                            LOG2("  [RSP+%03d] +0x%llX", s * 8,
                                 (unsigned long long)(addr - g_base));
                            found++;
                        }
                    }
                } __except (1) {}
                LOG2("--- end stack ---");
            }
        }

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void Arm(ULONG_PTR a, const char* name)
{
    if (g_c >= MAXBP || a < g_base || a >= g_end) return;
    for (int i = 0; i < g_c; i++) if (g_bp[i].addr == a) return;   // свёрнутый адрес
    g_bp[g_c].addr = a;
    g_bp[g_c].orig = *(BYTE*)a;
    strncpy_s(g_bp[g_c].name, sizeof(g_bp[g_c].name), name, _TRUNCATE);
    g_bp[g_c].armed = 1;
    g_bp[g_c].n = 0;
    DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
    *(BYTE*)a = 0xCC;
    VirtualProtect((void*)a, 1, o, &o);
    LOG("  точка на 0x%llX (+0x%llX)  %s", (unsigned long long)a,
        (unsigned long long)(a - g_base), name);
    g_c++;
}

struct Want { const char* ns; const char* cls; const char* method; uint32_t params; };
static const Want WANTED[] = {
    { "BackEnd.BackndLitJson",              "JsonMapper",  "ToObject", 1 },   // ответы сервера
    { "BackEnd.BackndLitJson",              "JsonMapper",  "ToJson",   1 },   // сериализация
    { "BackEnd.BackndNewtonsoft.Json.Linq", "JObject",     "Parse",    1 },
    { "BackEnd.BackndNewtonsoft.Json.Linq", "JArray",      "Parse",    1 },
};

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2500);
    g_mtx = CreateMutexA(NULL, FALSE, NULL);
    g_log  = fopen(F_LOG, "w");
    g_log2 = fopen(F_LOG ".boss", "w");
    if (!g_log) return 0;

    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll;
    g_end = g_base + mi.SizeOfImage;
    LOG("=== jsonspy === база 0x%llX", (unsigned long long)g_base);

#define GP(f) p_##f = (Fn_##f)GetProcAddress(h, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(image_get_class_count); GP(image_get_class);
    GP(class_get_name); GP(class_get_namespace); GP(class_get_methods);
    GP(method_get_name); GP(method_get_param_count);
#undef GP
    if (!p_domain_get) { LOG("нет экспортов"); fclose(g_log); return 0; }

    AddVectoredExceptionHandler(1, Veh);

    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);
    for (size_t a = 0; a < nasm; a++) {
        void* img = p_assembly_get_image(asms[a]);
        if (!img) continue;
        size_t nc = p_image_get_class_count(img);
        for (size_t c = 0; c < nc; c++) {
            void* cls = p_image_get_class(img, c);
            if (!cls) continue;
            const char* ns = p_class_get_namespace(cls);
            const char* cn = p_class_get_name(cls);
            if (!ns || !cn) continue;
            for (size_t w = 0; w < sizeof(WANTED) / sizeof(*WANTED); w++) {
                if (strcmp(ns, WANTED[w].ns) || strcmp(cn, WANTED[w].cls)) continue;
                void* it = NULL;
                while (true) {
                    void* m = p_class_get_methods(cls, &it);
                    if (!m) break;
                    const char* mn = p_method_get_name(m);
                    if (!mn || strcmp(mn, WANTED[w].method)) continue;
                    if (p_method_get_param_count(m) != WANTED[w].params) continue;
                    char nm[96];
                    sprintf_s(nm, "%s.%s::%s", ns, cn, mn);
                    Arm((ULONG_PTR)(*(void**)m), nm);
                }
            }
        }
    }
    LOG("");
    LOG("=== вооружено точек: %d — играй, ловлю ответы сервера ===", g_c);

    for (int t = 0; t < 1800; t++) {
        Sleep(1000);
        if (t == 300 || t == 900) LOG("-- прошло %d с --", t);
    }
    LOG("=== завершено ===");
    fclose(g_log);
    g_log = NULL;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, Worker, NULL, 0, NULL);
    }
    return TRUE;
}
