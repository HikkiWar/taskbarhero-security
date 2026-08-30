// tracer.cpp — частотный анализ вызовов методом исключения.
//
// Идея: узнать путь экипировки, не угадывая имя метода (они обфусцированы).
//
//   Фаза 1  — вооружаем ВСЕ пригодные методы. Игрок ничего не делает.
//             Всё, что сработало, — фоновый код. Помечаем как известное.
//   Фаза 2  — вооружаем ТОЛЬКО ни разу не сработавшие. Игрок один раз
//             меняет снаряжение. Что сработало теперь — путь экипировки.
//
// Две вещи делают это дешёвым:
//   * точки останова ОДНОРАЗОВЫЕ: сработала — байт возвращается навсегда.
//     Каждый метод стоит ровно одного исключения, а не сотен тысяч.
//   * в лог пишем имя метода ОДИН раз, дублей нет.
//
// Берём только адреса с ровно одним методом: линкер сворачивает одинаковый
// код (тривиальные геттеры), и на общий адрес точку ставить бессмысленно.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "tracer.log"
#define F_P1   DIR "phase1_background.txt"
#define F_P2   DIR "phase2_equip.txt"
#define F_GO   DIR "GO_PHASE2.flag"

static FILE*  g_log = NULL;
static HANDLE g_mtx = NULL;

#define LOG(fmt, ...) do { if (g_log && g_mtx) {                 \
    WaitForSingleObject(g_mtx, 1000);                           \
    fprintf(g_log, fmt "\n", ##__VA_ARGS__); fflush(g_log);     \
    ReleaseMutex(g_mtx); } } while (0)

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

struct Ent {
    ULONG_PTR addr;
    char*     name;
    BYTE      orig;
    volatile LONG armed;
    volatile LONG fired;
};

static Ent*  g_ent = NULL;
static int   g_n = 0;
static volatile LONG g_phase = 1;
static volatile LONG g_hits  = 0;
static ULONG_PTR g_base = 0, g_end = 0;

// адреса отсортированы -> двоичный поиск, иначе обработчик станет узким местом
static int Find(ULONG_PTR a)
{
    int lo = 0, hi = g_n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g_ent[mid].addr == a) return mid;
        if (g_ent[mid].addr < a) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}

static void Disarm(int i)
{
    DWORD old;
    VirtualProtect((void*)g_ent[i].addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)g_ent[i].addr = g_ent[i].orig;
    VirtualProtect((void*)g_ent[i].addr, 1, old, &old);
    InterlockedExchange(&g_ent[i].armed, 0);
}

static void Arm(int i)
{
    DWORD old;
    VirtualProtect((void*)g_ent[i].addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)g_ent[i].addr = 0xCC;
    VirtualProtect((void*)g_ent[i].addr, 1, old, &old);
    InterlockedExchange(&g_ent[i].armed, 1);
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
    int i = Find(a);
    if (i < 0) return EXCEPTION_CONTINUE_SEARCH;
    if (!InterlockedCompareExchange(&g_ent[i].armed, 0, 1))
        return EXCEPTION_CONTINUE_SEARCH;

    // одноразово: возвращаем байт навсегда, повторов не будет
    DWORD old;
    VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)a = g_ent[i].orig;
    VirtualProtect((void*)a, 1, old, &old);
    ep->ContextRecord->Rip = a;

    InterlockedExchange(&g_ent[i].fired, 1);
    InterlockedIncrement(&g_hits);

    if (g_phase == 2) {
        ULONG_PTR ret = 0;
        __try { ret = *(ULONG_PTR*)ep->ContextRecord->Rsp; } __except (1) {}
        LOG("%s", g_ent[i].name);
        LOG("      RCX=%llX RDX=%llX R8=%llX R9=%llX",
            ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
            ep->ContextRecord->R8, ep->ContextRecord->R9);
        if (ret >= g_base && ret < g_end)
            LOG("      вызван из GameAssembly.dll+0x%llX", ret - g_base);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static int CmpEnt(const void* a, const void* b)
{
    ULONG_PTR x = ((const Ent*)a)->addr, y = ((const Ent*)b)->addr;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void Dump(const char* path, LONG want)
{
    FILE* f = fopen(path, "w");
    if (!f) return;
    int c = 0;
    for (int i = 0; i < g_n; i++)
        if (g_ent[i].fired == want) { fprintf(f, "%s\n", g_ent[i].name); c++; }
    fclose(f);
    LOG("выгружено %d строк -> %s", c, path);
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2500);
    g_mtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen(F_LOG, "w");
    if (!g_log) return 0;

    LOG("=== tracer: частотный анализ методом исключения ===");
    HMODULE hGA = GetModuleHandleA("GameAssembly.dll");
    if (!hGA) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hGA, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;

#define GP(f) p_##f = (Fn_##f)GetProcAddress(hGA, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(image_get_class_count); GP(image_get_class);
    GP(class_get_name); GP(class_get_namespace); GP(class_get_methods);
    GP(method_get_name); GP(method_get_param_count);
#undef GP
    if (!p_domain_get) { LOG("нет экспортов"); return 0; }

    const int CAP = 60000;
    g_ent = (Ent*)calloc(CAP, sizeof(Ent));
    if (!g_ent) { LOG("нет памяти"); return 0; }

    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);

    for (size_t a = 0; a < nasm && g_n < CAP; a++) {
        void* img = p_assembly_get_image(asms[a]);
        if (!img) continue;
        size_t ncls = p_image_get_class_count(img);
        for (size_t c = 0; c < ncls && g_n < CAP; c++) {
            void* cls = p_image_get_class(img, c);
            if (!cls) continue;
            const char* cn = p_class_get_name(cls);
            const char* ns = p_class_get_namespace(cls);
            if (!cn) continue;
            // только игровой код: фреймворк и Steamworks не интересны
            if (!ns || !strstr(ns, "TaskbarHero")) continue;

            void* it = NULL;
            while (g_n < CAP) {
                void* m = p_class_get_methods(cls, &it);
                if (!m) break;
                const char* mn = p_method_get_name(m);
                void* fn = *(void**)m;
                if (!mn || !fn) continue;
                ULONG_PTR fa = (ULONG_PTR)fn;
                if (fa < g_base || fa >= g_end) continue;

                Ent& e = g_ent[g_n];
                e.addr = fa;
                int np = p_method_get_param_count ? p_method_get_param_count(m) : -1;
                char buf[224];
                sprintf_s(buf, "%s.%s::%s(p=%d)", ns, cn, mn, np);
                e.name = _strdup(buf);
                g_n++;
            }
        }
    }
    LOG("методов игрового кода: %d", g_n);

    qsort(g_ent, g_n, sizeof(Ent), CmpEnt);

    // выбрасываем свёрнутые адреса — на них несколько методов сразу
    int keep = 0;
    for (int i = 0; i < g_n; ) {
        int j = i;
        while (j < g_n && g_ent[j].addr == g_ent[i].addr) j++;
        if (j - i == 1) g_ent[keep++] = g_ent[i];
        i = j;
    }
    LOG("после отсева свёрнутых адресов: %d", keep);
    g_n = keep;

    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < g_n; i++) { g_ent[i].orig = *(BYTE*)g_ent[i].addr; Arm(i); }
    LOG("ФАЗА 1: вооружено %d. Ничего не делай — собираю фон.", g_n);

    // ждём флаг от оператора
    while (GetFileAttributesA(F_GO) == INVALID_FILE_ATTRIBUTES) Sleep(500);

    LOG("ФАЗА 1 завершена, сработало %ld методов", g_hits);
    Dump(F_P1, 1);

    // снимаем всё и вооружаем только НЕ сработавшее
    int rearm = 0;
    for (int i = 0; i < g_n; i++) {
        if (g_ent[i].armed) Disarm(i);
        if (g_ent[i].fired) { g_ent[i].fired = 2; }      // фон
        else { Arm(i); rearm++; }
    }
    g_hits = 0;
    InterlockedExchange(&g_phase, 2);
    LOG("");
    LOG("=== ФАЗА 2: вооружено %d ранее не вызывавшихся ===", rearm);
    LOG("=== МЕНЯЙ СНАРЯЖЕНИЕ ОДИН РАЗ ===");
    LOG("");

    for (int t = 0; t < 600; t++) {
        Sleep(1000);
        if (t == 120 || t == 300) {
            LOG("-- прошло %d с, новых методов: %ld --", t, g_hits);
        }
    }
    LOG("=== ФАЗА 2 завершена, новых методов: %ld ===", g_hits);
    Dump(F_P2, 1);
    fclose(g_log);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, Worker, NULL, 0, NULL); }
    return TRUE;
}
