// boxspy10 — награда и сеть в одном хронометраже.
//
// Почему всё в одной DLL. Обработчик исключений ставится в НАЧАЛО цепочки, а
// одноразовый шаг (TF) — состояние потока, общее на всех. Обработчик, который
// гасит шаг безусловно, съедает и чужие шаги, и соседняя DLL перестаёт
// перевзводить свои точки. Именно это и вышло: boxspy7 замолчал, как только
// появился boxspy9. Одна DLL — одна цепочка, конфликта нет.
//
// Что меряем: уходит ли хоть байт в сеть в момент, когда клиент читает
// награду сундука. Это закрывает вопрос, имеет ли смысл ждать отправки после
// подмены. Если в секунду открытия исходящих нет, ждать нечего: сервер узнаёт
// содержимое не от клиента.
//
// Содержимое пакетов зашифровано TLS и нам не нужно — важны время и размер.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG  "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\boxspy10.log"
#define F_SWAP "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\SWAP.txt"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

enum Kind { K_GAME, K_NET };
struct Bp {
    Kind kind;
    ULONG_PTR off;            // для K_GAME — смещение в GameAssembly
    const char* mod, *fn;     // для K_NET — модуль и экспорт
    const char* name;
    ULONG_PTR addr; BYTE orig; LONG cap;
    volatile LONG armed, n;
};

static Bp g_bp[] = {
    { K_GAME, 0x959C99, 0, 0, "НАГРАДА ПРОЧИТАНА",           0, 0, 100, 0, 0 },
    { K_GAME, 0x9B1A20, 0, 0, "BoxOpenLog  сундук раскрыт",  0, 0, 100, 0, 0 },
    { K_GAME, 0x9B5F30, 0, 0, "GetBoxLog   сундук подобран", 0, 0, 100, 0, 0 },
    { K_NET,  0, "ws2_32.dll", "send",    "сеть ->",  0, 0, 600, 0, 0 },
    { K_NET,  0, "ws2_32.dll", "WSASend", "сеть ->",  0, 0, 600, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static void Str(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 2000) return;
        char b[6200];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n > 0) { b[n] = 0; LOG("               %s %s", tag, b); }
    } __except(1) {}
}

// Задание на подмену: одно число в SWAP.txt. Нет файла — только наблюдение.
static int ReadSwap(int* key)
{
    FILE* f = fopen(F_SWAP, "r");
    if (!f) return 0;
    int k = 0; int ok = fscanf(f, "%d", &k) == 1;
    fclose(f);
    if (!ok || k < 100000 || k > 999999) return 0;
    *key = k; return 1;
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (!g_rearm) return EXCEPTION_CONTINUE_SEARCH;   // шаг не наш — не трогаем
        for (int i = 0; i < G_N; i++)
            if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                PutByte(g_bp[i].addr, 0xCC);
                InterlockedExchange(&g_bp[i].armed, 1); break;
            }
        g_rearm = NULL;
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < G_N; i++) {
        if (a != g_bp[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bp[i].armed, 0, 1)) return EXCEPTION_CONTINUE_SEARCH;

        PutByte(a, g_bp[i].orig);
        ep->ContextRecord->Rip = a;
        LONG n = InterlockedIncrement(&g_bp[i].n);
        if (n > g_bp[i].cap) return EXCEPTION_CONTINUE_EXECUTION;

        SYSTEMTIME s; GetLocalTime(&s);

        if (g_bp[i].kind == K_NET) {
            long long len = (long long)(LONG_PTR)ep->ContextRecord->R8;
            // однобайтовые — служебный пинг локального канала, шума от них много
            if (len != 1) {
                // пульс — ровно 36 байт каждые ~25 с; всё крупное это выгрузка
                const char* tag = (len > 200) ? "КРУПНЫЙ ОБМЕН" : g_bp[i].name;
                LOG("[%02d:%02d:%02d.%03d]  %s  сокет=%llu  длина=%lld",
                    s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, tag,
                    (unsigned long long)ep->ContextRecord->Rcx, len);
            }
        } else if (g_bp[i].off == 0x959C99) {
            int real = (int)(ep->ContextRecord->Rax & 0xFFFFFFFF);
            LOG("");
            LOG("[%02d:%02d:%02d.%03d]  >>> %s = %d",
                s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, g_bp[i].name, real);
            int nk;
            if (ReadSwap(&nk) && nk != real) {
                ep->ContextRecord->Rax = (ULONG_PTR)(unsigned int)nk;
                LOG("               >>> ПОДМЕНА: %d -> %d", real, nk);
            }
        } else {
            LOG("[%02d:%02d:%02d.%03d]  %s",
                s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, g_bp[i].name);
            Str(g_bp[i].off == 0x9B1A20 ? ep->ContextRecord->Rdx : ep->ContextRecord->R8, "->");
        }

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2000);
    g_mtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen(F_LOG, "w");
    if (!g_log) return 0;
    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi = {}; GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;

    LOG("=== boxspy10: награда и сеть в одном хронометраже ===");
    int sk;
    if (ReadSwap(&sk)) LOG("SWAP.txt: подменять награду на %d", sk);
    else               LOG("SWAP.txt нет — только наблюдение");
    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        if (g_bp[i].kind == K_GAME) g_bp[i].addr = g_base + g_bp[i].off;
        else {
            HMODULE m = GetModuleHandleA(g_bp[i].mod);
            if (!m) { LOG("  нет %s", g_bp[i].mod); continue; }
            g_bp[i].addr = (ULONG_PTR)GetProcAddress(m, g_bp[i].fn);
            if (!g_bp[i].addr) { LOG("  нет %s", g_bp[i].fn); continue; }
        }
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        if (g_bp[i].orig == 0xCC) { LOG("  %s занят чужой точкой", g_bp[i].name); continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  0x%llX  %s", g_bp[i].addr, g_bp[i].name);
    }
    LOG("");
    LOG("=== ГОТОВО — открывай сундук ===");

    for (int t = 0; t < 3600; t++) Sleep(1000);

    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed,0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
