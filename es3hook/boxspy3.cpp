// boxspy3.cpp — объект предмета в момент рождения из сундука.
//
// Что уже известно:
//   * сундук открывается целиком на клиенте: OpenBoxAsync::MoveNext вызывается
//     один раз, отрабатывает за 1-2 мс, автомат состояний лежит на стеке
//   * в автомате по +0x040 появляется указатель — ровно к моменту BoxOpenLog
//   * предмет доходит до сейва и остаётся: коробка 11261 -> предмет 11262/520011
//
// Отсюда вопрос: сервер узнаёт о предмете только из сейва и принимает его.
// Проверяет ли он, что этот ключ вообще мог выпасть из этой коробки?
//
// Заход первый — только чтение: найти, по какому смещению в свежесозданном
// объекте лежит ItemKey. Заход второй — подмена, читаем задание из SWAP.txt
// («смещение новый_ключ»), чтобы не пересобирать и не перезапускать игру.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy3.log"
#define F_SWAP DIR "SWAP.txt"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static void Stamp(char* o, size_t n)
{ SYSTEMTIME s; GetLocalTime(&s); sprintf_s(o,n,"%02d:%02d:%02d.%03d",s.wHour,s.wMinute,s.wSecond,s.wMilliseconds); }

static ULONG_PTR g_base, g_end;
static volatile ULONG_PTR g_sm;        // автомат OpenBoxAsync
static void* g_rearm;

struct Bp { ULONG_PTR off, addr; const char* name; BYTE orig; volatile LONG armed, n; };
static Bp g_bp[] = {
    { 0xA2DF60, 0, "OpenBoxAsync::MoveNext", 0, 0, 0 },
    { 0x9B1A20, 0, "BoxOpenLog::.ctor  ПРЕДМЕТ СОЗДАН", 0, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static int Ptr(ULONG_PTR v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF && (v & 7) == 0; }

static void LogStr(ULONG_PTR p, const char* tag)
{
    if (!Ptr(p)) return;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 2000) return;
        char b[6200];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n > 0) { b[n] = 0; LOG("      %s = %s", tag, b); }
    } __except(1) {}
}

// Ключи предметов шестизначные (520011, 910501) — подсвечиваем их отдельно,
// иначе нужное число теряется среди указателей.
static void Dump(ULONG_PTR p, const char* tag, int rows, int depth)
{
    if (!Ptr(p)) return;
    __try {
        LOG("      %s = 0x%llX", tag, p);
        for (int r = 0; r < rows; r++) {
            ULONG_PTR* q = (ULONG_PTR*)(p + r*16);
            LOG("        +%03X: %016llX %016llX   i32 %d %d %d %d",
                r*16, q[0], q[1],
                *(int*)(p+r*16), *(int*)(p+r*16+4), *(int*)(p+r*16+8), *(int*)(p+r*16+12));
            for (int k = 0; k < 4; k++) {
                int v = *(int*)(p + r*16 + k*4);
                if (v >= 100000 && v <= 999999)
                    LOG("           ^ +0x%02X = %d   <-- похоже на ItemKey", r*16 + k*4, v);
            }
        }
        if (depth > 0) {
            for (int r = 0; r < rows*2 && r < 16; r++) {
                ULONG_PTR v = *(ULONG_PTR*)(p + r*8);
                if (!Ptr(v) || v == p) continue;
                char t[64]; sprintf_s(t, "  -> по +0x%02X", r*8);
                LogStr(v, t);
                Dump(v, t, 4, depth - 1);
            }
        }
    } __except(1) {}
}

// Задание на подмену: строка «смещение ключ», например «20 340011».
static int ReadSwap(int* off, int* key)
{
    FILE* f = fopen(F_SWAP, "r");
    if (!f) return 0;
    int a = -1, b = -1;
    int ok = fscanf(f, "%x %d", &a, &b) == 2;
    fclose(f);
    if (!ok || a < 0 || a > 0x400 || b <= 0) return 0;
    *off = a; *key = b;
    return 1;
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (g_rearm) {
            for (int i = 0; i < G_N; i++)
                if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                    PutByte(g_bp[i].addr, 0xCC);
                    InterlockedExchange(&g_bp[i].armed, 1); break;
                }
            g_rearm = NULL;
        }
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
        if (n > 40) return EXCEPTION_CONTINUE_EXECUTION;

        char ts[32]; Stamp(ts, sizeof(ts));

        if (g_bp[i].off == 0xA2DF60) {
            g_sm = ep->ContextRecord->Rcx;
            LOG("");
            LOG("[%s] #%ld  %s   автомат на 0x%llX", ts, n, g_bp[i].name, g_sm);
        } else {
            LOG("");
            LOG("[%s] #%ld  %s", ts, n, g_bp[i].name);
            LogStr(ep->ContextRecord->Rdx, "имя предмета");

            ULONG_PTR obj = 0;
            if (g_sm) __try { obj = *(ULONG_PTR*)(g_sm + 0x40); } __except(1) {}
            if (Ptr(obj)) {
                LOG("      объект по автомат+0x40:");
                Dump(obj, "предмет", 12, 1);

                int off, key;
                if (ReadSwap(&off, &key)) {
                    __try {
                        int was = *(int*)(obj + off);
                        *(int*)(obj + off) = key;
                        LOG("      >>> ПОДМЕНА: +0x%X  %d -> %d", off, was, key);
                    } __except(1) { LOG("      >>> подмена не удалась"); }
                }
            } else {
                LOG("      автомат+0x40 пуст (0x%llX)", obj);
            }
        }

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2500);
    g_mtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen(F_LOG, "w");
    if (!g_log) return 0;
    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi = {}; GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;

    LOG("=== boxspy3: объект предмета в момент рождения ===");
    LOG("база = 0x%llX", g_base);
    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s", g_bp[i].off, g_bp[i].name);
    }
    LOG("");
    LOG("=== ГОТОВО — открывай сундук ===");

    for (int t = 0; t < 2400; t++) Sleep(1000);

    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed,0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
