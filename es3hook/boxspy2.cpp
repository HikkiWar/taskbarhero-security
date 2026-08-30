// boxspy2.cpp — в какой момент клиент узнаёт содержимое сундука.
//
// Первый заход показал: обычный сундук со стадии открывается ЦЕЛИКОМ на клиенте.
// Ни один метод ветки InventoryProcessBox* не сработал — та ветка обслуживает
// Steam Inventory Service (платные и рыночные предметы), а не дроп со стадии.
//
// Сработали только два лога:
//   GetBoxLog::.ctor    R8  = "MonsterName_10031"   подбор
//   BoxOpenLog::.ctor   RDX = "ItemName_340011"     что выпало
// Оба вызваны из <OpenBoxAsync>d__74::MoveNext — автомата состояний async-метода.
//
// Локальные переменные async-метода компилятор кладёт ПОЛЯМИ автомата. Значит
// ключ выпавшего предмета лежит в объекте автомата, и его видно ещё до анимации.
// Ставим точку на MoveNext и дампим объект на каждом шаге — ищем, на каком
// именно шаге поле с ключом обретает значение.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\boxspy2.log"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static void Stamp(char* o, size_t n)
{ SYSTEMTIME s; GetLocalTime(&s); sprintf_s(o,n,"%02d:%02d:%02d.%03d",s.wHour,s.wMinute,s.wSecond,s.wMilliseconds); }

struct Bp {
    ULONG_PTR off, addr; const char* name;
    BYTE orig; int dumpBig; LONG cap;
    volatile LONG armed, n;
};

static Bp g_bp[] = {
    { 0x9B5F30, 0, "GetBoxLog::.ctor          подбор коробки", 0, 0,  50, 0, 0 },
    { 0x9B1A20, 0, "BoxOpenLog::.ctor         ЧТО ВЫПАЛО",     0, 0,  50, 0, 0 },
    { 0xA2DF60, 0, "OpenBoxAsync::MoveNext    шаг автомата",   0, 1, 120, 0, 0 },
    { 0x9075F0, 0, "ClaimStageBoxAsync::MoveNext  заявка серверу", 0, 1, 60, 0, 0 },
    { 0xA2C480, 0, "AutoChestOpenAsync::MoveNext", 0, 1, 40, 0, 0 },
    { 0xA356C0, 0, "AbuseGuardCountdownAsync::MoveNext  ЗАЩИТА", 0, 1, 30, 0, 0 },
    { 0x997C20, 0, "CallCheckValidItems::MoveNext  ПРОВЕРКА СЕРВЕРОМ", 0, 1, 30, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;
static volatile ULONG_PTR g_lastSm;    // последний виденный автомат OpenBoxAsync

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static void LogStr(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 4000) return;
        char b[12300];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n <= 0) return;
        b[n] = 0;
        LOG("      %s = %s", tag, b);
    } __except(1) {}
}

// Дамп объекта + отдельно всё, что похоже на игровой ключ. Ключи предметов
// шестизначные (340011, 910501), ключи героев трёхзначные — их и ищем.
static void Dump(ULONG_PTR p, const char* tag, int rows)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        LOG("      %s = 0x%llX", tag, p);
        char keys[512]; keys[0] = 0; int kn = 0;
        for (int r = 0; r < rows; r++) {
            ULONG_PTR* q = (ULONG_PTR*)(p + r*16);
            LOG("        +%03X: %016llX %016llX   i32 %d %d %d %d",
                r*16, q[0], q[1],
                *(int*)(p+r*16), *(int*)(p+r*16+4), *(int*)(p+r*16+8), *(int*)(p+r*16+12));
            for (int k = 0; k < 4; k++) {
                int v = *(int*)(p + r*16 + k*4);
                if (v >= 100000 && v <= 999999 && kn < 400) {
                    char one[48];
                    sprintf_s(one, "+%03X=%d ", r*16 + k*4, v);
                    strcat_s(keys, sizeof(keys), one); kn += (int)strlen(one);
                }
            }
        }
        if (keys[0]) LOG("      >>> похоже на ключи: %s", keys);
    } __except(1) {}
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

        // после исчерпания лимита точку больше не взводим — лог не разрастётся
        if (n > g_bp[i].cap) return EXCEPTION_CONTINUE_EXECUTION;

        char ts[32]; Stamp(ts, sizeof(ts));
        LOG("");
        LOG("[%s] #%ld  %s", ts, n, g_bp[i].name);
        LOG("      RCX=%llX  RDX=%llX  R8=%llX  R9=%llX",
            ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
            ep->ContextRecord->R8, ep->ContextRecord->R9);

        LogStr(ep->ContextRecord->Rdx, "RDX как строка");
        LogStr(ep->ContextRecord->R8,  "R8 как строка");

        if (g_bp[i].dumpBig) {
            Dump(ep->ContextRecord->Rcx, "автомат", 16);
            if (g_bp[i].off == 0xA2DF60) g_lastSm = ep->ContextRecord->Rcx;
        } else {
            Dump(ep->ContextRecord->Rcx, "RCX", 3);
            // на моменте раскрытия показываем автомат — там уже лежит результат
            if (g_lastSm) Dump(g_lastSm, "автомат OpenBoxAsync в этот момент", 16);
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

    LOG("=== boxspy2: когда клиент узнаёт содержимое ===");
    LOG("база = 0x%llX", g_base);
    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s  (лимит %ld)", g_bp[i].off, g_bp[i].name, g_bp[i].cap);
    }
    LOG("");
    LOG("=== ГОТОВО — открывай сундук ===");

    for (int t = 0; t < 1500; t++) Sleep(1000);

    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed,0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
