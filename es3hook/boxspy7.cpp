// boxspy7 — узнаёт ли сервер о награде сундука, и когда.
//
// Вопрос, оставшийся открытым: подменённый предмет сервер удалил при входе
// («Предметы, не хранящиеся на сервере, очищены»). Но между подменой и
// перезапуском прошло всего четыре минуты — может, просто не успело уйти?
//
// Ответ даёт не ожидание, а хронометраж. Если клиент НИКОГДА не сообщает
// серверу, какой предмет выпал, то ждать бессмысленно: предмет попадает в
// серверный реестр не из сейва, а от того, кто его выдал.
//
// Поэтому смотрим на обычное открытие, без подмены, и ставим точки на всё,
// что связано с сервером:
//
//   ClaimStageBoxAsync          заявка на сундук
//   TryClaimItem                заявка на предмет
//   SendHttpRequestWithNonBro   собственно отправка
//   SynchronizeInventoryByBackendData / HandleBackendInventoryUpdate
//                               приход данных ОТ сервера
//   CallCheckValidItems / DeleteOnlyServerDeletedItems
//                               сверка и вычистка
//   AutoSaveAsync               локальное сохранение, для привязки времени
//
// Плюс сам геттер награды — чтобы в хронометраже была видна точка отсчёта.
// Подмена включается файлом SWAP.txt; по умолчанию его нет, только чтение.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy7.log"
#define F_SWAP DIR "SWAP.txt"

#define OFF_REWARD_RET 0x959C99      // BoxData::get_RewardItemId + 0x19

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

struct Bp {
    ULONG_PTR off, addr; const char* name;
    BYTE orig; LONG cap; volatile LONG armed, n;
};

static Bp g_bp[] = {
    { OFF_REWARD_RET, 0, "get_RewardItemId -> награда прочитана", 0, 100, 0, 0 },
    { 0x9075F0, 0, "ClaimStageBoxAsync        ЗАЯВКА НА СУНДУК",  0,  60, 0, 0 },
    { 0x908BF0, 0, "TryClaimItem              заявка на предмет", 0,  60, 0, 0 },
    { 0xC49940, 0, "SendHttpRequest           ОТПРАВКА В СЕТЬ",   0, 150, 0, 0 },
    { 0xC1BCD0, 0, "SyncInventoryByBackend    данные ОТ сервера", 0,  60, 0, 0 },
    { 0x999960, 0, "HandleBackendInvUpdate    обновление ОТ сервера", 0, 60, 0, 0 },
    { 0x997C20, 0, "CallCheckValidItems       СВЕРКА ПРЕДМЕТОВ",  0,  60, 0, 0 },
    { 0x999140, 0, "DeleteOnlyServerDeleted   ВЫЧИСТКА",          0,  60, 0, 0 },
    { 0xA81A50, 0, "AutoSaveAsync             локальное сохранение", 0, 40, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

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
        if (n > g_bp[i].cap) return EXCEPTION_CONTINUE_EXECUTION;   // точку больше не взводим

        SYSTEMTIME s; GetLocalTime(&s);

        if (g_bp[i].off == OFF_REWARD_RET) {
            int real = (int)(ep->ContextRecord->Rax & 0xFFFFFFFF);
            ULONG_PTR ret = 0;
            __try { ret = *(ULONG_PTR*)(ep->ContextRecord->Rsp + 0x38); } __except(1) {}
            LOG("[%02d:%02d:%02d.%03d] #%-3ld %s = %d  (спросил +0x%llX)",
                s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n, g_bp[i].name, real,
                (ret >= g_base && ret < g_end) ? ret - g_base : 0);
            int nk;
            if (ReadSwap(&nk) && nk != real) {
                ep->ContextRecord->Rax = (ULONG_PTR)(unsigned int)nk;
                LOG("               >>> ПОДМЕНА: %d -> %d", real, nk);
            }
        } else {
            LOG("[%02d:%02d:%02d.%03d] #%-3ld %s",
                s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n, g_bp[i].name);
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

    LOG("=== boxspy7: хронометраж общения с сервером ===");
    LOG("база = 0x%llX", g_base);
    int k;
    if (ReadSwap(&k)) LOG("SWAP.txt: подменять награду на %d", k);
    else              LOG("SWAP.txt нет — подмена выключена, только наблюдение");

    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        if (g_bp[i].orig == 0xCC) { LOG("  +0x%llX занят чужой точкой — пропускаю", g_bp[i].off); continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s  (лимит %ld)", g_bp[i].off, g_bp[i].name, g_bp[i].cap);
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
