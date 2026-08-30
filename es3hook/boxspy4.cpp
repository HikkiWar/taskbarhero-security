// boxspy4 — награда сундука: прочитать заранее и при необходимости подменить.
//
// Раскладка BoxData получена из дизассемблера BoxData::CopyToObscured.
// Функция берёт открытые поля, строит из них защищённые копии и затирает
// исходники нулями:
//
//     открытое            ->  защищённое
//     +0x54 int32 ItemId      +0x10
//     +0x58 строка UniqueKey  +0x20
//     +0x60 строка ClaimableAt+0x28
//     +0x68 int32 RewardItemId+0x30      <- ключ награды
//     +0x70 строка RewardUID  +0x40
//     +0x78 байт IsGet        +0x48
//
// Отсюда два вывода. Первый: на входе в CopyToObscured награда лежит открытым
// int32 — её видно до того, как игрок откроет сундук. Второй: если записать
// туда своё значение, игра сама построит из него защищённую копию, и вся
// Obscured-защита обходится не взломом, а приходом раньше неё.
//
// Подмена включается файлом SWAP.txt с одним числом — новым ключом. Нет
// файла — только чтение.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy4.log"
#define F_SWAP DIR "SWAP.txt"

#define OFF_ITEMID   0x54
#define OFF_UNIQUEK  0x58
#define OFF_CLAIMAT  0x60
#define OFF_REWARD   0x68
#define OFF_REWUID   0x70
#define OFF_ISGET    0x78

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static void Stamp(char* o, size_t n)
{ SYSTEMTIME s; GetLocalTime(&s); sprintf_s(o,n,"%02d:%02d:%02d.%03d",s.wHour,s.wMinute,s.wSecond,s.wMilliseconds); }

struct Bp { ULONG_PTR off, addr; const char* name; BYTE orig; volatile LONG armed, n; };
static Bp g_bp[] = {
    { 0x959B80, 0, "BoxData::CopyToObscured   НАГРАДА ВИДНА", 0, 0, 0 },
    { 0x9B5F30, 0, "GetBoxLog::.ctor          подбор", 0, 0, 0 },
    { 0x9B1A20, 0, "BoxOpenLog::.ctor         что выпало на самом деле", 0, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static int Ptr(ULONG_PTR v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }

// строка IL2CPP: +0x10 длина int32, +0x14 символы UTF-16
static void Str(ULONG_PTR p, const char* tag)
{
    if (!Ptr(p)) { LOG("      %-22s (пусто)", tag); return; }
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 2000) { LOG("      %-22s (не строка)", tag); return; }
        char b[6200];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n > 0) { b[n] = 0; LOG("      %-22s %s", tag, b); }
    } __except(1) { LOG("      %-22s (чтение упало)", tag); }
}

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
        if (n > 300) return EXCEPTION_CONTINUE_EXECUTION;

        char ts[32]; Stamp(ts, sizeof(ts));
        ULONG_PTR o = ep->ContextRecord->Rcx;

        LOG("");
        LOG("[%s] #%ld  %s", ts, n, g_bp[i].name);

        if (g_bp[i].off == 0x959B80) {
            __try {
                int itemId = *(int*)(o + OFF_ITEMID);
                int reward = *(int*)(o + OFF_REWARD);
                BYTE isget  = *(BYTE*)(o + OFF_ISGET);
                LOG("      объект 0x%llX", o);
                LOG("      %-22s %d", "ключ коробки", itemId);
                Str(*(ULONG_PTR*)(o + OFF_UNIQUEK), "UniqueKey");
                Str(*(ULONG_PTR*)(o + OFF_CLAIMAT), "ClaimableAt");
                LOG("      %-22s %d   <<<<<< НАГРАДА", "RewardItemId", reward);
                Str(*(ULONG_PTR*)(o + OFF_REWUID), "RewardItemUniqueID");
                LOG("      %-22s %d", "IsGet", isget);

                int nk;
                if (reward > 0 && ReadSwap(&nk) && nk != reward) {
                    *(int*)(o + OFF_REWARD) = nk;
                    LOG("      >>> ПОДМЕНА НАГРАДЫ: %d -> %d", reward, nk);
                    LOG("      >>> защищённую копию игра построит уже из нашего значения");
                }
            } __except(1) { LOG("      чтение объекта упало"); }
        } else {
            ULONG_PTR s = (g_bp[i].off == 0x9B1A20) ? ep->ContextRecord->Rdx
                                                    : ep->ContextRecord->R8;
            Str(s, "строка");
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

    LOG("=== boxspy4: награда сундука до открытия ===");
    LOG("база = 0x%llX", g_base);
    int k;
    if (ReadSwap(&k)) LOG("SWAP.txt найден: подменять награду на %d", k);
    else              LOG("SWAP.txt нет — только чтение");

    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s", g_bp[i].off, g_bp[i].name);
    }
    LOG("");
    LOG("=== ГОТОВО ===");

    for (int t = 0; t < 3000; t++) Sleep(1000);

    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed,0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
