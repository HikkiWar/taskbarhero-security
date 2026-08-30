// dragspy.cpp — прочитать аргументы ядра цепочки экипировки.
//
// Цели (смещения от базы GameAssembly.dll, найдены методом исключения):
//   0x846E00  DragData::.ctor(p=3)             захват предмета
//   0x878680  SlotInteractionManager::icd(p=1) обработка
//   0x875AF0  MoveResult::iaa(p=1)             результат
//
// Точки останова ПОСТОЯННЫЕ (перевзвод через одиночный шаг) — нужно видеть
// каждый вызов, а не только первый. Их всего три, лог не разрастётся.
//
// Соглашение вызова x64: RCX = this, далее RDX, R8, R9.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\dragspy.log"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,1000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

struct Bp { ULONG_PTR addr; BYTE orig; const char* name; volatile LONG armed; volatile LONG n; };
static Bp g_bp[8]; static int g_c = 0;
static void* g_rearm; static ULONG_PTR g_base, g_end;

static void DumpObj(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        LOG("      %s = 0x%llX", tag, p);
        for (int r = 0; r < 4; r++) {
            ULONG_PTR* q = (ULONG_PTR*)(p + r * 16);
            LOG("        +%02X: %016llX %016llX   int32: %d %d %d %d",
                r * 16, q[0], q[1],
                *(int*)(p + r*16), *(int*)(p + r*16 + 4),
                *(int*)(p + r*16 + 8), *(int*)(p + r*16 + 12));
        }
    } __except(1) { LOG("      %s: чтение упало", tag); }
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (g_rearm) {
            for (int i = 0; i < g_c; i++)
                if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                    DWORD o; VirtualProtect((void*)g_bp[i].addr,1,PAGE_EXECUTE_READWRITE,&o);
                    *(BYTE*)g_bp[i].addr = 0xCC;
                    VirtualProtect((void*)g_bp[i].addr,1,o,&o);
                    InterlockedExchange(&g_bp[i].armed,1); break;
                }
            g_rearm = NULL;
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < g_c; i++) {
        if (a != g_bp[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bp[i].armed, 0, 1)) return EXCEPTION_CONTINUE_SEARCH;

        DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o);
        *(BYTE*)a = g_bp[i].orig; VirtualProtect((void*)a,1,o,&o);
        ep->ContextRecord->Rip = a;

        LONG n = InterlockedIncrement(&g_bp[i].n);
        ULONG_PTR ret = 0;
        __try { ret = *(ULONG_PTR*)ep->ContextRecord->Rsp; } __except(1) {}

        LOG("");
        LOG("=== %s  вызов #%ld ===", g_bp[i].name, n);
        LOG("      RCX=%llX  RDX=%llX  R8=%llX  R9=%llX",
            ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
            ep->ContextRecord->R8, ep->ContextRecord->R9);
        if (ret >= g_base && ret < g_end)
            LOG("      вызван из +0x%llX", ret - g_base);
        DumpObj(ep->ContextRecord->Rcx, "RCX");
        DumpObj(ep->ContextRecord->Rdx, "RDX");
        DumpObj(ep->ContextRecord->R8,  "R8");

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void Set(ULONG_PTR off, const char* name)
{
    ULONG_PTR a = g_base + off;
    g_bp[g_c].addr = a; g_bp[g_c].orig = *(BYTE*)a;
    g_bp[g_c].name = name; g_bp[g_c].armed = 1; g_bp[g_c].n = 0;
    DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o);
    *(BYTE*)a = 0xCC; VirtualProtect((void*)a,1,o,&o);
    LOG("  точка на +0x%llX (0x%llX) orig=%02X  %s", off, a, g_bp[g_c].orig, name);
    g_c++;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2500);
    g_mtx = CreateMutexA(NULL,FALSE,NULL);
    g_log = fopen(F_LOG, "w");
    if (!g_log) return 0;
    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    MODULEINFO mi = {}; GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;
    LOG("=== dragspy === база 0x%llX", g_base);
    AddVectoredExceptionHandler(1, Veh);

    Set(0x846E00, "DragData::.ctor(p=3)");
    Set(0x878680, "SlotInteractionManager::icd(p=1)");
    Set(0x875AF0, "MoveResult::iaa(p=1)");
    LOG("");
    LOG("=== ГОТОВО — меняй снаряжение ===");

    for (int t = 0; t < 900; t++) Sleep(1000);
    LOG("=== завершено ===");
    fclose(g_log);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
