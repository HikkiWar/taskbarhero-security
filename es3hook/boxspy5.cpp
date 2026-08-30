// boxspy5 — подмена награды сундука одной инструкцией.
//
// Дизассемблер <OpenBoxAsync>d__74::MoveNext дал точное место:
//
//     +0x421  call  BoxData::get_RewardItemId
//     +0x426  mov   r13d, eax        <- EAX = ключ награды
//     +0x429  mov   [rsp+0x58], eax
//
// Ставим точку останова на +0x426. В обработчике переписываем RAX и
// возвращаем выполнение на тот же адрес — инструкция выполнится уже с нашим
// значением. Ни трамплина, ни правки кода: одна точка, один регистр.
//
// Почему это работает мимо защиты. Поля BoxData защищены паттерном Obscured:
//     +0x00 контрольная сумма, +0x04 (ключ^значение)+ключ, +0x08 ключ,
//     +0x0C открытая копия-приманка
// Все сверки происходят ВНУТРИ get_RewardItemId. Мы вмешиваемся после её
// возврата, когда проверять уже нечего — дальше по коду идёт голый int.
//
// Точка останова здесь ровно одна, с BoxOpenLog не пересекается: его пишет
// boxspy4, и это даёт независимое подтверждение подмены.
//
// Подмена включается файлом SWAP.txt с одним числом. Нет файла — только чтение.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy5.log"
#define F_SWAP DIR "SWAP.txt"

#define OFF_HOOK 0xA2E386          // <OpenBoxAsync>d__74::MoveNext + 0x426

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static ULONG_PTR g_addr, g_base;
static BYTE  g_orig;
static volatile LONG g_armed, g_n;
static void* g_rearm;

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
        if (g_rearm == (void*)g_addr) {
            PutByte(g_addr, 0xCC);
            InterlockedExchange(&g_armed, 1);
            g_rearm = NULL;
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c != EXCEPTION_BREAKPOINT || a != g_addr) return EXCEPTION_CONTINUE_SEARCH;
    if (!InterlockedCompareExchange(&g_armed, 0, 1)) return EXCEPTION_CONTINUE_SEARCH;

    PutByte(a, g_orig);
    ep->ContextRecord->Rip = a;
    LONG n = InterlockedIncrement(&g_n);

    SYSTEMTIME s; GetLocalTime(&s);
    int real = (int)(ep->ContextRecord->Rax & 0xFFFFFFFF);
    LOG("");
    LOG("[%02d:%02d:%02d.%03d] #%ld  награда сундука прочитана",
        s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n);
    LOG("      настоящая награда: %d", real);

    int nk;
    if (ReadSwap(&nk) && nk != real) {
        ep->ContextRecord->Rax = (ULONG_PTR)(unsigned int)nk;
        LOG("      >>> ПОДМЕНА: %d -> %d", real, nk);
        LOG("      >>> инструкция выполнится уже с новым значением");
    } else {
        LOG("      (подмена выключена — SWAP.txt отсутствует)");
    }

    g_rearm = (void*)a;
    ep->ContextRecord->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
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
    g_base = (ULONG_PTR)mi.lpBaseOfDll;
    g_addr = g_base + OFF_HOOK;

    LOG("=== boxspy5: подмена награды сундука ===");
    LOG("база = 0x%llX, точка на +0x%X (0x%llX)", g_base, OFF_HOOK, g_addr);
    int k;
    if (ReadSwap(&k)) LOG("SWAP.txt: подменять на %d", k);
    else              LOG("SWAP.txt нет — только чтение");

    AddVectoredExceptionHandler(1, Veh);
    __try { g_orig = *(BYTE*)g_addr; } __except(1) { LOG("адрес нечитаем"); return 0; }
    if (g_orig == 0xCC) { LOG("на адресе уже стоит чужая точка — отказываюсь"); return 0; }
    PutByte(g_addr, 0xCC);
    InterlockedExchange(&g_armed, 1);
    LOG("исходный байт %02X, точка взведена", g_orig);
    LOG("");
    LOG("=== ГОТОВО — открывай сундук ===");

    for (int t = 0; t < 3000; t++) Sleep(1000);

    if (g_armed) { PutByte(g_addr, g_orig); InterlockedExchange(&g_armed, 0); }
    LOG("=== завершено, точка снята ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
