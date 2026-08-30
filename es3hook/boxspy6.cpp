// boxspy6 — подмена награды на выходе из геттера, а не у одного вызывающего.
//
// Прошлый заход перехватывал EAX в <OpenBoxAsync>d__74::MoveNext+0x426, сразу
// после call get_RewardItemId. Подмена прошла: игра записала в свой лог наше
// значение (ItemName_340011). Но в сейв попала настоящая награда (352141) —
// значит выдачей занимается другой потребитель того же геттера, а +0x426
// кормит только строку лога.
//
// Отсюда правка: перехватываем не вызывающего, а САМ геттер на выходе.
//
//     BoxData::get_RewardItemId  (RVA 0x959C80)
//       +0x00  sub rsp, 0x38
//       +0x04  movups xmm0, [rcx+0x30]      защищённое значение
//       +0x14  call 0x6E8690                расшифровка, результат в EAX
//       +0x19  add rsp, 0x38                <- точка здесь
//       +0x1D  ret
//
// Ставим точку на +0x19: RAX уже содержит расшифрованный ключ, но функция ещё
// не вернулась. Переписываем — и наше значение получает КАЖДЫЙ вызывающий,
// включая тот, что создаёт предмет.
//
// Подмена включается файлом SWAP.txt с одним числом. Нет файла — только чтение.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy6.log"
#define F_SWAP DIR "SWAP.txt"

#define OFF_HOOK 0x959C99          // BoxData::get_RewardItemId + 0x19

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static ULONG_PTR g_addr, g_base, g_end;
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

    // адрес возврата геттера — видно, КТО именно спросил награду
    ULONG_PTR ret = 0;
    __try { ret = *(ULONG_PTR*)(ep->ContextRecord->Rsp + 0x38); } __except(1) {}

    SYSTEMTIME s; GetLocalTime(&s);
    int real = (int)(ep->ContextRecord->Rax & 0xFFFFFFFF);
    LOG("");
    LOG("[%02d:%02d:%02d.%03d] вызов #%ld  get_RewardItemId -> %d",
        s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n, real);
    if (ret >= g_base && ret < g_end) LOG("      спросил: +0x%llX", ret - g_base);

    int nk;
    if (ReadSwap(&nk) && nk != real) {
        ep->ContextRecord->Rax = (ULONG_PTR)(unsigned int)nk;
        LOG("      >>> ПОДМЕНА: %d -> %d", real, nk);
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
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;
    g_addr = g_base + OFF_HOOK;

    LOG("=== boxspy6: подмена на выходе из get_RewardItemId ===");
    LOG("база = 0x%llX, точка на +0x%X", g_base, OFF_HOOK);
    int k;
    if (ReadSwap(&k)) LOG("SWAP.txt: подменять на %d", k);
    else              LOG("SWAP.txt нет — только чтение");

    AddVectoredExceptionHandler(1, Veh);
    __try { g_orig = *(BYTE*)g_addr; } __except(1) { LOG("адрес нечитаем"); return 0; }
    if (g_orig == 0xCC) { LOG("на адресе уже чужая точка — отказываюсь"); return 0; }
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
