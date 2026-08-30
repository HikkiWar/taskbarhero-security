// boxspy8 — что именно клиент говорит серверу и когда.
//
// Прошлый заход перехватывал SendHttpRequest и не поймал ничего: игра держит
// постоянное соединение и общается через socket.io (BACKND), а не запросами.
// Значит слушать надо сокет и запись данных игрока:
//
//   SocketIoClientDotNet.Client.Socket::Emit(p=2)   отправка события (имя, данные)
//   SocketIoClientDotNet.Client.Socket::Send(p=1)
//   SendQueue::Enqueue(p=2)                         очередь отправки
//   PlayerDataTransactionWrite::AddUpdateMyData     ЗАПИСЬ ДАННЫХ ИГРОКА
//   PlayerDataTransactionWrite::AddInsert
//
// Вопрос, который это закрывает: сообщает ли клиент серверу, какой предмет
// выпал из сундука. Если нет — ждать отправки бессмысленно, подменённый
// предмет в серверный реестр не попадёт никогда.
//
// Точку на get_RewardItemId здесь не ставим: её держит boxspy7, а метки
// времени в обоих логах позволяют сопоставить события.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\boxspy8.log"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

struct Bp { ULONG_PTR off, addr; const char* name; BYTE orig; LONG cap; volatile LONG armed, n; };
static Bp g_bp[] = {
    { 0xC644A0, 0, "Socket::Emit           ОТПРАВКА СОБЫТИЯ", 0, 200, 0, 0 },
    { 0xC65490, 0, "Socket::Send",                            0, 200, 0, 0 },
    { 0xC45FE0, 0, "SendQueue::Enqueue     в очередь",        0, 200, 0, 0 },
    { 0xC45540, 0, "AddUpdateMyData        ЗАПИСЬ ДАННЫХ ИГРОКА", 0, 200, 0, 0 },
    { 0xC45420, 0, "AddInsert              вставка строки",   0, 200, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static int Ptr(ULONG_PTR v) { return v > 0x10000 && v < 0x7FFFFFFFFFFF; }

// строка IL2CPP: +0x10 длина int32, +0x14 символы UTF-16
static int Str(ULONG_PTR p, const char* tag)
{
    if (!Ptr(p)) return 0;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 3000) return 0;
        char b[9200];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n <= 0) return 0;
        b[n] = 0;
        LOG("        %s: %s", tag, b);
        return 1;
    } __except(1) { return 0; }
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
        if (n > g_bp[i].cap) return EXCEPTION_CONTINUE_EXECUTION;

        SYSTEMTIME s; GetLocalTime(&s);
        ULONG_PTR ret = 0;
        __try { ret = *(ULONG_PTR*)ep->ContextRecord->Rsp; } __except(1) {}

        LOG("[%02d:%02d:%02d.%03d] #%-3ld %s",
            s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n, g_bp[i].name);
        if (ret >= g_base && ret < g_end) LOG("        вызван из +0x%llX", ret - g_base);
        // аргументы: любой из них может оказаться строкой с именем события
        Str(ep->ContextRecord->Rdx, "RDX");
        Str(ep->ContextRecord->R8,  "R8");
        Str(ep->ContextRecord->R9,  "R9");

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

    LOG("=== boxspy8: что уходит на сервер ===");
    LOG("база = 0x%llX", g_base);
    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        if (g_bp[i].orig == 0xCC) { LOG("  +0x%llX занят — пропускаю", g_bp[i].off); continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s", g_bp[i].off, g_bp[i].name);
    }
    LOG("");
    LOG("=== ГОТОВО ===");

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
