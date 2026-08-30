// boxspy9 — уходит ли хоть байт в момент открытия сундука.
//
// Перехваты на socket.io и на запись данных игрока не дали ничего: возможно,
// данные идут другим слоем. Чтобы закрыть вопрос без догадок, встаём на самое
// дно — системные сокеты ws2_32.dll. Мимо них не проходит ни один байт.
//
// Содержимое зашифровано TLS и нам недоступно, но вопрос стоит иначе:
// сообщает ли клиент серверу о награде вообще. Если в секунду открытия
// исходящих байт нет, то ждать отправки бессмысленно — подменённый предмет
// в серверный реестр не попадёт никогда, сколько ни жди.
//
// Пишем только время, направление и размер. Этого хватает: метки времени
// сопоставляются с boxspy7, где виден момент чтения награды.
#include <windows.h>
#include <stdio.h>

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\boxspy9.log"

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

struct Bp { const char* mod; const char* fn; ULONG_PTR addr; const char* tag;
            BYTE orig; LONG cap; volatile LONG armed, n; };

static Bp g_bp[] = {
    { "ws2_32.dll", "send",    0, "-> ОТПРАВКА",   0, 400, 0, 0 },
    { "ws2_32.dll", "WSASend", 0, "-> ОТПРАВКА",   0, 400, 0, 0 },
    { "ws2_32.dll", "recv",    0, "<- приём",      0, 400, 0, 0 },
    { "ws2_32.dll", "WSARecv", 0, "<- приём",      0, 400, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);
static void* g_rearm;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

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
        // send/recv: RCX=сокет, RDX=буфер, R8=длина
        // WSASend/WSARecv: RCX=сокет, RDX=массив буферов, R8=их число
        LOG("[%02d:%02d:%02d.%03d] #%-3ld %-12s %s  сокет=%llu  длина=%lld",
            s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, n,
            g_bp[i].fn, g_bp[i].tag,
            (unsigned long long)ep->ContextRecord->Rcx,
            (long long)(LONG_PTR)ep->ContextRecord->R8);

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(1500);
    g_mtx = CreateMutexA(NULL, FALSE, NULL);
    g_log = fopen(F_LOG, "w");
    if (!g_log) return 0;

    LOG("=== boxspy9: системные сокеты ===");
    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        HMODULE m = GetModuleHandleA(g_bp[i].mod);
        if (!m) { LOG("  нет модуля %s", g_bp[i].mod); continue; }
        void* f = (void*)GetProcAddress(m, g_bp[i].fn);
        if (!f) { LOG("  нет функции %s", g_bp[i].fn); continue; }
        g_bp[i].addr = (ULONG_PTR)f;
        __try { g_bp[i].orig = *(BYTE*)f; } __except(1) { continue; }
        if (g_bp[i].orig == 0xCC) { LOG("  %s занят", g_bp[i].fn); continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  0x%llX  %s %s", g_bp[i].addr, g_bp[i].fn, g_bp[i].tag);
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
