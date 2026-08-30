// boxspy.cpp — кто решает содержимое сундука: клиент или сервер.
//
// Классы подсистемы коробок обфускация не тронула, и они называют схему сами:
//
//   InventoryProcessBoxRequest::CreateItemListToJson   список создаваемых предметов
//   InventoryProcessBoxRequest::UseItemKeyListToJson   какие коробки тратим
//   BoxCreateItem::Initialize(p=3)                     клиент готовит предмет
//   InventoryProcessBoxResult::Initialize(p=1)         ответ сервера
//
// Вопрос решается ПОРЯДКОМ вызовов:
//   BoxCreateItem раньше Result  -> предмет выбрал клиент, сервер лишь заверил
//   Result раньше BoxCreateItem  -> решает сервер, клиент только рисует
//
// Поэтому пишем время с точностью до миллисекунды и номер потока.
//
// Для методов, возвращающих строку, ставим ловушку на адрес возврата: на входе
// читаем его из RSP, вешаем одноразовый INT3, на срабатывании в RAX лежит
// готовая строка. Так виден настоящий JSON, а не обфусцированные поля объекта.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\boxspy.log"

static FILE* g_log; static HANDLE g_mtx; static ULONGLONG g_t0;

#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

static void Stamp(char* out, size_t n)
{
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(out, n, "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ── цели ────────────────────────────────────────────────────────────────────
struct Bp {
    ULONG_PTR off, addr;
    const char* name;
    BYTE  orig;
    int   wantRet;          // ловить ли возвращаемое значение
    const char* retTag;
    volatile LONG armed, n;
};

static Bp g_bp[] = {
    { 0x9B5F30, 0, "GetBoxLog::.ctor(p=2)                    подбор коробки", 0, 0, NULL, 0, 0 },
    { 0x959B20, 0, "BoxCreateItem::Initialize(p=3)           КЛИЕНТ готовит предмет", 0, 0, NULL, 0, 0 },
    { 0x960370, 0, "ProcessBoxRequest::Initialize(p=4)       сборка запроса", 0, 0, NULL, 0, 0 },
    { 0x960160, 0, "ProcessBoxRequest::CreateItemListToJson", 0, 1, "JSON создаваемых", 0, 0 },
    { 0x960650, 0, "ProcessBoxRequest::UseItemKeyListToJson", 0, 1, "JSON расходуемых", 0, 0 },
    { 0x960760, 0, "ProcessBoxResult::Initialize(p=1)        ОТВЕТ СЕРВЕРА", 0, 0, NULL, 0, 0 },
    { 0x960C10, 0, "ProcessBoxResult::ToString(p=0)",         0, 1, "результат", 0, 0 },
    { 0x9611E0, 0, "InventoryProcessBox::GetResultData(p=0)", 0, 0, NULL, 0, 0 },
    { 0x9B1A20, 0, "BoxOpenLog::.ctor(p=2)                   лог открытия", 0, 0, NULL, 0, 0 },
};
static const int G_N = sizeof(g_bp) / sizeof(g_bp[0]);

// ── ловушки на адрес возврата ───────────────────────────────────────────────
struct Ret { ULONG_PTR addr; BYTE orig; const char* tag; volatile LONG live; };
static Ret g_ret[16];

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{
    DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
    *(BYTE*)a = v; VirtualProtect((void*)a, 1, o, &o);
}

// строка IL2CPP: +0x10 длина (int32), +0x14 символы UTF-16
static void LogStr(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 8000) return;
        char buf[24600];
        int n = WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)(p + 0x14), len,
                                    buf, sizeof(buf) - 1, NULL, NULL);
        if (n <= 0) return;
        buf[n] = 0;
        LOG("      %s = %s", tag, buf);
    } __except(1) {}
}

static void DumpObj(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        LOG("      %s = 0x%llX", tag, p);
        for (int r = 0; r < 6; r++) {
            ULONG_PTR* q = (ULONG_PTR*)(p + r * 16);
            LOG("        +%02X: %016llX %016llX   int32: %d %d %d %d",
                r * 16, q[0], q[1],
                *(int*)(p + r*16),     *(int*)(p + r*16 + 4),
                *(int*)(p + r*16 + 8), *(int*)(p + r*16 + 12));
        }
    } __except(1) {}
}

static void ArmRet(ULONG_PTR ra, const char* tag)
{
    if (ra < g_base || ra >= g_end) return;
    BYTE cur = 0;
    __try { cur = *(BYTE*)ra; } __except(1) { return; }
    if (cur == 0xCC) return;                       // уже занято другой ловушкой
    for (int i = 0; i < 16; i++) {
        if (InterlockedCompareExchange(&g_ret[i].live, 1, 0) != 0) continue;
        g_ret[i].addr = ra; g_ret[i].orig = cur; g_ret[i].tag = tag;
        PutByte(ra, 0xCC);
        return;
    }
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
                    InterlockedExchange(&g_bp[i].armed, 1);
                    break;
                }
            g_rearm = NULL;
        }
        ep->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    // сперва ловушки возврата — они одноразовые
    for (int i = 0; i < 16; i++) {
        if (g_ret[i].live != 1 || g_ret[i].addr != a) continue;
        PutByte(a, g_ret[i].orig);
        ep->ContextRecord->Rip = a;
        LogStr(ep->ContextRecord->Rax, g_ret[i].tag);
        InterlockedExchange(&g_ret[i].live, 0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    for (int i = 0; i < G_N; i++) {
        if (a != g_bp[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bp[i].armed, 0, 1))
            return EXCEPTION_CONTINUE_SEARCH;

        PutByte(a, g_bp[i].orig);
        ep->ContextRecord->Rip = a;

        LONG n = InterlockedIncrement(&g_bp[i].n);
        ULONG_PTR ret = 0;
        __try { ret = *(ULONG_PTR*)ep->ContextRecord->Rsp; } __except(1) {}

        char ts[32]; Stamp(ts, sizeof(ts));
        LOG("");
        LOG("[%s] #%ld  %s   (поток %lu)", ts, n, g_bp[i].name, GetCurrentThreadId());
        LOG("      RCX=%llX  RDX=%llX  R8=%llX  R9=%llX",
            ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
            ep->ContextRecord->R8, ep->ContextRecord->R9);
        if (ret >= g_base && ret < g_end) LOG("      вызван из +0x%llX", ret - g_base);

        // аргументы могут быть строками или объектами — пробуем и то и другое
        LogStr(ep->ContextRecord->Rdx, "RDX как строка");
        LogStr(ep->ContextRecord->R8,  "R8 как строка");
        DumpObj(ep->ContextRecord->Rcx, "RCX");
        if (ep->ContextRecord->Rdx > 0x10000) DumpObj(ep->ContextRecord->Rdx, "RDX");

        if (g_bp[i].wantRet) ArmRet(ret, g_bp[i].retTag);

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
    g_t0 = GetTickCount64();

    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi = {}; GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    g_base = (ULONG_PTR)mi.lpBaseOfDll; g_end = g_base + mi.SizeOfImage;

    LOG("=== boxspy: кто решает содержимое сундука ===");
    LOG("база GameAssembly.dll = 0x%llX", g_base);
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

    for (int t = 0; t < 1200; t++) Sleep(1000);

    // снимаем всё, иначе после закрытия лога сработавшая точка уронит игру
    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed, 0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f);
    ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, Worker, NULL, 0, NULL); }
    return TRUE;
}
