// boxspy11 — подменить саму коробку, а не награду.
//
// Идея проверяемой атаки: сервер выдаёт коробку вместе с содержимым, поэтому
// подделать ключ предмета нельзя — сверят с выданным. Но если списать коробку A,
// а награду прочитать у коробки B, то предмет остаётся ЗАКОННЫМ (его выдал сам
// сервер), а B при этом останется неоткрытой. Тогда её можно вскрыть ещё раз.
//
// Это уже не подделка, а дублирование. Проверка «выдавал ли я такой предмет»
// такое пропускает по устройству: проверять надо «сколько раз выдавал».
//
// Где подменять. Прошлый заход правил EAX после call в MoveNext+0x426 — там
// сидит только построение строки лога, выдачу ведёт другой вызывающий
// (tt::iru+0x30). Поэтому правим RCX на ВХОДЕ в геттеры: тогда данные чужой
// коробки получат все потребители сразу.
//
//     BoxData::get_RewardItemId        RVA 0x959C80   (this в RCX)
//     BoxData::get_RewardItemUniqueID  RVA 0x959CA0   (this в RCX)
//
// Цель задаётся файлом BOXPTR.txt — шестнадцатеричный адрес объекта BoxData,
// который выдаёт peek.py. Нет файла — только наблюдение.
//
// Перед подменой адрес проверяется: по +0x54 у BoxData лежит открытый ItemId,
// и он обязан быть похож на ключ коробки. Иначе подсунем мусор и уроним игру.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

#define DIR    "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\"
#define F_LOG  DIR "boxspy11.log"
#define F_PTR  DIR "BOXPTR.txt"

#define OFF_GET_REWARD     0x959C80     // вход в get_RewardItemId
#define OFF_GET_REWARD_RET 0x959C99     // его +0x19, в RAX уже расшифровано
#define OFF_GET_REWUID     0x959CA0     // вход в get_RewardItemUniqueID
#define OFF_BOXOPENLOG     0x9B1A20
#define OFF_PLAIN_ITEMID   0x54         // открытый ItemId внутри BoxData

static FILE* g_log; static HANDLE g_mtx;
#define LOG(f_, ...) do { if (g_log && g_mtx) { WaitForSingleObject(g_mtx,2000); \
    fprintf(g_log, f_ "\n", ##__VA_ARGS__); fflush(g_log); ReleaseMutex(g_mtx);} } while(0)

struct Bp { ULONG_PTR off, addr; const char* name; BYTE orig; LONG cap; volatile LONG armed, n; };
static Bp g_bp[] = {
    { OFF_GET_REWARD,     0, "вход get_RewardItemId",       0, 200, 0, 0 },
    { OFF_GET_REWUID,     0, "вход get_RewardItemUniqueID", 0, 200, 0, 0 },
    { OFF_GET_REWARD_RET, 0, "награда после расшифровки",   0, 200, 0, 0 },
    { OFF_BOXOPENLOG,     0, "BoxOpenLog  что записано",    0, 200, 0, 0 },
};
static const int G_N = sizeof(g_bp)/sizeof(g_bp[0]);

static void* g_rearm; static ULONG_PTR g_base, g_end;

static void PutByte(ULONG_PTR a, BYTE v)
{ DWORD o; VirtualProtect((void*)a,1,PAGE_EXECUTE_READWRITE,&o); *(BYTE*)a=v; VirtualProtect((void*)a,1,o,&o); }

static void Str(ULONG_PTR p, const char* tag)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return;
    __try {
        int len = *(int*)(p + 0x10);
        if (len <= 0 || len > 2000) return;
        char b[6200];
        int n = WideCharToMultiByte(CP_UTF8,0,(wchar_t*)(p+0x14),len,b,sizeof(b)-1,NULL,NULL);
        if (n > 0) { b[n] = 0; LOG("               %s %s", tag, b); }
    } __except(1) {}
}

static ULONG_PTR ReadTarget(void)
{
    FILE* f = fopen(F_PTR, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    int ok = fscanf(f, "%llx", &v) == 1;
    fclose(f);
    return ok ? (ULONG_PTR)v : 0;
}

// Подсовывать что попало нельзя: проверяем, что это правда BoxData.
static int LooksLikeBox(ULONG_PTR p)
{
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF) return 0;
    __try {
        int k = *(int*)(p + OFF_PLAIN_ITEMID);
        return k >= 100000 && k <= 999999;
    } __except(1) { return 0; }
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (!g_rearm) return EXCEPTION_CONTINUE_SEARCH;
        for (int i = 0; i < G_N; i++)
            if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                PutByte(g_bp[i].addr, 0xCC);
                InterlockedExchange(&g_bp[i].armed, 1); break;
            }
        g_rearm = NULL;
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

        if (g_bp[i].off == OFF_GET_REWARD || g_bp[i].off == OFF_GET_REWUID) {
            ULONG_PTR cur = ep->ContextRecord->Rcx;
            int curkey = 0;
            __try { curkey = *(int*)(cur + OFF_PLAIN_ITEMID); } __except(1) {}
            LOG("[%02d:%02d:%02d.%03d] %s  коробка 0x%llX (ключ %d)  спросил +0x%llX",
                s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, g_bp[i].name,
                cur, curkey, (ret >= g_base && ret < g_end) ? ret - g_base : 0);

            ULONG_PTR tgt = ReadTarget();
            if (tgt && tgt != cur) {
                if (LooksLikeBox(tgt)) {
                    ep->ContextRecord->Rcx = tgt;
                    LOG("               >>> ПОДМЕНА КОРОБКИ: 0x%llX -> 0x%llX", cur, tgt);
                } else {
                    LOG("               !!! адрес 0x%llX не похож на BoxData — не трогаю", tgt);
                }
            }
        } else if (g_bp[i].off == OFF_GET_REWARD_RET) {
            LOG("               = награда %d", (int)(ep->ContextRecord->Rax & 0xFFFFFFFF));
        } else {
            LOG("[%02d:%02d:%02d.%03d] %s", s.wHour, s.wMinute, s.wSecond, s.wMilliseconds, g_bp[i].name);
            Str(ep->ContextRecord->Rdx, "->");
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

    LOG("=== boxspy11: подмена самой коробки ===");
    LOG("база = 0x%llX", g_base);
    ULONG_PTR t = ReadTarget();
    if (t) LOG("BOXPTR.txt: цель 0x%llX%s", t, LooksLikeBox(t) ? "" : "  (НЕ похоже на BoxData!)");
    else   LOG("BOXPTR.txt нет — только наблюдение");

    AddVectoredExceptionHandler(1, Veh);
    for (int i = 0; i < G_N; i++) {
        g_bp[i].addr = g_base + g_bp[i].off;
        __try { g_bp[i].orig = *(BYTE*)g_bp[i].addr; } __except(1) { continue; }
        if (g_bp[i].orig == 0xCC) { LOG("  +0x%llX занят", g_bp[i].off); continue; }
        PutByte(g_bp[i].addr, 0xCC);
        InterlockedExchange(&g_bp[i].armed, 1);
        LOG("  +0x%llX  %s", g_bp[i].off, g_bp[i].name);
    }
    LOG("");
    LOG("=== ГОТОВО ===");

    for (int t2 = 0; t2 < 3600; t2++) Sleep(1000);

    for (int i = 0; i < G_N; i++)
        if (g_bp[i].armed) { PutByte(g_bp[i].addr, g_bp[i].orig); InterlockedExchange(&g_bp[i].armed,0); }
    LOG("=== завершено, точки сняты ===");
    WaitForSingleObject(g_mtx, 2000);
    FILE* f = g_log; g_log = NULL; fclose(f); ReleaseMutex(g_mtx);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{ if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL);} return TRUE; }
