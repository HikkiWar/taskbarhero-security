// stagespy v9
// Guard → сканируем назад → FnStart инициатора
// При FnStart: RSP[0] = return addr внутри родителя → сканируем назад → ParentStart
// Хукаем ParentStart → авто-вызов РОДИТЕЛЯ (он генерирует свежий stage-clear token)

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define F_LOG  "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\stagespy.log"
#define F_BOSS "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\stagespy.boss"
#define MAXBP  64

enum BpKind { BP_DIRECTING, BP_GUARD, BP_FNSTART, BP_PARENT };

struct Bp {
    ULONG_PTR    addr;
    BYTE         orig;
    char         name[96];
    volatile LONG armed;
    BpKind        kind;
};

static Bp        g_bp[MAXBP];
static int       g_c     = 0;
static void*     g_rearm = NULL;
static ULONG_PTR g_base, g_end;
static FILE*     g_log, *g_log2;
static HANDLE    g_mtx;

#define LOG(f_,...) do{ if(g_log&&g_mtx){ \
    WaitForSingleObject(g_mtx,800); \
    fprintf(g_log,f_ "\n",##__VA_ARGS__); \
    fflush(g_log); ReleaseMutex(g_mtx); } }while(0)
#define LOG2(f_,...) do{ if(g_log2&&g_mtx){ \
    WaitForSingleObject(g_mtx,800); \
    fprintf(g_log2,f_ "\n",##__VA_ARGS__); \
    fflush(g_log2); ReleaseMutex(g_mtx); } }while(0)

static volatile ULONG_PTR g_par_fn   = 0;
static volatile ULONG_PTR g_par_this = 0;
static volatile ULONG_PTR g_par_p1   = 0;
static volatile ULONG_PTR g_par_p2   = 0;
static volatile ULONG_PTR g_par_p3   = 0;
static volatile LONG      g_auto     = 0;
static volatile int       g_fn_found = 0; // 1=FnStart нашли, 2=Parent нашли

static void* g_domain = NULL;
typedef void* (*Fn_ta)(void*);
static Fn_ta p_ta = NULL;

static ULONG_PTR FindFuncStart(ULONG_PTR addr, int scan_bytes)
{
    const BYTE* p = (const BYTE*)addr;
    __try {
        for (int i = 4; i < scan_bytes; i++) {
            const BYTE* q = p - i;
            if (q[0]==0x48 && q[1]==0x83 && q[2]==0xEC) {
                const BYTE* b = q - 1;
                while (b >= q - 40) {
                    if (*b==0x53||*b==0x55||*b==0x56||*b==0x57) { b--; }
                    else if (b>q-39 && b[0]==0x41 && b[1]>=0x54 && b[1]<=0x57) { b-=2; }
                    else break;
                }
                ULONG_PTR start = (ULONG_PTR)(b + 1);
                if (start >= g_base && start < (ULONG_PTR)addr)
                    return start;
                return (ULONG_PTR)q;
            }
            if (q[0]==0x4C && q[1]==0x8B && q[2]==0xDC) {
                const BYTE* b = q - 1;
                while (b >= q - 40) {
                    if (*b==0x53||*b==0x55||*b==0x56||*b==0x57) { b--; }
                    else if (b>q-39 && b[0]==0x41 && b[1]>=0x54 && b[1]<=0x57) { b-=2; }
                    else break;
                }
                ULONG_PTR start = (ULONG_PTR)(b + 1);
                if (start >= g_base && start < (ULONG_PTR)addr)
                    return start;
                return (ULONG_PTR)q;
            }
        }
    } __except(1) {}
    return 0;
}

static void LogStack(FILE* f, ULONG_PTR* rsp, int mx)
{
    int found = 0;
    __try {
        for (int s = 0; s < 128 && found < mx; s++) {
            ULONG_PTR a = rsp[s];
            if (a >= g_base && a < g_end) {
                WaitForSingleObject(g_mtx, 800);
                fprintf(f, "  [RSP+%03d] +0x%llX\n", s*8, (unsigned long long)(a-g_base));
                fflush(f); ReleaseMutex(g_mtx);
                found++;
            }
        }
    } __except(1) {}
}

static void ArmRaw(ULONG_PTR a, const char* name, BpKind kind)
{
    if (g_c >= MAXBP || a < g_base || a >= g_end) return;
    for (int i = 0; i < g_c; i++) if (g_bp[i].addr == a) return;
    g_bp[g_c].addr  = a;
    g_bp[g_c].orig  = *(BYTE*)a;
    g_bp[g_c].kind  = kind;
    g_bp[g_c].armed = 1;
    strncpy_s(g_bp[g_c].name, sizeof(g_bp[g_c].name), name, _TRUNCATE);
    DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
    *(BYTE*)a = 0xCC;
    VirtualProtect((void*)a, 1, o, &o);
    const char* kn = kind==BP_PARENT?"PARENT":kind==BP_FNSTART?"FNSTART":
                     kind==BP_GUARD?"GUARD":"DIR";
    LOG("  BP [%s] +0x%llX  %s", kn, (unsigned long long)(a-g_base), name);
    g_c++;
}

static LONG NTAPI Veh(PEXCEPTION_POINTERS ep)
{
    DWORD c     = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR a = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (c == EXCEPTION_SINGLE_STEP) {
        if (g_rearm) {
            for (int i = 0; i < g_c; i++)
                if (g_bp[i].addr == (ULONG_PTR)g_rearm) {
                    DWORD o; VirtualProtect((void*)g_bp[i].addr, 1, PAGE_EXECUTE_READWRITE, &o);
                    *(BYTE*)g_bp[i].addr = 0xCC;
                    VirtualProtect((void*)g_bp[i].addr, 1, o, &o);
                    InterlockedExchange(&g_bp[i].armed, 1);
                    break;
                }
            g_rearm = NULL;
            ep->ContextRecord->EFlags &= ~0x100u;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (c != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    for (int i = 0; i < g_c; i++) {
        if (a != g_bp[i].addr) continue;
        if (!InterlockedCompareExchange(&g_bp[i].armed, 0, 1))
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
        *(BYTE*)a = g_bp[i].orig; VirtualProtect((void*)a, 1, o, &o);
        ep->ContextRecord->Rip = a;

        ULONG_PTR rcx = ep->ContextRecord->Rcx;
        ULONG_PTR rdx = ep->ContextRecord->Rdx;
        ULONG_PTR r8  = ep->ContextRecord->R8;
        ULONG_PTR r9  = ep->ContextRecord->R9;
        ULONG_PTR* rsp = (ULONG_PTR*)ep->ContextRecord->Rsp;

        switch (g_bp[i].kind) {

        case BP_DIRECTING: {
            int state = -999;
            __try { state = *(int*)(rcx+0x10); } __except(1){}
            LOG("[DIR] state=%d", state);
            break;
        }

        case BP_GUARD: {
            ULONG_PTR ret = rsp[0];
            ULONG_PTR ret_off = (ret>=g_base&&ret<g_end)?(ret-g_base):0;
            LOG("[GUARD] %s  ret=+0x%llX", g_bp[i].name, (unsigned long long)ret_off);

            if (g_fn_found == 0 && ret_off > 0) {
                ULONG_PTR fn_start = FindFuncStart(ret, 1024);
                if (fn_start) {
                    LOG("[SCAN] FnStart=+0x%llX", (unsigned long long)(fn_start-g_base));
                    g_fn_found = 1;
                    ArmRaw(fn_start, "FnStart", BP_FNSTART);
                }
            }
            break;
        }

        case BP_FNSTART: {
            LOG("[FNSTART] +0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
                (unsigned long long)(a-g_base),
                (unsigned long long)rcx, (unsigned long long)rdx,
                (unsigned long long)r8,  (unsigned long long)r9);

            // RSP[0] = return addr внутри родителя → ищем начало родителя
            if (g_fn_found == 1) {
                ULONG_PTR caller_ret = rsp[0];
                ULONG_PTR cr_off = (caller_ret>=g_base&&caller_ret<g_end)?(caller_ret-g_base):0;
                LOG("[SCAN] parent_ret=+0x%llX", (unsigned long long)cr_off);
                LOG2("=== FNSTART +0x%llX ===", (unsigned long long)(a-g_base));
                LOG2("  parent_ret=+0x%llX", (unsigned long long)cr_off);
                LOG2("--- stack ---"); LogStack(g_log2, rsp, 12); LOG2("---");

                ULONG_PTR par_start = FindFuncStart(caller_ret, 2048);
                if (par_start) {
                    LOG("[SCAN] ParentStart=+0x%llX (-%d от ret)",
                        (unsigned long long)(par_start-g_base), (int)(caller_ret-par_start));
                    g_fn_found = 2;
                    ArmRaw(par_start, "Parent", BP_PARENT);
                } else {
                    LOG("[SCAN] пролог родителя не найден — ставим BP на ret");
                    g_fn_found = 2;
                    ArmRaw(caller_ret, "ParentRet", BP_PARENT);
                }
            }
            break;
        }

        case BP_PARENT: {
            LOG("[PARENT] +0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
                (unsigned long long)(a-g_base),
                (unsigned long long)rcx, (unsigned long long)rdx,
                (unsigned long long)r8,  (unsigned long long)r9);
            LOG2("=== PARENT +0x%llX ===", (unsigned long long)(a-g_base));
            LOG2("  rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
                 (unsigned long long)rcx, (unsigned long long)rdx,
                 (unsigned long long)r8,  (unsigned long long)r9);
            LOG2("--- parent stack ---"); LogStack(g_log2, rsp, 12); LOG2("---");

            if (g_par_fn == 0) {
                g_par_fn   = a;
                g_par_this = rcx;
                g_par_p1   = rdx;
                g_par_p2   = r8;
                g_par_p3   = r9;
                LOG("*** PARENT ЗАХВАЧЕН fn=+0x%llX ***",
                    (unsigned long long)(a-g_base));
            }
            break;
        }

        }

        g_rearm = (void*)a;
        ep->ContextRecord->EFlags |= 0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void Arm(ULONG_PTR a, const char* name, BpKind kind)
{
    if (g_c >= MAXBP || a < g_base || a >= g_end) return;
    for (int i = 0; i < g_c; i++) if (g_bp[i].addr == a) return;
    g_bp[g_c].addr  = a;
    g_bp[g_c].orig  = *(BYTE*)a;
    g_bp[g_c].kind  = kind;
    g_bp[g_c].armed = 1;
    strncpy_s(g_bp[g_c].name, sizeof(g_bp[g_c].name), name, _TRUNCATE);
    DWORD o; VirtualProtect((void*)a, 1, PAGE_EXECUTE_READWRITE, &o);
    *(BYTE*)a = 0xCC; VirtualProtect((void*)a, 1, o, &o);
    const char* kn = kind==BP_PARENT?"PARENT":kind==BP_FNSTART?"FNSTART":
                     kind==BP_GUARD?"GUARD":"DIR";
    LOG("  BP [%s] +0x%llX  %s", kn, (unsigned long long)(a-g_base), name);
    g_c++;
}

typedef void* (*Fn_dg)(); typedef void** (*Fn_da)(void*,size_t*);
typedef void*  (*Fn_ai)(void*); typedef size_t (*Fn_nc)(void*);
typedef void*  (*Fn_ic)(void*,size_t); typedef const char* (*Fn_cn)(void*);
typedef void*  (*Fn_cm)(void*,void**); typedef const char* (*Fn_mn)(void*);
typedef uint32_t (*Fn_mp)(void*);

static LONG ExcFilter(PEXCEPTION_POINTERS ep, LONG n)
{
    ULONG_PTR ca = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
    LONG off = (ca>=g_base&&ca<g_end)?(LONG)(ca-g_base):-1;
    if (g_log&&g_mtx) {
        WaitForSingleObject(g_mtx,800);
        if (off>=0) fprintf(g_log,"  EXC #%ld code=0x%X crash=+0x%lX\n",n,
                        ep->ExceptionRecord->ExceptionCode,off);
        else        fprintf(g_log,"  EXC #%ld code=0x%X crash=0x%llX\n",n,
                        ep->ExceptionRecord->ExceptionCode,(unsigned long long)ca);
        fflush(g_log); ReleaseMutex(g_mtx);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI Repeater(LPVOID)
{
    while (g_par_fn == 0) Sleep(500);
    void* thr = NULL;
    if (p_ta && g_domain) thr = p_ta(g_domain);
    LOG("=== Repeater fn=+0x%llX ===",(unsigned long long)(g_par_fn-g_base));
    typedef ULONG_PTR (*Fn)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
    for (;;) {
        Sleep(16000);
        if (!g_par_fn) continue;
        LONG n = InterlockedIncrement(&g_auto);
        LOG("--- авто #%ld fn=+0x%llX ---",n,(unsigned long long)(g_par_fn-g_base));
        __try {
            ((Fn)g_par_fn)(g_par_this,g_par_p1,g_par_p2,g_par_p3);
            LOG("  OK #%ld",n);
        } __except(ExcFilter(GetExceptionInformation(),n)) {}
    }
    return 0;
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2500);
    g_mtx = CreateMutexA(NULL,FALSE,NULL);
    g_log = fopen(F_LOG,"w"); g_log2 = fopen(F_BOSS,"w");
    if (!g_log) return 0;

    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { LOG("нет GameAssembly"); return 0; }
    MODULEINFO mi={}; GetModuleInformation(GetCurrentProcess(),h,&mi,sizeof(mi));
    g_base=(ULONG_PTR)mi.lpBaseOfDll; g_end=g_base+mi.SizeOfImage;
    LOG("=== stagespy v9 === база 0x%llX",(unsigned long long)g_base);

    p_ta=(Fn_ta)GetProcAddress(h,"il2cpp_thread_attach");
    Fn_dg p_dg=(Fn_dg)GetProcAddress(h,"il2cpp_domain_get");
    Fn_da p_da=(Fn_da)GetProcAddress(h,"il2cpp_domain_get_assemblies");
    Fn_ai p_ai=(Fn_ai)GetProcAddress(h,"il2cpp_assembly_get_image");
    Fn_nc p_nc=(Fn_nc)GetProcAddress(h,"il2cpp_image_get_class_count");
    Fn_ic p_ic=(Fn_ic)GetProcAddress(h,"il2cpp_image_get_class");
    Fn_cn p_cn=(Fn_cn)GetProcAddress(h,"il2cpp_class_get_name");
    Fn_cm p_cm=(Fn_cm)GetProcAddress(h,"il2cpp_class_get_methods");
    Fn_mn p_mn=(Fn_mn)GetProcAddress(h,"il2cpp_method_get_name");
    Fn_mp p_mp=(Fn_mp)GetProcAddress(h,"il2cpp_method_get_param_count");
    if (!p_dg) { LOG("нет IL2CPP"); return 0; }

    AddVectoredExceptionHandler(1,Veh);
    void* dom=p_dg(); g_domain=dom;
    size_t na=0; void** asms=p_da(dom,&na);
    int n_dir=0, n_guard=0;

    for (size_t ai=0;ai<na;ai++) {
        void* img=p_ai(asms[ai]); if(!img) continue;
        size_t nc=p_nc(img);
        for (size_t ci=0;ci<nc;ci++) {
            void* cls=p_ic(img,ci); if(!cls) continue;
            const char* cn=p_cn(cls); if(!cn) continue;
            bool isDir   = strstr(cn,"DirectingStageClear")!=NULL;
            bool isGuard = strcmp(cn,"StageBoxRequestAbuseGuard")==0;
            if (!isDir&&!isGuard) continue;
            void* it=NULL;
            while (true) {
                void* m=p_cm(cls,&it); if(!m) break;
                const char* mn=p_mn(m); if(!mn||mn[0]=='.') continue;
                ULONG_PTR fp=(ULONG_PTR)(*(void**)m);
                if (fp<g_base||fp>=g_end) continue;
                uint32_t pc=p_mp?p_mp(m):0;
                char nm[96];
                if (isDir) {
                    if (strcmp(mn,"MoveNext")!=0) continue;
                    sprintf_s(nm,"Dir::MoveNext");
                    Arm(fp,nm,BP_DIRECTING); n_dir++;
                } else {
                    if (pc==0) continue;
                    sprintf_s(nm,"Guard::%s(p=%u)",mn,pc);
                    Arm(fp,nm,BP_GUARD); n_guard++;
                }
            }
        }
    }

    LOG("=== вооружено: %d Dir + %d Guard ===",n_dir,n_guard);
    LOG("=== убей боса x2 → Parent захвачен → авто-фарм ===");

    CreateThread(NULL,0,Repeater,NULL,0,NULL);

    for (int t=0;t<7200;t++) {
        Sleep(1000);
        if (t%60==59) LOG("-- %d мин -- авто: %ld",(t+1)/60,(long)g_auto);
    }
    fclose(g_log); g_log=NULL;
    if (g_log2) { fclose(g_log2); g_log2=NULL; }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h,DWORD r,LPVOID)
{
    if (r==DLL_PROCESS_ATTACH){ DisableThreadLibraryCalls(h); CreateThread(NULL,0,Worker,NULL,0,NULL); }
    return TRUE;
}
