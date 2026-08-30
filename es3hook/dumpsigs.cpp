// dumpsigs.cpp — выгрузить сигнатуры методов игры.
//
// Имена методов обфусцированы, а вот ТИПЫ — нет. Значит метод можно опознать
// по возвращаемому значению: ETryEquipGearResult возвращает почти наверняка
// один-единственный метод во всей игре, и его класс и есть владелец
// экипировки. Тем же приёмом ищется всё остальное.
//
// Пишем: класс, адрес, возвращаемый тип, типы параметров.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define F_OUT "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\signatures.txt"

typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef const char* (*Fn_class_get_name)(void*);
typedef const char* (*Fn_class_get_namespace)(void*);
typedef void*       (*Fn_class_get_methods)(void*, void**);
typedef const char* (*Fn_method_get_name)(void*);
typedef void*       (*Fn_method_get_return_type)(void*);
typedef uint32_t    (*Fn_method_get_param_count)(void*);
typedef void*       (*Fn_method_get_param)(void*, uint32_t);
typedef const char* (*Fn_method_get_param_name)(void*, uint32_t);
typedef char*       (*Fn_type_get_name)(void*);
typedef size_t      (*Fn_image_get_class_count)(void*);
typedef void*       (*Fn_image_get_class)(void*, size_t);

static Fn_domain_get            p_domain_get;
static Fn_domain_get_assemblies p_domain_get_assemblies;
static Fn_assembly_get_image    p_assembly_get_image;
static Fn_class_get_name        p_class_get_name;
static Fn_class_get_namespace   p_class_get_namespace;
static Fn_class_get_methods     p_class_get_methods;
static Fn_method_get_name       p_method_get_name;
static Fn_method_get_return_type p_method_get_return_type;
static Fn_method_get_param_count p_method_get_param_count;
static Fn_method_get_param      p_method_get_param;
static Fn_type_get_name         p_type_get_name;
static Fn_image_get_class_count p_image_get_class_count;
static Fn_image_get_class       p_image_get_class;

static FILE* g_f;
#define WR(f_, ...) do { fprintf(g_f, f_ "\n", ##__VA_ARGS__); fflush(g_f); } while (0)

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2000);
    g_f = fopen(F_OUT, "w");
    if (!g_f) return 0;
    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { WR("нет GameAssembly"); fclose(g_f); return 0; }
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
    WR("база GameAssembly.dll = 0x%llX", (unsigned long long)base);

#define GP(f) p_##f = (Fn_##f)GetProcAddress(h, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(class_get_name); GP(class_get_namespace); GP(class_get_methods);
    GP(method_get_name); GP(method_get_return_type);
    GP(method_get_param_count); GP(method_get_param);
    GP(type_get_name); GP(image_get_class_count); GP(image_get_class);
#undef GP
    if (!p_domain_get || !p_method_get_return_type) {
        WR("нужных экспортов нет"); fclose(g_f); return 0;
    }

    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);
    int n = 0;

    for (size_t a = 0; a < nasm; a++) {
        void* img = p_assembly_get_image(asms[a]);
        if (!img) continue;
        size_t nc = p_image_get_class_count(img);
        for (size_t c = 0; c < nc; c++) {
            void* cls = p_image_get_class(img, c);
            if (!cls) continue;
            const char* ns = p_class_get_namespace(cls);
            const char* cn = p_class_get_name(cls);
            if (!cn || !ns || !strstr(ns, "TaskbarHero")) continue;

            void* it = NULL;
            while (true) {
                void* m = p_class_get_methods(cls, &it);
                if (!m) break;
                const char* mn = p_method_get_name(m);
                void* fn = *(void**)m;
                void* rt = p_method_get_return_type(m);
                char* rn = rt ? p_type_get_name(rt) : NULL;
                char args[512];
                args[0] = 0;
                uint32_t np = p_method_get_param_count(m);
                for (uint32_t i = 0; i < np && i < 8; i++) {
                    void* pt = p_method_get_param(m, i);
                    char* pn = pt ? p_type_get_name(pt) : NULL;
                    if (i) strncat_s(args, sizeof(args), ", ", _TRUNCATE);
                    strncat_s(args, sizeof(args), pn ? pn : "?", _TRUNCATE);
                }
                ULONG_PTR fa = (ULONG_PTR)fn;
                WR("%s.%s\t%s\t%s\t%s\t%s",
                   ns, cn, mn ? mn : "?",
                   fa >= base && fa < base + mi.SizeOfImage ? "код" : "нет",
                   rn ? rn : "?", args);
                n++;
            }
        }
    }
    WR("");
    WR("=== методов: %d ===", n);
    fclose(g_f);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, Worker, NULL, 0, NULL); }
    return TRUE;
}
