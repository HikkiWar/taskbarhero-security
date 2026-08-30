// dumpstatic.cpp — найти живые синглтоны игры через статические поля.
//
// Копий PlayerSaveData и HeroSaveData в памяти десятки: каждое сохранение
// оставляет снимок. Отличить живой объект по содержимому нельзя — они
// одинаковые. Но живой на кого-то ссылается, а поля типа PlayerSaveData
// ни в одном классе не нашлось, значит ссылка в СТАТИКЕ.
//
// Выгружаем все статические поля классов игры вместе с текущими значениями.
// Указатель на живой PlayerSaveData окажется среди них.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define F_OUT "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\statics.txt"
#define FIELD_STATIC 0x0010

typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef const char* (*Fn_class_get_name)(void*);
typedef const char* (*Fn_class_get_namespace)(void*);
typedef void*       (*Fn_class_get_fields)(void*, void**);
typedef const char* (*Fn_field_get_name)(void*);
typedef void*       (*Fn_field_get_type)(void*);
typedef char*       (*Fn_type_get_name)(void*);
typedef int         (*Fn_field_get_flags)(void*);
typedef void        (*Fn_field_static_get_value)(void*, void*);
typedef size_t      (*Fn_image_get_class_count)(void*);
typedef void*       (*Fn_image_get_class)(void*, size_t);

static Fn_domain_get             p_domain_get;
static Fn_domain_get_assemblies  p_domain_get_assemblies;
static Fn_assembly_get_image     p_assembly_get_image;
static Fn_class_get_name         p_class_get_name;
static Fn_class_get_namespace    p_class_get_namespace;
static Fn_class_get_fields       p_class_get_fields;
static Fn_field_get_name         p_field_get_name;
static Fn_field_get_type         p_field_get_type;
static Fn_type_get_name          p_type_get_name;
static Fn_field_get_flags        p_field_get_flags;
static Fn_field_static_get_value p_field_static_get_value;
static Fn_image_get_class_count  p_image_get_class_count;
static Fn_image_get_class        p_image_get_class;

static FILE* g_f;
#define WR(f_, ...) do { fprintf(g_f, f_ "\n", ##__VA_ARGS__); fflush(g_f); } while (0)

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2000);
    g_f = fopen(F_OUT, "w");
    if (!g_f) return 0;
    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { WR("нет GameAssembly"); fclose(g_f); return 0; }

#define GP(f) p_##f = (Fn_##f)GetProcAddress(h, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(class_get_name); GP(class_get_namespace); GP(class_get_fields);
    GP(field_get_name); GP(field_get_type); GP(type_get_name);
    GP(field_get_flags); GP(field_static_get_value);
    GP(image_get_class_count); GP(image_get_class);
#undef GP
    if (!p_domain_get || !p_field_static_get_value) {
        WR("нужных экспортов нет"); fclose(g_f); return 0;
    }

    WR("=== статические поля классов игры ===");
    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);
    int total = 0;

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
            bool head = false;
            while (true) {
                void* fl = p_class_get_fields(cls, &it);
                if (!fl) break;
                if (!(p_field_get_flags(fl) & FIELD_STATIC)) continue;
                const char* fn = p_field_get_name(fl);
                void* ty = p_field_get_type(fl);
                char* tn = ty ? p_type_get_name(ty) : NULL;
                // интересуют только ссылки на объекты
                if (!tn || strchr(tn, '.') == NULL) continue;
                void* val = NULL;
                __try { p_field_static_get_value(fl, &val); }
                __except (1) { continue; }
                if ((ULONG_PTR)val < 0x10000) continue;
                if (!head) { WR(""); WR("--- %s.%s ---", ns, cn); head = true; }
                WR("    %-36s = 0x%llX   %s",
                   fn ? fn : "?", (unsigned long long)val, tn);
                total++;
            }
        }
    }
    WR("");
    WR("=== ненулевых статических ссылок: %d ===", total);
    fclose(g_f);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, Worker, NULL, 0, NULL); }
    return TRUE;
}
