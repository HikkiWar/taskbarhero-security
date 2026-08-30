// dumpdata.cpp — спросить у IL2CPP раскладку таблиц описаний предметов.
//
// Ранжировать вещи по цифрам ключа — гадание, а имена в подсказке игра
// собирает на лету, поэтому статической записи «имя -> урон» в памяти нет.
// Зато есть классы с говорящими именами: GearInfoData, GradeInfoData,
// ItemLevelScaleInfoData. Обфускатор трогает методы, а имена ПОЛЕЙ и КЛАССОВ
// остаются — значит можно просто спросить смещения у среды выполнения.
//
// Выгружаем: указатель на класс, имя и смещение каждого поля, его тип.
// Дальше скан по указателю класса найдёт все строки таблицы уже из Python.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")

#define F_OUT "C:\\Users\\Gigabyte\\Desktop\\THB\\es3hook\\datalayout.txt"

typedef void*       (*Fn_domain_get)();
typedef void**      (*Fn_domain_get_assemblies)(void*, size_t*);
typedef void*       (*Fn_assembly_get_image)(void*);
typedef void*       (*Fn_class_from_name)(void*, const char*, const char*);
typedef const char* (*Fn_class_get_name)(void*);
typedef const char* (*Fn_class_get_namespace)(void*);
typedef void*       (*Fn_class_get_fields)(void*, void**);
typedef const char* (*Fn_field_get_name)(void*);
typedef size_t      (*Fn_field_get_offset)(void*);
typedef void*       (*Fn_field_get_type)(void*);
typedef char*       (*Fn_type_get_name)(void*);
typedef int         (*Fn_type_get_type)(void*);
typedef size_t      (*Fn_image_get_class_count)(void*);
typedef void*       (*Fn_image_get_class)(void*, size_t);
typedef int         (*Fn_class_get_flags)(void*);
typedef uint32_t    (*Fn_class_instance_size)(void*);
typedef void        (*Fn_field_static_get_value)(void*, void*);

static Fn_domain_get            p_domain_get;
static Fn_domain_get_assemblies p_domain_get_assemblies;
static Fn_assembly_get_image    p_assembly_get_image;
static Fn_class_from_name       p_class_from_name;
static Fn_class_get_name        p_class_get_name;
static Fn_class_get_namespace   p_class_get_namespace;
static Fn_class_get_fields      p_class_get_fields;
static Fn_field_get_name        p_field_get_name;
static Fn_field_get_offset      p_field_get_offset;
static Fn_field_get_type        p_field_get_type;
static Fn_type_get_name         p_type_get_name;
static Fn_image_get_class_count p_image_get_class_count;
static Fn_image_get_class       p_image_get_class;
static Fn_class_instance_size   p_class_instance_size;
static Fn_field_static_get_value p_field_static_get_value;

static FILE* g_f;
#define WR(f_, ...) do { fprintf(g_f, f_ "\n", ##__VA_ARGS__); fflush(g_f); } while (0)

// что нас интересует: описания снаряжения и множители
static const char* WANTED[] = {
    "GearInfoData", "GearTypeInfoData", "GearTypeScaleInfoData",
    "ItemInfoData", "ItemLevelScaleInfoData", "ItemTypeScaleInfoData",
    "GradeInfoData", "ItemGroupInfoData", "MaterialInfoData",
    "UniqueModInfoData", "StatModInfoData", "HeroInfoData",
};

// перечисления: имена рангов, слотов, типов статов
static const char* ENUMS[] = {
    "StatType", "MODTYPE", "EGearType", "EGradeType", "EItemParts",
    "EItemType", "EEquipClassType", "EGearGroup", "EMaterialType",
};

static void DumpEnum(void* cls)
{
    const char* ns = p_class_get_namespace(cls);
    const char* cn = p_class_get_name(cls);
    WR("");
    WR("=== ENUM %s.%s ===", ns ? ns : "", cn ? cn : "?");
    void* it = NULL;
    while (true) {
        void* fl = p_class_get_fields(cls, &it);
        if (!fl) break;
        const char* fn = p_field_get_name(fl);
        if (!fn || strcmp(fn, "value__") == 0) continue;
        int v = -1;
        if (p_field_static_get_value) p_field_static_get_value(fl, &v);
        WR("    %-4d %s", v, fn);
    }
}

static void DumpClass(void* cls)
{
    const char* ns = p_class_get_namespace(cls);
    const char* cn = p_class_get_name(cls);
    uint32_t isz = p_class_instance_size ? p_class_instance_size(cls) : 0;
    WR("");
    WR("=== %s.%s ===", ns ? ns : "", cn ? cn : "?");
    WR("    klass = 0x%llX   размер объекта = 0x%X", (unsigned long long)cls, isz);
    void* it = NULL;
    int n = 0;
    while (true) {
        void* fl = p_class_get_fields(cls, &it);
        if (!fl) break;
        const char* fn = p_field_get_name(fl);
        size_t off = p_field_get_offset(fl);
        void* ty = p_field_get_type(fl);
        char* tn = ty && p_type_get_name ? p_type_get_name(ty) : NULL;
        WR("    +0x%03zX  %-34s %s", off, fn ? fn : "?", tn ? tn : "?");
        n++;
    }
    WR("    полей: %d", n);
}

static DWORD WINAPI Worker(LPVOID)
{
    Sleep(2000);
    g_f = fopen(F_OUT, "w");
    if (!g_f) return 0;

    HMODULE h = GetModuleHandleA("GameAssembly.dll");
    if (!h) { WR("нет GameAssembly"); fclose(g_f); return 0; }
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    WR("=== раскладка таблиц описаний ===");
    WR("база GameAssembly.dll = 0x%llX", (unsigned long long)mi.lpBaseOfDll);

#define GP(f) p_##f = (Fn_##f)GetProcAddress(h, "il2cpp_" #f)
    GP(domain_get); GP(domain_get_assemblies); GP(assembly_get_image);
    GP(class_from_name); GP(class_get_name); GP(class_get_namespace);
    GP(class_get_fields); GP(field_get_name); GP(field_get_offset);
    GP(field_get_type); GP(type_get_name);
    GP(image_get_class_count); GP(image_get_class);
    GP(class_instance_size); GP(field_static_get_value);
#undef GP
    if (!p_domain_get || !p_class_get_fields) {
        WR("нужных экспортов нет"); fclose(g_f); return 0;
    }

    void* domain = p_domain_get();
    size_t nasm = 0;
    void** asms = p_domain_get_assemblies(domain, &nasm);
    int done = 0;

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
            DumpClass(cls); done++;
        }
    }
    WR("");
    WR("=== выгружено классов: %d ===", done);
    fclose(g_f);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, Worker, NULL, 0, NULL); }
    return TRUE;
}
