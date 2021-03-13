#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

//gcc -m64 -c MonoInjector.cpp
//gcc -m64 -shared -o MonoInjector.dll -Wl,--out-implib,libtstdll.a MonoInjector.o
typedef void *(__cdecl *MONO_GET_ROOT_DOMAIN)(void);
typedef void *(__cdecl *MONO_THREAD_ATTACH)(void *domain);
typedef void(__cdecl *MONO_THREAD_DETACH)(void *monothread);

typedef void *(__cdecl *MONO_COMPILE_METHOD)(void *method);
typedef void *(__cdecl *MONO_METHOD_GET_CLASS)(void *method);
typedef void *(__cdecl *MONO_RUNTIME_INVOKE)(void *method, void *obj, void **params, void **exc);
typedef void *(__cdecl *MONO_CLASS_FROM_NAME)(void *image, char *name_space, char *name);
typedef void *(__cdecl *MONO_CLASS_GET_METHOD_FROM_NAME)(void *klass, char *methodname, int paramcount); //paramcount=-1

typedef void *(__cdecl *MONO_DOMAIN_ASSEMBLY_OPEN)(void *domain, char *name);
typedef void *(__cdecl *MONO_ASSEMBLY_GET_IMAGE)(void *assembly);
typedef void *(__cdecl *MONO_DOMAIN_GET)();


HMODULE hMono = GetModuleHandle("mono.dll");
MONO_GET_ROOT_DOMAIN mono_get_root_domain = (MONO_GET_ROOT_DOMAIN)GetProcAddress(hMono, "mono_get_root_domain");
MONO_THREAD_ATTACH mono_thread_attach = (MONO_THREAD_ATTACH)GetProcAddress(hMono, "mono_thread_attach");
MONO_THREAD_DETACH mono_thread_detach = (MONO_THREAD_DETACH)GetProcAddress(hMono, "mono_thread_detach");

MONO_COMPILE_METHOD mono_compile_method = (MONO_COMPILE_METHOD)GetProcAddress(hMono, "mono_compile_method");
MONO_CLASS_FROM_NAME mono_class_from_name = (MONO_CLASS_FROM_NAME)GetProcAddress(hMono, "mono_class_from_name");
MONO_CLASS_GET_METHOD_FROM_NAME mono_class_get_method_from_name = (MONO_CLASS_GET_METHOD_FROM_NAME)GetProcAddress(hMono, "mono_class_get_method_from_name");

MONO_DOMAIN_ASSEMBLY_OPEN mono_domain_assembly_open = (MONO_DOMAIN_ASSEMBLY_OPEN)GetProcAddress(hMono, "mono_domain_assembly_open");
MONO_ASSEMBLY_GET_IMAGE mono_assembly_get_image = (MONO_ASSEMBLY_GET_IMAGE)GetProcAddress(hMono, "mono_assembly_get_image");
MONO_DOMAIN_GET mono_domain_get = (MONO_DOMAIN_GET)GetProcAddress(hMono, "mono_domain_get");



struct monoParams
{
    char *filePath;
    char *klassname;
    char *methodname;
};

extern "C" __declspec(dllexport) int do_mono_compile_method(int method)
{
    void *mono_selfthread = mono_thread_attach(mono_get_root_domain());
    int addr = (intptr_t)mono_compile_method((void *)method);
    mono_thread_detach(mono_selfthread);
    return addr;
}

extern "C" __declspec(dllexport) int do_mono_class_get_method_from_name(monoParams *p)
{
    char* filePath = (*p).filePath;
    char* name_space = (char *)"";

    void *mono_selfthread = mono_thread_attach(mono_get_root_domain());
    void *image = mono_assembly_get_image(mono_domain_assembly_open(mono_domain_get(), filePath));
    void *klass = mono_class_from_name(image, name_space, (*p).klassname);
    int method = (intptr_t)mono_class_get_method_from_name(klass, (*p).methodname, -1);
    mono_thread_detach(mono_selfthread);
    return method;
}

extern "C" __declspec(dllexport) int do_test(monoParams *p)
{
    //char klassStr[1024];
    //sprintf(klassStr, "%d", klass);
    MessageBoxA(0, (*p).klassname, "klass", MB_OK);
    MessageBoxA(0, (*p).methodname, "methodname", MB_OK);
    return 0;
}
