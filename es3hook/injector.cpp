// injector.cpp - injects es3hook.dll into running game process
// Usage: injector.exe <PID> <path_to_dll>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: injector.exe <PID> [dll_path]\n");
        printf("       injector.exe TaskbarHero (by name)\n");
        return 1;
    }

    // Determine PID
    DWORD pid = 0;
    if (isdigit(argv[1][0])) {
        pid = (DWORD)atoi(argv[1]);
    } else {
        // Find by process name
        char* procName = argv[1];
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (_strnicmp(pe.szExeFile, procName, strlen(procName)) == 0) {
                    pid = pe.th32ProcessID;
                    printf("[+] Found process '%s' PID=%lu\n", pe.szExeFile, pid);
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (!pid) { printf("[-] Process not found\n"); return 1; }

    // Get DLL path
    char dllPath[MAX_PATH];
    if (argc >= 3) {
        strcpy_s(dllPath, argv[2]);
    } else {
        GetModuleFileNameA(NULL, dllPath, MAX_PATH);
        char* last = strrchr(dllPath, '\\');
        if (last) strcpy_s(last+1, MAX_PATH - (last-dllPath) - 1, "es3hook.dll");
        else strcpy_s(dllPath, "es3hook.dll");
    }

    printf("[*] Injecting '%s' into PID %lu\n", dllPath, pid);

    // Get full path
    char fullPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);
    printf("[*] Full DLL path: %s\n", fullPath);

    // Open process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // Allocate memory in target process
    SIZE_T pathLen = strlen(fullPath) + 1;
    LPVOID remMem = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!remMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    // Write DLL path to remote process
    if (!WriteProcessMemory(hProc, remMem, fullPath, pathLen, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Get LoadLibraryA address
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    printf("[*] LoadLibraryA at 0x%p\n", loadLib);

    // Create remote thread calling LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remMem, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    printf("[*] Waiting for injection to complete...\n");
    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] LoadLibrary returned 0x%lX %s\n", exitCode, exitCode ? "(success)" : "(FAILED - NULL)");

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode) {
        printf("[+] DLL injected! Check C:\\ES3_PASSWORD.txt for results\n");
        printf("    Trigger ES3 save by playing the game or opening a chest.\n");
        printf("    The game auto-saves every ~3 minutes.\n");
    }
    return exitCode ? 0 : 1;
}
