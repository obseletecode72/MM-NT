#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "injector.h"

using namespace std;

DWORD GetCurrentProcessIdFromTEB() {
#ifdef _M_X64
    return (DWORD)__readgsqword(0x40); // UniqueProcessId
#else
    return (DWORD)__readfsdword(0x20); // UniqueProcessId
#endif
}

int main() {
    ntdll_base = GetModuleHandleW(skCrypt(L"ntdll.dll"));
    if (!ntdll_base) {
        return -1;
    }
    kernel32_base = GetModuleHandleW(skCrypt(L"kernel32.dll"));
    if (!kernel32_base) {
        return -1;
    }

    pfnNtOpenProcess NtOpenProcess = (pfnNtOpenProcess)GetProcAddress(ntdll_base, skCrypt("NtOpenProcess"));
    pfnNtClose NtClose = (pfnNtClose)GetProcAddress(ntdll_base, skCrypt("NtClose"));
    NtDelayExecution_t NtDelayExecution = (NtDelayExecution_t)GetProcAddress(ntdll_base, skCrypt("NtDelayExecution"));

    LARGE_INTEGER interval;
    interval.QuadPart = -100000; // 10ms ?

    if (!NtOpenProcess || !NtClose) {
        return -1;
    }

    DWORD currentProcessId = GetCurrentProcessIdFromTEB();

    HANDLE hProc = NULL;
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)currentProcessId;
    clientId.UniqueThread = 0;

    NTSTATUS status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return -2;
    }

    if (!ManualMapDll2(hProc, dll_bytes.data(), dll_bytes.size())) {
        if(!NT_SUCCESS(NtClose(hProc)))
            return -8;

        return -8;
    }

    if (!NT_SUCCESS(NtClose(hProc)))
        return -1;

    system(skCrypt("pause"));

    return 0;
}
