// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <format>

unsigned char trampoline[13] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov rax, jmpAddress
    0xFF, 0xE0, 0x90                                                    // jmp rax
};

HMODULE HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    MessageBoxA(NULL, std::format("Nice try getting {}", lpProcName).c_str(), lpProcName, MB_ICONHAND);
    return NULL;
}

VOID Hook() {
    HMODULE hk32dll = GetModuleHandleA("kernel32.dll");
    FARPROC pGetProcAddress = GetProcAddress(hk32dll, "GetProcAddress");

    VOID* jmpAddress = (VOID*)HookedGetProcAddress;
    memcpy(&trampoline[2], &jmpAddress, sizeof(jmpAddress));
    WriteProcessMemory((HANDLE)-1, pGetProcAddress, &trampoline, sizeof(trampoline), 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Hook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

