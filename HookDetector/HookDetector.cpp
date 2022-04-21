// HookDetector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "PEParser.hpp"
#include "Helpers.hpp"
#include "MemoryModule.hpp"
#include <algorithm>
#include <iostream>
#include <string>


bool iequals(const string& a, const string& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

bool wiequals(const wstring& a, const wstring& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

BOOL IsFunctionHooked(string dllPath, string functionName)
{
    vector<unsigned char> vDll;
    PE peDll;
    if (ReadFile(dllPath, vDll) != 0)
    {
        return FALSE;
    }
    if (!ParsePE(vDll, 0, peDll))
    {
        return FALSE;
    }
    auto res = GetLoadedModules();
    wstring wsDllPath(dllPath.begin(), dllPath.end());
    wstring wsFuncName(functionName.begin(), functionName.end());
    for (auto& mod : res)
    {
        if (wiequals(wstring(mod->FullDllName.pBuffer), wsDllPath))
        {
            PE memDll;
            if (ParseLdrDataTableEntry(mod, memDll))
            {
                for (auto& func : memDll.ExportDirectory.ExportedFunctions)
                {
                    if (wiequals(wstring(func.Name.begin(), func.Name.end()), wsFuncName))
                    {
                        unsigned char* inMemFuncAddr = reinterpret_cast<unsigned char*>(memDll.Base + func.FunctionRVA);
                        ULONG_PTR funcOffset = GetFunctionCodeOffset(functionName, peDll);
                        for (int i = 0; i < 13; i++)
                        {
                            if (inMemFuncAddr[i] != vDll[funcOffset + i])
                            {
                                // something fishy is going on
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}

int main()
{
    LoadLibrary(L"GetProcAddressHook.dll");
    if (IsFunctionHooked("C:\\Windows\\System32\\kernel32.dll", "GetProcAddress"))
    {
        std::cout << "GetProcAddress is hooked!" << std::endl;
    }
    else
    {
        std::cout << "GetProcAddress is clean!" << std::endl;
    }
    //vector<unsigned char> vK32;
    //PE peK32;
    //if (ReadFile("C:\\Windows\\System32\\kernel32.dll", vK32) == 0)
    //{
    //    if (ParsePE(vK32, 0, peK32))
    //    {
    //        std::cout << "Parsed K32" << std::endl;
    //    }
    //}
    //vector<unsigned char> vBoxit;
    //PE peBoxit;
    //if (ReadFile("C:\\Users\\User\\Downloads\\boxreflect.dll", vBoxit) == 0)
    //{
    //    if (ParsePE(vBoxit, 0, peBoxit))
    //    {
    //        std::cout << "Parsed Boxit" << std::endl;
    //    }
    //}
    //auto res = GetLoadedModules();
    //for (auto& mod : res)
    //{
    //    if (wstring(mod->BaseDllName.pBuffer).compare(L"KERNEL32.DLL") == 0)
    //    {
    //        PE memK32;
    //        if (ParseLdrDataTableEntry(mod, memK32))
    //        {
    //            HMODULE hK32 = GetModuleHandle(L"kernel32.dll");
    //            unsigned char* pGetProcAddress = (unsigned char*)GetProcAddress(hK32, "GetProcAddress");
    //            for (auto& func : memK32.ExportDirectory.ExportedFunctions)
    //            {
    //                if (func.Name.compare("GetProcAddress") == 0)
    //                {
    //                    ULONG_PTR funcOffset = GetFunctionCodeOffset("GetProcAddress", peK32);
    //                    for (int i = 0; i < 13; i++)
    //                    {
    //                        if (inMemGetProcAddress[i] != vK32[funcOffset + i])
    //                        {
    //                            // something fishy is going on
    //                        }
    //                    }

    //                    break;
    //                }
    //            }
    //        }
    //    }
    //}
    //std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
