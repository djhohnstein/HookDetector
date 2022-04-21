#include "MemoryModule.hpp"

vector<PLDR_DATA_TABLE_ENTRY> GetLoadedModules()
{
    _PPEB myPEB = reinterpret_cast<_PPEB>(__readgsqword(0x60));
    vector<PLDR_DATA_TABLE_ENTRY> results;
    LIST_ENTRY* ldrLink = myPEB->pLdr->InMemoryOrderModuleList.Flink;
    do
    {
        results.push_back(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldrLink));
        wcout << wstring(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldrLink)->FullDllName.pBuffer) << endl;
        ldrLink = reinterpret_cast<LIST_ENTRY*>(DEREF(reinterpret_cast<ULONG_PTR>(ldrLink)));
    } while (ldrLink != myPEB->pLdr->InMemoryOrderModuleList.Flink);
    return results;
}

BOOL ParseLdrDataTableEntry(PLDR_DATA_TABLE_ENTRY entry, PE& result)
{
    vector<unsigned char> dllBytes;
    for (int i = 0; i < entry->SizeOfImage; i++)
    {
        dllBytes.push_back(reinterpret_cast<unsigned char*>(entry->DllBase)[i]);
    }

    if (ParsePE(dllBytes, reinterpret_cast<ULONG_PTR>(entry->DllBase), result))
    {
        wstring baseName(entry->BaseDllName.pBuffer);
        result.Name = string(baseName.begin(), baseName.end());
        return TRUE;
    }
    return FALSE;
}