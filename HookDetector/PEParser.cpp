#include "PEParser.hpp"
#include <iostream>
DWORD GetFunctionCodeOffset(string functionName, PE data)
{
    for (ExportDirectoryFunction& function : data.ExportDirectory.ExportedFunctions)
    {
        if (function.Name.compare(functionName) == 0)
        {
            return (data.Base + function.FunctionRVA - data.TextSection.VirtualAddress + data.TextSection.RawAddress);
        }
    }
    return -1;
}

BOOL ParsePE(vector<unsigned char> dllBytes, ULONG_PTR dllBase, PE& result)
{
    result.Base = dllBase;
    DWORD initialOffset = 0x3c; // This is Dos Header -> e_lfanew
    // Tells us where the PE Signature starts
    DWORD peHeaderOffset = (dllBytes[initialOffset + 2] << 16) | (dllBytes[initialOffset + 1] << 8) | dllBytes[initialOffset];
    // Signature is a 4 byte value (DWORD), so increment to get Machine type value
    DWORD machineTypeOffset = peHeaderOffset + 4;
    // Machine value is a WORD, so increment by 2 to get No. of Sections
    DWORD noOfSectionsOffset = machineTypeOffset + 0x2;
    // Read values in from noOfSectionsOffset to get number of sections
    DWORD noOfSections = (dllBytes[noOfSectionsOffset + 1] << 8) | (dllBytes[noOfSectionsOffset]);
    // noOfSections is a WORD, so increment by 2
    DWORD timeDateStampOffset = noOfSectionsOffset + 0x2;
    // We skip over PointerToSymbolTable and NumberOfSymbols headers as deprecated,
    // so 0x4 x 3 (as +0x4 -> PointerToSymbolTable, +0x4 + 0x4 -> NumberOfSymbols)
    DWORD sizeOfOptionalHeaderOffset = timeDateStampOffset + 0x4 + 0x4 + 0x4;
    // Read WORD in from sizeOfOptionalHeaderOffset
    DWORD sizeOfOptionalHeader = (dllBytes[sizeOfOptionalHeaderOffset + 1] << 8) | (dllBytes[sizeOfOptionalHeaderOffset]);

    // Characteristics is at sizeOfOptionalHeaderOffset + 0x2, value of of Characteristics
    // is a WORD so increment by another 2, now at beginning of optional headers
    DWORD optionalHeaderOffset = sizeOfOptionalHeaderOffset + 0x2 + 0x2;
    DWORD dwMagic = dllBytes[optionalHeaderOffset + 1] << 8 | dllBytes[optionalHeaderOffset];

    // This changes based on x86 or x64, see:
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
    DWORD dwExportDirectoryRVAOffset;
    if (dwMagic == 0x10b)
    {
        result.Magic = MAGIC_X86;
        dwExportDirectoryRVAOffset = optionalHeaderOffset + 96;
    }
    else if (dwMagic == 0x20b)
    {
        result.Magic = MAGIC_X64;
        dwExportDirectoryRVAOffset = optionalHeaderOffset + 112;
    }
    else
    {
        return FALSE;
    }

    DWORD dwExportDirectoryRVA = ReadDWORD(dllBytes, dwExportDirectoryRVAOffset);

    DWORD firstSectionHeaderOffset = optionalHeaderOffset + sizeOfOptionalHeader;
    vector<SectionHeader> sectionHeaders = GetSectionHeaders(dllBytes, firstSectionHeaderOffset, noOfSections);
    SectionHeader textSection;
    for (SectionHeader& header : sectionHeaders)
    {
        if (header.Name.compare(".text") == 0)
        {
            result.TextSection = header;
            break;
        }
    }
    ExportDirectory edData;
    for (auto& section : sectionHeaders)
    {
        if ((section.RawSize + section.VirtualAddress) >= dwExportDirectoryRVA &&
            section.VirtualAddress <= dwExportDirectoryRVA)
        {
            DWORD dwExportDirectoryOffset = dwExportDirectoryRVA - section.VirtualAddress + section.RawAddress;
            edData = ParseExportDirectory(dllBytes, dwExportDirectoryOffset, section);
            break;
        }
    }
    result.ExportDirectory = edData;
    result.SectionHeaders = sectionHeaders;
    return TRUE;
}