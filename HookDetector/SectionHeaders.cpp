#include "SectionHeaders.hpp"

#define DWORD unsigned long

vector<SectionHeader> GetSectionHeaders(vector<unsigned char> rdll, unsigned long firstHeaderOffset, unsigned short numberOfHeaders)
{
    vector<SectionHeader> headers;

    DWORD nextSectionHeaderOffset = firstHeaderOffset;
    for (int i = 0; i < numberOfHeaders; i++) {
        SectionHeader section;
        // The header name is at the nextSectionHeaderOffset
        section.Name = string(reinterpret_cast<char*>(&rdll[nextSectionHeaderOffset]));
        // Since the above is an 8-byte value, skip ahead 8 to get the Virtual Size offset
        DWORD virtualSizeOffset = nextSectionHeaderOffset + 0x8;
        // Virtual Size is a DWORD, so skip 4
        DWORD virtualAddressOffset = virtualSizeOffset + 0x4;
        // Virtual Address is a DWORD, so skip 4
        DWORD rawSizeOffset = virtualAddressOffset + 0x4;
        // RawDataOffset is a DWORD, skip 4
        DWORD rawAddressOffset = rawSizeOffset + 0x4;
        DWORD relocAddressOffset = rawAddressOffset + 0x4;
        DWORD lineNumbersOffset = relocAddressOffset + 0x4;
        DWORD relocationsNumberOffset = lineNumbersOffset + 0x4;
        DWORD lineNumbersNumberOffset = relocationsNumberOffset + 0x2;
        DWORD characteristicsOffset = lineNumbersNumberOffset + 0x2;

        section.VirtualAddress = ReadDWORD(rdll, virtualAddressOffset);
        section.VirtualSize = ReadDWORD(rdll, virtualSizeOffset);
        section.RawSize = ReadDWORD(rdll, rawSizeOffset);
        section.RawAddress = ReadDWORD(rdll, rawAddressOffset);
        section.RelocAddress = ReadDWORD(rdll, relocAddressOffset);
        section.Linenumbers = ReadDWORD(rdll, lineNumbersOffset);
        section.RelocationsNumber = ReadWORD(rdll, relocationsNumberOffset);
        section.LinenumbersNumber = ReadWORD(rdll, lineNumbersNumberOffset);
        section.Characteristics = ReadDWORD(rdll, characteristicsOffset);

        headers.push_back(section);
        // See if we've found the export directory data
        //if (headerName.compare(".edata") == 0) {
        //    DWORD firstByte = rdll[rawAddressOffset + 3];
        //    DWORD secondByte = rdll[rawAddressOffset + 2];
        //    DWORD thirdByte = rdll[rawAddressOffset + 1];
        //    DWORD fourthByte = rdll[rawAddressOffset + 0];
        //    // We've read in the correct number of bytes, format address accordingly
        //    DWORD pointerToRawData = (firstByte << 24) | (secondByte << 16) | (thirdByte << 8) | fourthByte;
        //    DWORD symbolRVA = findExportDirectoryInfo(rdll, pointerToRawData, virtualAddressOffset);

        //    DWORD tempSectionHeaderOffset = firstSectionHeaderOffset;
        //    for (int i = 0; i < 11; i++) {
        //        // VirtualAddress offset is 12 bytes from firstSectionHeaderOffset ( Name = 8 bytes, VirtualSize = 4 bytes )
        //        DWORD sectionVirtualAddressOffset = firstSectionHeaderOffset + 0xC;
        //        DWORD sectionVirtualAddress = (rdll[sectionVirtualAddressOffset + 3] << 24) | (rdll[sectionVirtualAddressOffset + 2] << 16) | (rdll[sectionVirtualAddressOffset + 1] << 8) | rdll[sectionVirtualAddressOffset];
        //        // SizeOfRawData offset is 4 bytes from VirtualAddress ( VirtualAddress = 4 )
        //        DWORD sectionSizeOfRawDataOffset = sectionVirtualAddressOffset + 0x4;
        //        DWORD sectionSizeOfRawData = (rdll[sectionSizeOfRawDataOffset + 3] << 24) | (rdll[sectionSizeOfRawDataOffset + 2] << 16) | (rdll[sectionSizeOfRawDataOffset + 1] << 8) | rdll[sectionSizeOfRawDataOffset];
        //        // SizeOfRawData offset is 4 bytes from SizeOfRawData ( SizeOfRawData = 4 )
        //        DWORD sectionPointerToRawDataOffset = sectionSizeOfRawDataOffset + 0x4;
        //        DWORD sectionPointerToRawData = (rdll[sectionPointerToRawDataOffset + 3] << 24) | (rdll[sectionPointerToRawDataOffset + 2] << 16) | (rdll[sectionPointerToRawDataOffset + 1] << 8) | rdll[sectionPointerToRawDataOffset];

        //        if (symbolRVA > sectionVirtualAddress && (symbolRVA < sectionVirtualAddress + sectionSizeOfRawData)) {
        //            DWORD symbolFileOffset = (symbolRVA - sectionVirtualAddress) + sectionPointerToRawData;

        //            unsigned char* boxreflectDllExectuableBuffer = (unsigned char*)VirtualAlloc(NULL, rdll_len + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        //            memcpy(boxreflectDllExectuableBuffer, &rdll, rdll_len);

        //            DWORD flOldProtect;
        //            if (VirtualProtect(boxreflectDllExectuableBuffer, rdll_len + 1, PAGE_EXECUTE_READ, &flOldProtect)) {
        //                LPTHREAD_START_ROUTINE symbolExecutableAddress = (LPTHREAD_START_ROUTINE)((ULONG_PTR)boxreflectDllExectuableBuffer + symbolFileOffset);
        //                DWORD lpThreadId;
        //                HANDLE hThread = CreateThread(NULL, 1024 * 1024, symbolExecutableAddress, NULL, 0, &lpThreadId);
        //                if (hThread) {
        //                    WaitForSingleObject(hThread, INFINITE);
        //                }
        //                VirtualFree(boxreflectDllExectuableBuffer, 0, MEM_RELEASE);
        //                break;
        //            }

        //        }
        //        tempSectionHeaderOffset += 0x28;
        //    }
        //}

        nextSectionHeaderOffset += 0x28;
    }
    return headers;
}