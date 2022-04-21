#pragma once

#include <Windows.h>
#include "Helpers.hpp"
#include "SectionHeaders.hpp"
#include "ExportDirectory.hpp"

#define MAGIC_X86 0x10b
#define MAGIC_X64 0x20b

struct PE {
	string Name;
	ULONG_PTR Base;
	unsigned long Magic;
	vector<SectionHeader> SectionHeaders;
	SectionHeader TextSection;
	ExportDirectory ExportDirectory;
};

BOOL ParsePE(vector<unsigned char> dllBytes, ULONG_PTR dllBase, PE& result);
DWORD GetFunctionCodeOffset(string functionName, PE data);