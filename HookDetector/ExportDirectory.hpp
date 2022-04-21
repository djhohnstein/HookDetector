#pragma once
#include <vector>
#include <string>

struct ExportDirectoryFunction {
	unsigned long Ordinal;
	unsigned long FunctionRVA;
	unsigned short NameOrdinal;
	unsigned long NameRVA;
	std::string Name;
};

struct ExportDirectory {
	unsigned long Characteristics;
	unsigned long TimeDateStamp;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	unsigned long Name;
	unsigned long Base;
	unsigned long NumberOfFunctions;
	unsigned long NumberOfNames;
	unsigned long AddressOfFunctions;
	unsigned long AddressOfNames;
	unsigned long AddressOfNameOrdinals;
	std::vector<ExportDirectoryFunction> ExportedFunctions;
};

void GetExportedFunctions(std::vector<unsigned char>& rdll, ExportDirectory& data, SectionHeader& header);
ExportDirectory ParseExportDirectory(std::vector<unsigned char>& rdll, unsigned long dwExportDirectoryOffset, SectionHeader& residingHeader);