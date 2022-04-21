#include "SectionHeaders.hpp"
#include "ExportDirectory.hpp"
#include "Helpers.hpp"

ExportDirectory ParseExportDirectory(std::vector<unsigned char>& rdll, unsigned long dwExportDirectoryOffset, SectionHeader& residingHeader)
{
	ExportDirectory edRet = { 0 };

	unsigned long dwCharacteristicsOffset = dwExportDirectoryOffset;
	unsigned long dwTimeDateStampOffset = dwExportDirectoryOffset + 4;
	unsigned long dwMajorVersionOffset = dwTimeDateStampOffset + 4;
	unsigned long dwMinorVersionOffset = dwMajorVersionOffset + 2;
	unsigned long dwNameOffset = dwMinorVersionOffset + 2;
	unsigned long dwBaseOffset = dwNameOffset + 4;
	unsigned long dwNumberOfFunctionsOffset = dwBaseOffset + 4;
	unsigned long dwNumberOfNamesOffset = dwNumberOfFunctionsOffset + 4;
	unsigned long dwAddressOfFunctionsOffset = dwNumberOfNamesOffset + 4;
	unsigned long dwAddressOfNamesOffset = dwAddressOfFunctionsOffset + 4;
	unsigned long dwAddressOfNameOrdinalsOffset = dwAddressOfNamesOffset + 4;

	edRet.Characteristics = ReadDWORD(rdll, dwCharacteristicsOffset);
	edRet.TimeDateStamp = ReadDWORD(rdll, dwTimeDateStampOffset);
	edRet.MajorVersion = ReadWORD(rdll, dwMajorVersionOffset);
	edRet.MinorVersion = ReadWORD(rdll, dwMinorVersionOffset);
	edRet.Name = ReadDWORD(rdll, dwNameOffset);
	edRet.Base = ReadDWORD(rdll, dwBaseOffset);
	edRet.NumberOfFunctions = ReadDWORD(rdll, dwNumberOfFunctionsOffset);
	edRet.NumberOfNames = ReadDWORD(rdll, dwNumberOfNamesOffset);
	edRet.AddressOfFunctions = ReadDWORD(rdll, dwAddressOfFunctionsOffset);
	edRet.AddressOfNames = ReadDWORD(rdll, dwAddressOfNamesOffset);
	edRet.AddressOfNameOrdinals = ReadDWORD(rdll, dwAddressOfNameOrdinalsOffset);

	GetExportedFunctions(rdll, edRet, residingHeader);

	return edRet;
}

void GetExportedFunctions(std::vector<unsigned char>& rdll, ExportDirectory& data, SectionHeader& header)
{
	if (data.AddressOfFunctions == NULL)
	{
		return;
	}
	unsigned long addressOfFunctionsOffset = data.AddressOfFunctions - header.VirtualAddress + header.RawAddress;
	unsigned long addressOfNameOrdinalsOffset = data.AddressOfNameOrdinals - header.VirtualAddress + header.RawAddress;
	unsigned long addressOfNamesOffset = data.AddressOfNames - header.VirtualAddress + header.RawAddress;
	for (int i = 0; i < data.NumberOfFunctions; i++)
	{
		ExportDirectoryFunction edFunc = { 0 };
		unsigned long dwFunctionRVAOffset = addressOfFunctionsOffset + 4 * i;
		unsigned long dwNameOrdinalOffset = addressOfNameOrdinalsOffset + 2 * i;
		unsigned long dwNameRVAOffset = addressOfNamesOffset + 4 * i;

		unsigned long dwFunctionRVA = ReadDWORD(rdll, dwFunctionRVAOffset);
		unsigned long dwNameOrdinal = ReadWORD(rdll, dwNameOrdinalOffset);
		unsigned long dwNameRVA = ReadDWORD(rdll, dwNameRVAOffset);

		edFunc.FunctionRVA = dwFunctionRVA;
		edFunc.NameOrdinal = dwNameOrdinal;
		edFunc.Ordinal = dwNameOrdinal + 1;
		edFunc.NameRVA = dwNameRVA;
		edFunc.Name = std::string(reinterpret_cast<char*>(&rdll[dwNameRVA - header.VirtualAddress + header.RawAddress]));
		data.ExportedFunctions.push_back(edFunc);
	}
}