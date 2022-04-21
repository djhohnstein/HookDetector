#pragma once
#include <string>
#include <vector>
#include "Helpers.hpp"

using namespace std;

struct SectionHeader
{
	string Name;
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long RawSize;
	unsigned long RawAddress;
	unsigned long RelocAddress;
	unsigned long Linenumbers;
	unsigned short RelocationsNumber;
	unsigned short LinenumbersNumber;
	unsigned long Characteristics;
};


vector<SectionHeader> GetSectionHeaders(vector<unsigned char> rdll, unsigned long firstHeaderOffset, unsigned short numberOfHeaders);