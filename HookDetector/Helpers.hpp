#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

unsigned long ReadDWORD(std::vector<unsigned char> data, unsigned long dwOffset);
unsigned long ReadWORD(std::vector<unsigned char> data, unsigned long dwOffset);
int ReadFile(string dllName, vector<unsigned char>& fileBytes);