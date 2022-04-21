#include "Helpers.hpp"

unsigned long ReadDWORD(std::vector<unsigned char> data, unsigned long dwOffset)
{
	return data[dwOffset + 3] << 24 | data[dwOffset + 2] << 16 | data[dwOffset + 1] << 8 | data[dwOffset];
}

unsigned long ReadWORD(std::vector<unsigned char> data, unsigned long dwOffset)
{
	return data[dwOffset + 1] << 8 | data[dwOffset];
}


int ReadFile(string dllName, vector<unsigned char>& fileBytes) {
    ifstream ifs(dllName, ios::binary | ios::ate);
    if (ifs.fail())
    {
        return -1;
    }
    ifstream::pos_type pos = ifs.tellg();

    // What happens if the OS supports really big files.
    // It may be larger than 32 bits?
    // This will silently truncate the value/
    int length = pos;

    fileBytes.resize(length);

    ifs.seekg(0, ios::beg);
    ifs.read(reinterpret_cast<char*>(&fileBytes[0]), length);

    // No need to manually close.
    // When the stream goes out of scope it will close the file
    // automatically. Unless you are checking the close for errors
    // let the destructor do it.
    ifs.close();
    return 0;
}