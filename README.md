# HookDetector
Playing with PE's and Building Structures by Hand


## GetProcAddressHook

This is a simple trampoline hook to hook the GetProcAddress function from Kernel32

## HookDetector

Detects the hook from GetProcAddressHook by finding Kernel32 in memory, getting the GetProcAddress address, and reading the first 13 bytes from the function address and comparing it to the function as defined in Kernel32.dll on disk.

## Not Supported

This is me playing with C++, CFF Explorer, and trying to cement the concepts of PEs by building structures by hand and calculating offsets manually.
