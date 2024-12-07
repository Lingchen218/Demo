

// ²Î¿¼´úÂë https://github.com/CheckPointSW/InviZzzible/blob/master/SandboxEvasion/cuckoo.cpp#L40-L49
#include <iostream>
#pragma data_seg(".whtld")
#pragma section(".whtl", read,write,execute)
#pragma comment(linker, "/section:.whtl,RWE")
#pragma comment(linker, "/merge:.whtld=.whtl")

__declspec(code_seg(".whtl"))
void   myFunction() {
    std::cout << "This function is in a custom section a ile." << std::endl;

}