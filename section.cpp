#include "FileName.h"
#include <stdio.h>
void Module1Func()
{
	printf("Module1Func\n");
}

#pragma section("F1$a")
__declspec(allocate("F1$a")) node section_node_created_by_module1 = { "Module1Func",Module1Func };



// module2.cpp
void Module2Func()
{
	printf("Module2Func \n");
}

#pragma section("F1$m")
__declspec(allocate("F1$m")) node section_node_created_by_module2 = { "Module2Func",Module2Func };
