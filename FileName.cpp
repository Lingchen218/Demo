#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include"FileName.h"
#ifdef __linux__
// linux ����ڷ�ʽ https://blog.csdn.net/nyist327/article/details/59481809 
using myown_call =  void (*)(void);
#define _init __attribute__((unused, section(".myown")))
#define func_init(func) myown_call _fn_##func _init = func
#elif _WIN32
// msvc section ʹ�ý��� https://blog.csdn.net/yuanshenqiang/article/details/129927806
#elif __ANDROID__

#endif


// ʹ�� #pragma section ����һ����Ϊ ".my_custom_section" �Ľڣ������Ϊ��ִ��
//#pragma section(".my_custom_section", execute)





int test() {
    
    node* ss = &section_start[0];
    node* ee = &section_end[0];
    // ������section��С�Լ����Դ�ŵ�node�����ɱ�������ز���ȷ��
    printf("section size = %d, element count=%d.\n", (ee - ss) * sizeof(node), ee - ss);
    int id = 0;
    for (; ss < ee; ss++, id++)
    {
        if (ss->func != NULL)
        {
            printf("find a valid element in this section, id=%d, name=%s.\n", id, ss->name);
            //( (void*)())(ss->func);
            ((void(*)())((ss->func)))();
        }
            
        
        //section����ʼ����ʱ��ȫ����0������ss->funcΪ0��ʱ������˴�δʹ��
    }
   


    return 0;
}

