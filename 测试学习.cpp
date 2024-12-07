// 测试学习.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
// #include <string.h>
#include <Windows.h>
#include<TlHelp32.h>
#include"FileName.h"
#include"crc32.h"
// 反调试学习
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    DWORD PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger
}THREAD_INFO_CLASS;

typedef NTSTATUS(NTAPI* _ZwSetInformationThread)(
    HANDLE          ThreadHandle,
    THREAD_INFO_CLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation  // 所有对象类型信息
} OBJECT_INFORMATION_CLASS;

 typedef NTSTATUS (NTAPI *_NtQueryObject)(
     HANDLE                   Handle,
     OBJECT_INFORMATION_CLASS ObjectInformationClass, // 查询对象类型枚举值
     PVOID                    ObjectInformation,      // 输出结果缓冲区
     ULONG                    ObjectInformationLength,// 缓冲区大小
     PULONG                   ReturnLength             // 实际使用大小
);

 typedef struct _UNICODE_STRING
 {
     USHORT Length;
     USHORT MaximumLength;
     _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
 } UNICODE_STRING, * PUNICODE_STRING;


 /**
 * The OBJECT_NAME_INFORMATION structure contains various statistics and properties about an object type.
 */
 typedef struct _OBJECT_TYPE_INFORMATION
 {
     UNICODE_STRING TypeName; // 内核对象类型名称
     ULONG TotalNumberOfObjects;
     ULONG TotalNumberOfHandles;
     ULONG TotalPagedPoolUsage;
     ULONG TotalNonPagedPoolUsage;
     ULONG TotalNamePoolUsage;
     ULONG TotalHandleTableUsage;
     ULONG HighWaterNumberOfObjects;
     ULONG HighWaterNumberOfHandles;
     ULONG HighWaterPagedPoolUsage;
     ULONG HighWaterNonPagedPoolUsage;
     ULONG HighWaterNamePoolUsage;
     ULONG HighWaterHandleTableUsage;
     ULONG InvalidAttributes;
     GENERIC_MAPPING GenericMapping;
     ULONG ValidAccessMask;
     BOOLEAN SecurityRequired;
     BOOLEAN MaintainHandleCount;
     UCHAR TypeIndex; // since WINBLUE
     CHAR ReservedByte;
     ULONG PoolType;
     ULONG DefaultPagedPoolCharge;
     ULONG DefaultNonPagedPoolCharge;
 } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

 typedef struct  _OBJECT_TYPES_INFORMATION
 {
    ULONG numberOfTypesInfo;
    OBJECT_TYPE_INFORMATION typeInfo[1];
 }OBJECT_TYPES_INFORMATION,*POBJECT_TYPES_INFORMATION;

EXCEPTION_DISPOSITION WINAPI myExceptHandler(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    PVOID EstablisherFrame,
    PCONTEXT pcontext,
    PVOID DispatcherContext
) {
    if (pcontext->Dr0 != 0 || pcontext->Dr1 != 0 || pcontext->Dr2 != 0 || pcontext->Dr3 != 0) {
        printf("检测到硬件断点 程序被调试了1\n");
        ExitProcess(0);
    }
    printf("未检测硬件断点\n");
    // ExceptionContinueSearch 我处理不了，你继续往下执行只可以处理异常的
    // ExceptionContinueExecution 继续到异常触发的位置接着执行
      pcontext->Eip = pcontext->Eip + 2;
    return ExceptionContinueExecution;
}

//unsigned make_crc(const unsigned char* instr, const size_t& strlent) {
//    // 这里是crc32 计算，还没写，先忽略，
//    return 0;
//}
int main()
{
    test();
    _ZwSetInformationThread ZwSetInformationThread;
    _NtQueryInformationProcess NtQueryInformationProcess;
    _NtQueryObject NtQueryObject;
    //PROCESSINFOCLASS
    // LPDEBUG_EVENT out_debuevent;
    //DWORD testst;
    //WaitForDebugEvent(out_debuevent, 0);
    // 注册sehandler
    DWORD sehHandler = (DWORD)myExceptHandler;
    // 异常来获取进程上下文信息里面包含了寄存器信息，
     // seh 实现的veh 如何实现呢？
    __asm {
        push myExceptHandler
        mov eax, fs:[0]
        push eax
        mov fs:[0],esp
    }

    int a = 10;
      a = a / 0;
     // throw("x");  //抛出异常 myExceptHandler 函数就会被执行
      // 解绑异常
      __asm {
          mov eax,[esp]
          mov fs:[0],eax
          add esp,8
      }
    DWORD isbug = 0;
    BOOL isdebug = IsDebuggerPresent();
    if (isdebug) {
        printf("IsDebuggerPresent检测到 被调试\n");
    }
    else {
        printf("IsDebuggerPresent未被调试\n");
    }


    _asm {
        mov eax, fs: [0x30]
        mov eax, [eax + 0x68]
        mov isbug, eax
    }
    if (isbug == 0x70) {
        // 以附件的形式 无法检测到
        printf("NtglobalFlag标致检测到 被调试\n");
    }
    else {
        // vs debug调试检测不到
        printf("NtglobalFlag标致 未被调试\n");
    }

    // ProcessDebugPort 调试端口  7
    // ProcessDebugObject 调试对象的句柄30
    // ProcessDebugFlags 31  0调试状态 1 非调试状态
    BOOL pbDebuggerPresent = false;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &pbDebuggerPresent);

    if (pbDebuggerPresent) {
        printf("ProcessDebugPort 端口 被调试\n");
    }
    else {
        printf("ProcessDebugPort 端口 未被调试\n");
    }





    HMODULE hmodule = LoadLibraryA("ntdll.dll");
    //GetModuleHandleA("ntdll.dll");  // 这种也可以获取 dll 对象
    if (hmodule != 0) {
        NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hmodule, "NtQueryInformationProcess");
        ZwSetInformationThread = (_ZwSetInformationThread)GetProcAddress(hmodule, "ZwSetInformationThread");
        NtQueryObject = (_NtQueryObject)GetProcAddress(hmodule, "NtQueryObject");
    }
    //


    DWORD debugPort = 0;
    HANDLE DebugHandle = 0;
    BOOL ProcessDebugFlags = false;
    NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 30, &DebugHandle, sizeof(HANDLE), NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 31, &ProcessDebugFlags, sizeof(BOOL), NULL);


    if (debugPort != 0) {
        printf("ProcessDebugPort 调试状态\n");
    }
    else {
        printf("NtQueryInformationProcess 未被调试\n");
    }

    if (DebugHandle != 0) {
        printf("ProcessDebugObject 调试状态\n");
    }
    else {
        printf("ProcessDebugObject 未被调试\n");
    }

    if (ProcessDebugFlags == 0) {
        printf("ProcessDebugFlags 检测到调试器\n");
    }
    else {
        printf("ProcessDebugFlags 未被调试\n");
    }
    __try {
        // 关闭一个不存在的句柄 如果被调试 就会触发异常
        // vs debug时会抛出异常，用户正常运行时 不会有异常问题
        CloseHandle((HANDLE)0x112121);
    }
    __except (1) {
        printf("CloseHandle 检测到被调试\n");
    }

    // 设置线程信息分离调试器  如果遇到调试将会自动退出剥离调试线程
    ZwSetInformationThread(GetCurrentProcess(), ThreadHideFromDebugger, NULL, NULL);


    // 硬件断点 检测
    CONTEXT context{ 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentProcess(), &context);

    if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
        printf("检测到硬件断点 程序被调试了\n");
    }
    else {
        printf("未检测到硬件断点\n");
    }

    // 获取父进程Handle
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnlength;
    NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &basicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnlength);

    // 获取资源管理器Handler
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("创建进程快照失败\n");
    }
    PROCESSENTRY32W lpprocessentry;
    lpprocessentry.dwSize = sizeof(PROCESSENTRY32W);
    Process32First(hSnap, &lpprocessentry);
    do {
        if (wcscmp(L"explorer.exe", lpprocessentry.szExeFile) == 0) {
            if (lpprocessentry.th32ProcessID != basicInfo.InheritedFromUniqueProcessId) {
                printf("程序可能被调试了\n");
            }

        }
    } while (Process32Next(hSnap, &lpprocessentry));
    if (hSnap != 0) {
        CloseHandle(hSnap);
    }


    //
    char* charbuffer = (char*)malloc(0x4000);
    DWORD realsiez = 0;
    NTSTATUS ret = NtQueryObject(NULL, ObjectTypesInformation, charbuffer, 0x4000, &realsiez);

    if (ret != 0)
    {
        printf("NtQueryObject error");
    }
    POBJECT_TYPES_INFORMATION typesInfo = (POBJECT_TYPES_INFORMATION) (charbuffer);
    POBJECT_TYPE_INFORMATION typeinfo = typesInfo->typeInfo;
    for (ULONG i = 0; i < typesInfo->numberOfTypesInfo; i++) {
        if (wcscmp(L"DebugObject", typeinfo->TypeName.Buffer) == 0) {
            if (typeinfo->TotalNumberOfObjects > 0) {
                printf("%d", typeinfo->TotalNumberOfObjects);
                printf("检测到调试对象\n");
                break;
            }
            else {
                printf("未检测到调试对象\n");
            }
        }
#ifdef WIN32
        DWORD buffLen = typeinfo->TypeName.MaximumLength;
        buffLen = buffLen + buffLen % 4;
        typeinfo = (POBJECT_TYPE_INFORMATION)((DWORD)typeinfo + buffLen);
        typeinfo++;
        
#else
        // debug 模式下会出现cdcdcdc情况
        char* temp = (char*)typeinfo->TypeName.Buffer;
        temp = temp + typeInfo->Typename.MaximumLength;
        temp = temp + (DWORD)temp % 4;
        DWORD data = *(DWORLD*)temp;
        while (data == 0) {
            temp += 4;
            data = *(DWORD*)temp;
        }
        typeinfo = (POBJECT_TYPE_INFORMATION)temp;
#endif
    }
    // 
    free(charbuffer);


    // crc32 判断int3断点
    
    char*  buff = (char*)GetModuleHandleA(0); // 获取模块的首地址

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff; // 转换为dos 头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + buff);
    
    PIMAGE_SECTION_HEADER pfirstHeader = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(pNtHeader)+((LONG)__builtin_offsetof(IMAGE_NT_HEADERS, OptionalHeader)) + ((pNtHeader))->FileHeader.SizeOfOptionalHeader));
    
    int selectnum = pNtHeader->FileHeader.NumberOfSections; // 获取节的数量
    
    for (int i = 0; i < selectnum; i++) {
        if (pfirstHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // 有执行权限
            uint32_t crc111 = make_crc((unsigned char*)(pfirstHeader->VirtualAddress + buff), pfirstHeader->Misc.VirtualSize);
            std::cout << "有执行 权限名称是：" << pfirstHeader->Name << " 0x" << std::hex << crc111 << std::endl;

        }
        else {
            std::cout << "没有执行权限，名称是：" << pfirstHeader->Name << std::endl;
        }
        pfirstHeader++;
    }
    // vmware 检测


    system("pause");
    return 0;
}

