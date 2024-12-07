#include <windows.h>
#include <iostream>
#include <vector>


// ai 生成的 读取 pd 文件解析pe头

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

// 函数：检查文件是否为有效的 PE 文件
BOOL IsValidPE(LPVOID lpBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // 可以添加更多检查，例如 Machine 类型等
    return true;
}

// 函数：获取所有节的名称和执行权限
void GetSectionInfo(LPVOID lpBase) {
    if (!IsValidPE(lpBase)) {
        std::cerr << "无效的 PE 文件。" << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD numberOfSections = pFileHeader->NumberOfSections;
    
    std::cout << "节区信息：" << std::endl;
    for (WORD i = 0; i < numberOfSections; ++i) {
        std::cout << "节区 " << i + 1 << ":" << std::endl;
        std::cout << "  名称: " << pSectionHeader[i].Name << std::endl;
        std::cout << "  虚拟大小: " << pSectionHeader[i].Misc.VirtualSize << std::endl;
        std::cout << "  虚拟地址: 0x" << std::hex << pSectionHeader[i].VirtualAddress << std::dec << std::endl;
        std::cout << "  原始大小: " << pSectionHeader[i].SizeOfRawData << std::endl;
        std::cout << "  原始地址: 0x" << std::hex << pSectionHeader[i].PointerToRawData << std::dec << std::endl;
        std::cout << "  标志: 0x" << std::hex << pSectionHeader[i].Characteristics << std::dec << std::endl;

        // 判断是否具有执行权限
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            std::cout << "  该节区具有执行权限。" << std::endl;
        }
        else {
            std::cout << "  该节区不具有执行权限。" << std::endl;
        }
        std::cout << std::endl;
    }
}

int main1(int argc, char* argv[]) {


    // 定义权限标志


    
    if (argc != 2) {
        std::cerr << "用法: " << argv[0] << " <PE 文件路径>" << std::endl;
        return 1;
    }

    // 打开 PE 文件
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "无法打开文件: " << argv[1] << std::endl;
        return 1;
    }

    // 创建文件映射对象
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        std::cerr << "无法创建文件映射。" << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    // 映射文件视图
    LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpBase == NULL) {
        std::cerr << "无法映射文件视图。" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // 获取节区信息
    GetSectionInfo(lpBase);

    // 清理
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

       
	return 0;
}