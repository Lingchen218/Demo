#include <windows.h>
#include <iostream>
#include <vector>


// ai ���ɵ� ��ȡ pd �ļ�����peͷ

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

// ����������ļ��Ƿ�Ϊ��Ч�� PE �ļ�
BOOL IsValidPE(LPVOID lpBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // ������Ӹ����飬���� Machine ���͵�
    return true;
}

// ��������ȡ���нڵ����ƺ�ִ��Ȩ��
void GetSectionInfo(LPVOID lpBase) {
    if (!IsValidPE(lpBase)) {
        std::cerr << "��Ч�� PE �ļ���" << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD numberOfSections = pFileHeader->NumberOfSections;
    
    std::cout << "������Ϣ��" << std::endl;
    for (WORD i = 0; i < numberOfSections; ++i) {
        std::cout << "���� " << i + 1 << ":" << std::endl;
        std::cout << "  ����: " << pSectionHeader[i].Name << std::endl;
        std::cout << "  �����С: " << pSectionHeader[i].Misc.VirtualSize << std::endl;
        std::cout << "  �����ַ: 0x" << std::hex << pSectionHeader[i].VirtualAddress << std::dec << std::endl;
        std::cout << "  ԭʼ��С: " << pSectionHeader[i].SizeOfRawData << std::endl;
        std::cout << "  ԭʼ��ַ: 0x" << std::hex << pSectionHeader[i].PointerToRawData << std::dec << std::endl;
        std::cout << "  ��־: 0x" << std::hex << pSectionHeader[i].Characteristics << std::dec << std::endl;

        // �ж��Ƿ����ִ��Ȩ��
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            std::cout << "  �ý�������ִ��Ȩ�ޡ�" << std::endl;
        }
        else {
            std::cout << "  �ý���������ִ��Ȩ�ޡ�" << std::endl;
        }
        std::cout << std::endl;
    }
}

int main1(int argc, char* argv[]) {


    // ����Ȩ�ޱ�־


    
    if (argc != 2) {
        std::cerr << "�÷�: " << argv[0] << " <PE �ļ�·��>" << std::endl;
        return 1;
    }

    // �� PE �ļ�
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "�޷����ļ�: " << argv[1] << std::endl;
        return 1;
    }

    // �����ļ�ӳ�����
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        std::cerr << "�޷������ļ�ӳ�䡣" << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    // ӳ���ļ���ͼ
    LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpBase == NULL) {
        std::cerr << "�޷�ӳ���ļ���ͼ��" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // ��ȡ������Ϣ
    GetSectionInfo(lpBase);

    // ����
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

       
	return 0;
}