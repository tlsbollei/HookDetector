#include <iostream>
#include <Windows.h>
#include <psapi.h>


bool isSyscall(const char* funcName) {
    return (funcName[0] == 'N' && funcName[1] == 't') || (funcName[0] == 'Z' && funcName[1] == 'w');
}

void checkFunctionHook(VOID* funcAddress, const char* funcName) {
    BYTE originalBytes[] = { 0x4c, 0x8b, 0xd1, 0xb8 }; 
    BYTE firstBytes[sizeof(originalBytes)];
    SIZE_T bytesRead;

    if (ReadProcessMemory(GetCurrentProcess(), funcAddress, firstBytes, sizeof(originalBytes), &bytesRead) && bytesRead == sizeof(originalBytes)) {
        if (isSyscall(funcName)) {
            if (memcmp(firstBytes, originalBytes, sizeof(originalBytes)) == 0) {
                printf("Function %s is unhooked (Nt/Zw syscall).\n", funcName);
            }
            else if (firstBytes[0] == 0xE9 || firstBytes[0] == 0xFF) {
                printf("Function %s is hooked (detected JMP or CALL in syscall)            !!!.\n", funcName);
            }
            else {
                printf("Function %s might be modified (unexpected bytes in syscall).\n", funcName);
            }
        }
        else {
            if (firstBytes[0] == 0xE9 || firstBytes[0] == 0xFF) {
                printf("Function %s is hooked (detected JMP or CALL).\n", funcName);
            }
            else {
                printf("Function %s is unhooked (regular function).\n", funcName);
            }
        }
    }
    else {
        printf("Failed to read function %s\n", funcName);
    }
}

int main()
{

    HMODULE libraryBase = LoadLibraryA("ntdll");
    if (libraryBase == NULL) {
        printf("Failed to load NTDLL.dll. Error : %lu\n", GetLastError());
        return -1;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    if (imageNTHeaders == NULL) {
        printf("Failed to load NT Headers of the Portable Executable file structure");
        return -1;
    }

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
    {
        const char* funcName = (const char*)((BYTE*)libraryBase + addressOfNamesRVA[i]);

        VOID* funcAddress = ((BYTE*)libraryBase + addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]]);

        checkFunctionHook(funcAddress, funcName);
    }
    return 0;
    // Signed by Dvorniky
}
