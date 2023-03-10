// Wow64Injectx64.cpp : 定义控制台应用程序的入口点。
//

#include <Windows.h>
#include <iostream>
#include <string>
#include "shlwapi.h"
#include "wow64ext.h"
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"wow64ext.lib")
using namespace std;
#define _CRT_SECURE_NO_WARNINGS



unsigned char ShellCode[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
    0x57,                                                       // push      rdi
    0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
    0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
    0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
    0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
    0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
    0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
    0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r9,0  //PVOID*  BaseAddr opt
    0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r8,0  //PUNICODE_STRING Name
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rdx,0
    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
    0xff, 0xd0,                                                 // call      rax   LdrLoadDll
    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
    0xff, 0xd0                                                  // call      rax
};

//BOOL Wow64Injectx64(DWORD ProcessID, const TCHAR* FilePath);
int main()
{
    WCHAR FilePath[] = L"C:\\Users\\desktop1\\Desktop\\runas64.dll";
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    CHAR cmdPath[] = "C:\\Windows\\system32\\cmd.exe";
    //LPCSTR  cmdArgs = "C:\\Program Files (x86)\\BETA_CAE_Systems\\ansa_v19.1.1\\test_bat.bat";
    //LPCSTR  cmdArgs = "\"C:\\Program Files (x86)\\BETA_CAE_Systems\\ansa_v19.1.1\\ansa64.bat\" -changdir %USERPROFILE%";
    LPCSTR  cmdArgs = "\"C:\\Program Files\\MATLAB\\R2022b\\bin\\win64\\MATLAB.exe\" -useStartupFolderPref";
    CHAR cmd_line[MAX_PATH];
    sprintf_s(cmd_line, MAX_PATH, "%s /c \"%s\"", cmdPath, cmdArgs);
    PVOID OldValue;
    Wow64DisableWow64FsRedirection(&OldValue);
    if (!CreateProcessA(NULL, (LPSTR)cmd_line, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("CreateProcess fail %d\n", GetLastError());
        return 1;
    }
    Wow64RevertWow64FsRedirection(OldValue);
    if (!PathFileExists(FilePath))
    {
        int a = GetLastError();
        return FALSE;
    }
    SIZE_T    FilePathLength = (SIZE_T)wcslen(FilePath);
    SIZE_T    ParamemterSize = (FilePathLength + 1) * sizeof(TCHAR) + sizeof(_UNICODE_STRING_T<DWORD64>) + sizeof(DWORD64);
    DWORD64    ParamemterMemAddr = (DWORD64)VirtualAllocEx64(pi.hProcess, NULL, ParamemterSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD64 ShellCodeAddr = (DWORD64)VirtualAllocEx64(pi.hProcess, NULL, sizeof(ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if ((!ParamemterMemAddr) || (!ShellCodeAddr))
    {
        return FALSE;
    }
    char* ParamemterMemLocal = new char[ParamemterSize];
    memset(ParamemterMemLocal, 0, ParamemterSize);

    _UNICODE_STRING_T<DWORD64>* UnicodeString = (_UNICODE_STRING_T<DWORD64>*)(ParamemterMemLocal + sizeof(DWORD64));
    UnicodeString->Length = FilePathLength * sizeof(wchar_t);
    UnicodeString->MaximumLength = (FilePathLength + 1) * 2;
    wcscpy((WCHAR*)(UnicodeString + 1), FilePath);
    UnicodeString->Buffer = ParamemterMemAddr + sizeof(DWORD64) + sizeof(_UNICODE_STRING_T<DWORD64>);

    DWORD64 Ntdll64 = GetModuleHandle64(L"ntdll.dll");
    DWORD64 NtdllLdrLoadDll = GetProcAddress64(Ntdll64, "LdrLoadDll");
    DWORD64 NtdllRtlCreateUserThread = GetProcAddress64(Ntdll64, "RtlCreateUserThread");
    DWORD64 NtdllRtlExitThread = GetProcAddress64(Ntdll64, "RtlExitUserThread");

    if (NtdllLdrLoadDll == NULL || NtdllRtlCreateUserThread == NULL || NtdllRtlExitThread == NULL)
    {
        return FALSE;
    }
    // DWORD转char
    union {
        DWORD64 from;
        unsigned char to[8];
    }Convert;
    // 写入r9寄存器
    Convert.from = ParamemterMemAddr;
    memcpy(ShellCode + 32, Convert.to, sizeof(Convert.to));

    // 写入r8寄存器
    Convert.from = ParamemterMemAddr + sizeof(DWORD64);
    memcpy(ShellCode + 42, Convert.to, sizeof(Convert.to));

    // 写入LdrLoadDll地址
    Convert.from = NtdllLdrLoadDll;
    memcpy(ShellCode + 72, Convert.to, sizeof(Convert.to));

    // 写入NtdllRtlExitThread地址
    Convert.from = NtdllRtlExitThread;
    memcpy(ShellCode + 94, Convert.to, sizeof(Convert.to));

    SIZE_T WriteSize = 0;
    if (!WriteProcessMemory64(pi.hProcess, ParamemterMemAddr, ParamemterMemLocal, ParamemterSize, NULL) ||
        !WriteProcessMemory64(pi.hProcess, ShellCodeAddr, ShellCode, sizeof(ShellCode), NULL))
    {
        return FALSE;
    }

    DWORD64 hRemoteThread = 0;
    struct {
        DWORD64 UniqueProcess;
        DWORD64 UniqueThread;
    }ClientID;

    int nRet = X64Call(NtdllRtlCreateUserThread, 10,
        (DWORD64)pi.hProcess,                    // ProcessHandle
        (DWORD64)NULL,                      // SecurityDescriptor
        (DWORD64)FALSE,                     // CreateSuspended
        (DWORD64)0,                         // StackZeroBits
        (DWORD64)NULL,                      // StackReserved
        (DWORD64)NULL,                      // StackCommit
        ShellCodeAddr,                        // StartAddress
        (DWORD64)NULL,                      // StartParameter
        (DWORD64)&hRemoteThread,            // ThreadHandle
        (DWORD64)&ClientID);                // ClientID)

    if (hRemoteThread != 0)
    {
        CloseHandle((HANDLE)hRemoteThread);
        WaitForSingleObject((HANDLE)hRemoteThread, INFINITE);
        ResumeThread(pi.hThread);
        ResumeThread(pi.hProcess);
        return TRUE;
    }
    
    
    return 0;
}
