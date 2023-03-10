// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "detours.h"
#include<stdio.h>
#include<winsock2.h>
#include<windows.h>
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "detours_x86.lib")
#pragma comment(lib,"ws2_32.lib")



/**
 * chatgpt的示例
 * .
 */
 //BOOL(WINAPI* TrueCreateProcessW)(
 //	LPCWSTR lpApplicationName,
 //	LPWSTR lpCommandLine,
 //	LPSECURITY_ATTRIBUTES lpProcessAttributes,
 //	LPSECURITY_ATTRIBUTES lpThreadAttributes,
 //	BOOL bInheritHandles,
 //	DWORD dwCreationFlags,
 //	LPVOID lpEnvironment,
 //	LPCWSTR lpCurrentDirectory,
 //	LPSTARTUPINFOW lpStartupInfo,
 //	LPPROCESS_INFORMATION lpProcessInformation
 //	) = CreateProcessW;
 //
 //BOOL WINAPI HookCreateProcessW(
 //	LPCWSTR lpApplicationName,
 //	LPWSTR lpCommandLine,
 //	LPSECURITY_ATTRIBUTES lpProcessAttributes,
 //	LPSECURITY_ATTRIBUTES lpThreadAttributes,
 //	BOOL bInheritHandles,
 //	DWORD dwCreationFlags,
 //	LPVOID lpEnvironment,
 //	LPCWSTR lpCurrentDirectory,
 //	LPSTARTUPINFOW lpStartupInfo,
 //	LPPROCESS_INFORMATION lpProcessInformation
 //) {
 //	// 将要注入的DLL路径
 //	const WCHAR* dllPath = L"C:\\path\\to\\your\\dll.dll";
 //
 //	// 在创建进程时注入dll
 //	dwCreationFlags |= CREATE_SUSPENDED;
 //	if (TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
 //		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) 
 // {
 //		LPVOID remoteString = VirtualAllocEx(lpProcessInformation->hProcess, NULL, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 //		WriteProcessMemory(lpProcessInformation->hProcess, remoteString, dllPath, sizeof(dllPath), NULL);
 //		LPTHREAD_START_ROUTINE startRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
 //		HANDLE remoteThread = CreateRemoteThread(lpProcessInformation->hProcess, NULL, 0, startRoutine, remoteString, 0, NULL);
 //		WaitForSingleObject(remoteThread, INFINITE);
 //		CloseHandle(remoteThread);
 //		VirtualFreeEx(lpProcessInformation->hProcess, remoteString, sizeof(dllPath), MEM_RELEASE);
 //		ResumeThread(lpProcessInformation->hThread);
 //		return TRUE;
 //	}
 //	return FALSE;
 //}



static BOOL(WINAPI* OriginalCreateProcessA)(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessA;
BOOL HookCreateProcessA(_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
	MessageBoxA(0, 0, "CreateProcessA start", 0);
	BOOL bRet=OriginalCreateProcessA(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
	return bRet;
}

static BOOL(WINAPI* OriginalCreateProcessW)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessW;
BOOL HookCreateProcessW(_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation)
{
	
	MessageBoxW(0, 0, L"CreateProcessW start", 0);
	MessageBoxW(0, 0, lpApplicationName, 0);
	//将要注入的DLL路径
	HANDLE hThread;
	DWORD dwThreadId;
	char SystemPath[MAX_PATH] = { 0 };
	GetSystemDirectory(SystemPath, MAX_PATH);
	strcat(SystemPath, "\\runas64.dll");
	// 在创建进程时注入dll
	dwCreationFlags |= CREATE_SUSPENDED;
	BOOL bRet = OriginalCreateProcessW(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
	if (bRet)
	{
		DWORD dwSize = lstrlenA(SystemPath) + 1;
		LPVOID remoteString = VirtualAllocEx(
			lpProcessInformation->hProcess,
			NULL, dwSize,
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_READWRITE);
		if (NULL == remoteString)
		{
			MessageBox(0, 0, "VirtualAllocEx fail", 0);
			return FALSE;
		}
		if (FALSE == WriteProcessMemory(
			lpProcessInformation->hProcess,
			remoteString,
			SystemPath,
			dwSize,
			NULL)) 
		{
			MessageBox(0, 0, "WriteProcessMemory fail", 0);
			VirtualFreeEx(lpProcessInformation->hProcess, remoteString, dwSize, MEM_RELEASE);
			CloseHandle(lpProcessInformation->hProcess);
			return FALSE;
		}
		LPTHREAD_START_ROUTINE startRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if(NULL == startRoutine)
		{
			MessageBox(0, 0, "GetProcAddress fail", 0);
			VirtualFreeEx(lpProcessInformation->hProcess, remoteString, dwSize, MEM_RELEASE);
			CloseHandle(lpProcessInformation->hProcess);
			return FALSE;
		}
		HANDLE remoteThread = CreateRemoteThread(lpProcessInformation->hProcess, NULL, 0, startRoutine, remoteString, 0, NULL);
		if (NULL == remoteThread) 
		{
			char buf[250] = { 0 };
			sprintf(buf, "%d", GetLastError());
			MessageBox(0, buf, "CreateRemoteThread fail", 0);
			VirtualFreeEx(lpProcessInformation->hProcess, remoteString, dwSize, MEM_RELEASE);
			CloseHandle(lpProcessInformation->hProcess);
			return FALSE;
		}
		WaitForSingleObject(remoteThread, INFINITE);
		CloseHandle(remoteThread);
		VirtualFreeEx(lpProcessInformation->hProcess, remoteString, dwSize, MEM_RELEASE);
		//hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ResumeThread, (LPVOID)lpProcessInformation->hThread, 0, &dwThreadId);
		ResumeThread(lpProcessInformation->hThread);
		//WaitForSingleObject(lpProcessInformation->hProcess, -1);
		//CloseHandle(lpProcessInformation->hProcess);
		//CloseHandle(lpProcessInformation->hThread);
		MessageBoxW(0, 0, L"CreateProcessW end", 0);
		return bRet;
	}
	return FALSE;
}

static BOOL(WINAPI* OriginalGetUserNameA)(
	_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
	_Inout_ LPDWORD pcbBuffer
	) = GetUserNameA;
BOOL HookGetUserNameA(_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer, _Inout_ LPDWORD pcbBuffer)
{
	DWORD size = *pcbBuffer;
	BOOL bRet = OriginalGetUserNameA(lpBuffer, pcbBuffer);
	if (bRet)
	{

		if (size > 5)
		{
			strncpy(lpBuffer, "Administrator", size);
			*pcbBuffer = 14;
		}
		else
		{
			*pcbBuffer = 6;
			SetLastError(ERROR_BUFFER_OVERFLOW);
			bRet = FALSE;
		}
	}
	return bRet;
}



/**
 * WINADVAPI
BOOL
WINAPI
GetUserNameW (
	_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPWSTR lpBuffer,
	_Inout_ LPDWORD pcbBuffer
	);
 */
static BOOL(WINAPI* OriginalGetUserNameW)(
	_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPWSTR lpBuffer,
	_Inout_ LPDWORD pcbBuffer
	) = GetUserNameW;
BOOL HookGetUserNameW(_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPWSTR lpBuffer, _Inout_ LPDWORD pcbBuffer)
{
	//MessageBoxW(0, 0, L"GetUserNameW", 0);
	DWORD size = *pcbBuffer;
	BOOL bRet = OriginalGetUserNameW(lpBuffer, pcbBuffer);
	if (bRet)
	{

		if (size > 5)
		{
			wcsncpy(lpBuffer, L"Administrator", size);
			*pcbBuffer = 14;
		}
		else
		{
			*pcbBuffer = 6;
			SetLastError(ERROR_BUFFER_OVERFLOW);
			bRet = FALSE;
		}
	}
	return bRet;
}

static BOOL(WINAPI* OriginalGetComputerNameW)(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	_Inout_ LPDWORD nSize
	) = GetComputerNameW;
BOOL HookGetComputerNameW(_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer, _Inout_ LPDWORD nSize)
{
	BOOL bRet = FALSE;
	DWORD dwSize = *nSize;

	if ((NULL == lpBuffer) || (NULL == nSize)) {
		bRet = OriginalGetComputerNameW(lpBuffer, nSize);
		return bRet;
	}

	bRet = OriginalGetComputerNameW(lpBuffer, nSize);
	if (bRet) 
	{
		if (dwSize > 5) 
		{
			wcsncpy(lpBuffer, L"Administrator", dwSize);
			*nSize = 14;
		}
		else 
		{
			*nSize = 6;
			bRet = FALSE;
		}
	}
	return bRet;
}

/*
BOOL
WINAPI
GetComputerNameA (
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize
	);
*/
static BOOL(WINAPI* OriginalGetComputerNameA)(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize
	) = GetComputerNameA;
BOOL HookGetComputerNameA(_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize)
{
	BOOL bRet = FALSE;
	DWORD dwSize = *nSize;

	if ((NULL == lpBuffer) || (NULL == nSize)) {
		bRet = OriginalGetComputerNameA(lpBuffer, nSize);
		return bRet;
	}

	bRet = OriginalGetComputerNameA(lpBuffer, nSize);
	if (bRet) 
	{
		if (dwSize > 5) 
		{
			strncpy(lpBuffer, "Administrator", dwSize);
			*nSize = 14;
		}
		else 
		{
			*nSize = 6;
			bRet = FALSE;
		}
	}
	return bRet;
}


/*
int
WSAAPI
gethostname(
	_Out_writes_bytes_(namelen) char FAR * name,
	_In_ int namelen
	);
*/
static int (WSAAPI* Originalgethostname)(
	_Out_writes_bytes_(namelen) char FAR* name,
	_In_ int namelen
	) = gethostname;
int HookGetHostName(_Out_writes_bytes_(namelen) char FAR* name,
	_In_ int namelen)
{
	BOOL bRet = FALSE;
	int nSize = namelen;
	bRet = Originalgethostname(name, namelen);
	if (bRet)
	{
		if (nSize > 5) 
		{
			strncpy(name, "Administrator", nSize);
		}
		else 
		{
			bRet = FALSE;
		}
	}
	return bRet;
}

static BOOL(WINAPI* OriginalGetComputerNameExA)(
	_In_    COMPUTER_NAME_FORMAT NameType,
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize
	) = GetComputerNameExA;
BOOL HookComputerNameExA(
	_In_    COMPUTER_NAME_FORMAT NameType,
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize) {
	MessageBoxA(0, 0, "GetComputerNameExA", 0);
	BOOL bRet = FALSE;
	char szComputerName[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	if ((NULL == lpBuffer) || (NULL == nSize)) {
		bRet = OriginalGetComputerNameExA(NameType, lpBuffer, &dwSize);
		return bRet;
	}
	bRet = OriginalGetComputerNameExA(NameType, lpBuffer, &dwSize);
	strcpy(lpBuffer, "Administrator");
	*nSize = 0;
	return bRet;
}

/*
BOOL
WINAPI
GetComputerNameExW(
	_In_ COMPUTER_NAME_FORMAT NameType,
	_Out_writes_to_opt_(*nSize,*nSize + 1) LPWSTR lpBuffer,
	_Inout_ LPDWORD nSize
	);
*/
static BOOL(WINAPI* OriginalGetComputerNameExW)(
	_In_    COMPUTER_NAME_FORMAT NameType,
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	__inout LPDWORD nSize
	) = GetComputerNameExW;
BOOL HookComputerNameExW(__in    COMPUTER_NAME_FORMAT NameType,
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	__inout LPDWORD nSize) {

	MessageBoxW(0, 0, L"GetComputerNameExW", 0);
	BOOL bRet = FALSE;
	WCHAR szComputerName[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	if ((NULL == lpBuffer) || (NULL == nSize)) {
		bRet = OriginalGetComputerNameExW(NameType, lpBuffer, &dwSize);
		return bRet;
	}
	bRet = OriginalGetComputerNameExW(NameType, lpBuffer, &dwSize);
	wcscpy(lpBuffer, L"Administrator");
	*nSize = 0;

	return bRet;
}

void StartFun()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriginalGetUserNameA, HookGetUserNameA);
	DetourAttach(&(PVOID&)OriginalGetUserNameW, HookGetUserNameW);
	DetourAttach(&(PVOID&)OriginalCreateProcessA, HookCreateProcessA);
	DetourAttach(&(PVOID&)OriginalCreateProcessW, HookCreateProcessW);

	/*DetourAttach(&(PVOID&)OriginalGetComputerNameW, HookGetComputerNameW);
	DetourAttach(&(PVOID&)OriginalGetComputerNameA, HookGetComputerNameA);
	DetourAttach(&(PVOID&)Originalgethostname, HookGetHostName);
	DetourAttach(&(PVOID&)OriginalGetComputerNameExA, HookComputerNameExA);
	DetourAttach(&(PVOID&)OriginalGetComputerNameExW, HookComputerNameExW);*/
	DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		StartFun();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

