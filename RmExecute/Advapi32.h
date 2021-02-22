

//这个类专门导出Advapi32.dll中的系统API
class Advapi32 :BaseInclude
{
#define Advapi32_EXTEND_H win.advapi32
#define Advapi32_DEF(x) if (!Advapi32Base)GetAdvapi32();if (!g_##x##)Init_##x##();
public:
	HMODULE Advapi32Base = 0;//Shell32.dll的模块基址

public:
	typedef LSTATUS(WINAPI* fnRegCreateKeyExA)(
		_In_ HKEY hKey,
		_In_ LPCSTR lpSubKey,
		_Reserved_ DWORD Reserved,
		_In_opt_ LPSTR lpClass,
		_In_ DWORD dwOptions,
		_In_ REGSAM samDesired,
		_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_Out_ PHKEY phkResult,
		_Out_opt_ LPDWORD lpdwDisposition
		);
	fnRegCreateKeyExA g_RegCreateKeyExA = 0;


	typedef LSTATUS(WINAPI* fnRegSetValueExA)(
		_In_ HKEY hKey,
		_In_opt_ LPCSTR lpValueName,
		_Reserved_ DWORD Reserved,
		_In_ DWORD dwType,
		_In_reads_bytes_opt_(cbData) CONST BYTE * lpData,
		_In_ DWORD cbData
		);
	fnRegSetValueExA g_RegSetValueExA = 0;

	typedef LSTATUS(WINAPI* fnRegCloseKey)(
		_In_ HKEY hKey
		);
	fnRegCloseKey g_RegCloseKey = 0;


		typedef LSTATUS(WINAPI* fnRegOpenKeyExA)(
		_In_ HKEY hKey,
		_In_opt_ LPCSTR lpSubKey,
		_In_opt_ DWORD ulOptions,
		_In_ REGSAM samDesired,
		_Out_ PHKEY phkResult
		);
	fnRegOpenKeyExA g_RegOpenKeyExA = 0;
	
	
		typedef LSTATUS(WINAPI* fnRegEnumKeyExA)(
		_In_ HKEY hKey,
		_In_ DWORD dwIndex,
		_Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
		_Inout_ LPDWORD lpcchName,
		_Reserved_ LPDWORD lpReserved,
		_Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPSTR lpClass,
		_Inout_opt_ LPDWORD lpcchClass,
		_Out_opt_ PFILETIME lpftLastWriteTime
		);
		fnRegEnumKeyExA g_RegEnumKeyExA = 0;
		
		typedef BOOL(WINAPI* fnLookupAccountNameA)(
			_In_opt_  LPCTSTR       lpSystemName,
			_In_      LPCTSTR       lpAccountName,
			_Out_opt_ PSID          Sid,
			_Inout_   LPDWORD       cbSid,
			_Out_opt_ LPTSTR        ReferencedDomainName,
			_Inout_   LPDWORD       cchReferencedDomainName,
			_Out_     PSID_NAME_USE peUse
			);
		fnLookupAccountNameA g_LookupAccountNameA = 0;

		typedef BOOL(WINAPI* fnGetFileSecurityA)(
			_In_  LPCSTR lpFileName,
			_In_  SECURITY_INFORMATION RequestedInformation,
			_Out_writes_bytes_to_opt_(nLength, *lpnLengthNeeded) PSECURITY_DESCRIPTOR pSecurityDescriptor,
			_In_  DWORD nLength,
			_Out_ LPDWORD lpnLengthNeeded
			);
		fnGetFileSecurityA  g_GetFileSecurityA = 0;
		
		typedef BOOL(WINAPI* fnGetSecurityDescriptorDacl)(
			_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
			_Out_ LPBOOL lpbDaclPresent,
			_Outptr_ PACL * pDacl,
			_Out_ LPBOOL lpbDaclDefaulted
			);
		fnGetSecurityDescriptorDacl g_GetSecurityDescriptorDacl = 0;

		typedef BOOL(WINAPI* fnGetAclInformation)(
			_In_ PACL pAcl,
			_Out_writes_bytes_(nAclInformationLength) LPVOID pAclInformation,
			_In_ DWORD nAclInformationLength,
			_In_ ACL_INFORMATION_CLASS dwAclInformationClass
			);
		fnGetAclInformation g_GetAclInformation = 0;
		
		typedef BOOL(WINAPI* fnGetAce)(
			_In_ PACL pAcl,
			_In_ DWORD dwAceIndex,
			_Outptr_ LPVOID * pAce
			);
		fnGetAce g_GetAce = 0;
		
		typedef BOOL(WINAPI* fnEqualSid)(
			_In_ PSID pSid1,
			_In_ PSID pSid2
			);
		fnEqualSid g_EqualSid = 0;
		
		typedef BOOL(WINAPI* fnGetUserNameA)(
			_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
			_Inout_ LPDWORD pcbBuffer
			);
		fnGetUserNameA  g_GetUserNameA = 0;
		

public:
	Advapi32()
	{
	}

	void GetAdvapi32()//初始化，加载上预定好的函数的偏移，这里是ShellExecuteA函数
	{
		char Advapi32[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', '\0' };
		Advapi32Base = fLoadLibraryA(Advapi32);
	}

	//API寻址导出
public:

	void __stdcall Init_RegCreateKeyExA()
	{
		char szRegCreateKeyExA[16] = { 'R', 'e', 'g', 'C', 'r', 'e', 'a', 't', 'e', 'K', 'e', 'y', 'E', 'x', 'A', 0 };
		g_RegCreateKeyExA = (fnRegCreateKeyExA)fGetProcAddress(Advapi32Base, szRegCreateKeyExA);
	}
	LSTATUS
		APIENTRY
		RegCreateKeyExA(
		_In_ HKEY hKey,
		_In_ LPCSTR lpSubKey,
		_Reserved_ DWORD Reserved,
		_In_opt_ LPSTR lpClass,
		_In_ DWORD dwOptions,
		_In_ REGSAM samDesired,
		_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_Out_ PHKEY phkResult,
		_Out_opt_ LPDWORD lpdwDisposition
		)
	{
		Advapi32_DEF(RegCreateKeyExA);
		return g_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	}

	void __stdcall Init_RegSetValueExA()
	{
		char szRegSetValueExA[15] = { 'R', 'e', 'g', 'S', 'e', 't', 'V', 'a', 'l', 'u', 'e', 'E', 'x', 'A', 0 };
		g_RegSetValueExA = (fnRegSetValueExA)fGetProcAddress(Advapi32Base, szRegSetValueExA);
	}
	LSTATUS
		APIENTRY
		RegSetValueExA(
		_In_ HKEY hKey,
		_In_opt_ LPCSTR lpValueName,
		_Reserved_ DWORD Reserved,
		_In_ DWORD dwType,
		_In_reads_bytes_opt_(cbData) CONST BYTE * lpData,
		_In_ DWORD cbData
		)
	{
		Advapi32_DEF(RegSetValueExA);
		return g_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	}

	void __stdcall Init_RegCloseKey()
	{
		char szRegCloseKey[12] = { 'R', 'e', 'g', 'C', 'l', 'o', 's', 'e', 'K', 'e', 'y', 0 };
		g_RegCloseKey = (fnRegCloseKey)fGetProcAddress(Advapi32Base, szRegCloseKey);
	}
	LSTATUS
		APIENTRY
		RegCloseKey(
		_In_ HKEY hKey
		)
	{
		Advapi32_DEF(RegCloseKey);
		return g_RegCloseKey(hKey);
	}

	void __stdcall Init_RegOpenKeyExA()
	{
		char szRegOpenKeyExA[14] = { 'R', 'e', 'g', 'O', 'p', 'e', 'n', 'K', 'e', 'y', 'E', 'x', 'A', 0 };
		g_RegOpenKeyExA = (fnRegOpenKeyExA)fGetProcAddress(Advapi32Base, szRegOpenKeyExA);
	}
	LSTATUS
		APIENTRY
		RegOpenKeyExA(
		_In_ HKEY hKey,
		_In_opt_ LPCSTR lpSubKey,
		_In_opt_ DWORD ulOptions,
		_In_ REGSAM samDesired,
		_Out_ PHKEY phkResult
		)
	{
		Advapi32_DEF(RegOpenKeyExA);
		return g_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	}

	void __stdcall Init_RegEnumKeyExA()
	{
		char szRegEnumKeyExA[14] = { 'R', 'e', 'g', 'E', 'n', 'u', 'm', 'K', 'e', 'y', 'E', 'x', 'A', 0 };
		g_RegEnumKeyExA = (fnRegEnumKeyExA)fGetProcAddress(Advapi32Base, szRegEnumKeyExA);
	}
	LSTATUS
		APIENTRY
		RegEnumKeyExA(
		_In_ HKEY hKey,
		_In_ DWORD dwIndex,
		_Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
		_Inout_ LPDWORD lpcchName,
		_Reserved_ LPDWORD lpReserved,
		_Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPSTR lpClass,
		_Inout_opt_ LPDWORD lpcchClass,
		_Out_opt_ PFILETIME lpftLastWriteTime
		)
	{
		Advapi32_DEF(RegEnumKeyExA);
		return g_RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
	}

	void __stdcall Init_LookupAccountNameA()
	{
		char szLookupAccountNameA[19] = { 'L', 'o', 'o', 'k', 'u', 'p', 'A', 'c', 'c', 'o', 'u', 'n', 't', 'N', 'a', 'm', 'e','A', 0 };
		g_LookupAccountNameA = (fnLookupAccountNameA)fGetProcAddress(Advapi32Base, szLookupAccountNameA);
	}
	BOOL
		WINAPI
		LookupAccountNameA(
		_In_opt_  LPCTSTR       lpSystemName,
		_In_      LPCTSTR       lpAccountName,
		_Out_opt_ PSID          Sid,
		_Inout_   LPDWORD       cbSid,
		_Out_opt_ LPTSTR        ReferencedDomainName,
		_Inout_   LPDWORD       cchReferencedDomainName,
		_Out_     PSID_NAME_USE peUse
		)
	{
		Advapi32_DEF(LookupAccountNameA);
		return g_LookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse);
	}

	void __stdcall Init_GetFileSecurityA()
	{
		char szGetFileSecurityA[18] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'A', 0 };
		g_GetFileSecurityA = (fnGetFileSecurityA)fGetProcAddress(Advapi32Base, szGetFileSecurityA);
	}
	BOOL
		WINAPI
		GetFileSecurityA(
		_In_  LPCSTR lpFileName,
		_In_  SECURITY_INFORMATION RequestedInformation,
		_Out_writes_bytes_to_opt_(nLength, *lpnLengthNeeded) PSECURITY_DESCRIPTOR pSecurityDescriptor,
		_In_  DWORD nLength,
		_Out_ LPDWORD lpnLengthNeeded
		)
	{
		Advapi32_DEF(GetFileSecurityA);
		return g_GetFileSecurityA(lpFileName, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded);
	}

	void __stdcall Init_GetSecurityDescriptorDacl()
	{
		char szGetSecurityDescriptorDacl[26] = { 'G', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'D', 'a', 'c', 'l', 0 };
		g_GetSecurityDescriptorDacl = (fnGetSecurityDescriptorDacl)fGetProcAddress(Advapi32Base, szGetSecurityDescriptorDacl);
	}
	BOOL
		WINAPI
		GetSecurityDescriptorDacl(
		_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
		_Out_ LPBOOL lpbDaclPresent,
		_Outptr_ PACL * pDacl,
		_Out_ LPBOOL lpbDaclDefaulted
		)
	{
		Advapi32_DEF(GetSecurityDescriptorDacl);
		return g_GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted);
	}

	void __stdcall Init_GetAclInformation()
	{
		char szGetAclInformation[18] = { 'G', 'e', 't', 'A', 'c', 'l', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0 };
		g_GetAclInformation = (fnGetAclInformation)fGetProcAddress(Advapi32Base, szGetAclInformation);
	}
	BOOL
		WINAPI
		GetAclInformation(
		_In_ PACL pAcl,
		_Out_writes_bytes_(nAclInformationLength) LPVOID pAclInformation,
		_In_ DWORD nAclInformationLength,
		_In_ ACL_INFORMATION_CLASS dwAclInformationClass
		)
	{
		Advapi32_DEF(GetAclInformation);
		return g_GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass);
	}

	void __stdcall Init_GetAce()
	{
		char szGetAce[7] = { 'G', 'e', 't', 'A', 'c', 'e', 0 };
		g_GetAce = (fnGetAce)fGetProcAddress(Advapi32Base, szGetAce);
	}
	BOOL
		WINAPI
		GetAce(
		_In_ PACL pAcl,
		_In_ DWORD dwAceIndex,
		_Outptr_ LPVOID * pAce
		)
	{
		Advapi32_DEF(GetAce);
		return g_GetAce(pAcl, dwAceIndex, pAce);
	}

	void __stdcall Init_EqualSid()
	{
		char szEqualSid[9] = { 'E', 'q', 'u', 'a', 'l', 'S', 'i', 'd', 0 };
		g_EqualSid = (fnEqualSid)fGetProcAddress(Advapi32Base, szEqualSid);
	}
	BOOL
		WINAPI
		EqualSid(
		_In_ PSID pSid1,
		_In_ PSID pSid2
		)
	{
		Advapi32_DEF(EqualSid);
		return g_EqualSid(pSid1, pSid2);
	}

	void __stdcall Init_GetUserNameA()
	{
		char szGetUserNameA[14] = { 'G', 'e', 't', 'U', 's', 'e', 'r', 'N', 'a', 'm', 'e', 'A', 0 };
		g_GetUserNameA = (fnGetUserNameA)fGetProcAddress(Advapi32Base, szGetUserNameA);
	}
	BOOL
		WINAPI
		GetUserNameA(
		_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
		_Inout_ LPDWORD pcbBuffer
		)
	{
		Advapi32_DEF(GetUserNameA);
		return g_GetUserNameA(lpBuffer, pcbBuffer);
	}

#define GetUserNameA Advapi32_EXTEND_H.GetUserNameA
#define EqualSid Advapi32_EXTEND_H.EqualSid
#define GetAce Advapi32_EXTEND_H.GetAce
#define GetAclInformation Advapi32_EXTEND_H.GetAclInformation
#define GetSecurityDescriptorDacl Advapi32_EXTEND_H.GetSecurityDescriptorDacl
#define GetFileSecurityA Advapi32_EXTEND_H.GetFileSecurityA
#define LookupAccountNameA Advapi32_EXTEND_H.LookupAccountNameA
#define RegEnumKeyExA Advapi32_EXTEND_H.RegEnumKeyExA
#define RegOpenKeyExA Advapi32_EXTEND_H.RegOpenKeyExA
#define RegCloseKey Advapi32_EXTEND_H.RegCloseKey
#define RegSetValueExA Advapi32_EXTEND_H.RegSetValueExA
#define RegCreateKeyExA Advapi32_EXTEND_H.RegCreateKeyExA
};