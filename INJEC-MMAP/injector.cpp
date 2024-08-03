#include "injector.h"

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool ManualMapDll2(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved) 
{
	pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtAllocateVirtualMemory"));
	pfnNtProtectVirtualMemory NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtProtectVirtualMemory"));
	pfnNtFreeVirtualMemory NtFreeVirtualMemory = (pfnNtFreeVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtFreeVirtualMemory"));
	pfnNtWriteVirtualMemory NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtWriteVirtualMemory"));
	pfnNtReadVirtualMemory NtReadVirtualMemory = (pfnNtReadVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtReadVirtualMemory"));
	pfnNtClose NtClose = (pfnNtClose)GetProcAddress(ntdll_base, skCrypt("NtClose"));
	NtDelayExecution_t NtDelayExecution = (NtDelayExecution_t)GetProcAddress(ntdll_base, skCrypt("NtDelayExecution"));

	LARGE_INTEGER interval;
	interval.QuadPart = -100000; // 10ms ?

	LPVOID pLoadLibrary = GetProcAddress(kernel32_base, skCrypt("LoadLibraryA"));
	if (!pLoadLibrary) {
		return false;
	}

	LPVOID pRtlAddFunctionTable = GetProcAddress(ntdll_base, skCrypt("RtlAddFunctionTable"));
	if (!pRtlAddFunctionTable) {
		return false;
	}

	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	PVOID pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH) {
		return false;
	}

	SIZE_T size = pOldOptHeader->SizeOfImage;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc, &pTargetBase, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		return false;

	DWORD oldp = 0;
	size = pOldOptHeader->SizeOfImage;
	if (!NT_SUCCESS(NtProtectVirtualMemory(hProc, &pTargetBase, &size, PAGE_EXECUTE_READWRITE, &oldp)))
		return false;

	MANUAL_MAPPING_DATA_NEW data{ 0 };

	data.pLoadLibraryA = (f_LoadLibraryA)pLoadLibrary;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)pRtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;

	if (!NT_SUCCESS(NtWriteVirtualMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)))
	{
		if(!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			PVOID v1 = (PVOID)((uintptr_t)pTargetBase + pSectionHeader->VirtualAddress);
			BYTE* v2 = pSrcData + pSectionHeader->PointerToRawData;
			SIZE_T cur_size = pSectionHeader->SizeOfRawData;

			NTSTATUS status = NtWriteVirtualMemory(hProc, v1, v2, cur_size, nullptr);
			if (!NT_SUCCESS(status)) 
			{
				if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
					return false;

				return false;
			}
		}
	}

	PVOID MappingDataAlloc = nullptr;
	SIZE_T size_of_struct = sizeof(MANUAL_MAPPING_DATA_NEW);
	if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc, &MappingDataAlloc, 0, &size_of_struct, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
	{
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	if (!NT_SUCCESS(NtWriteVirtualMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA_NEW), nullptr))) {
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	PVOID pShellCode = nullptr;
	SIZE_T pSizeShellCode = 0x1000;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc, &pShellCode, 0, &pSizeShellCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
	{
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		return false;
	}


	if (!NT_SUCCESS(NtWriteVirtualMemory(hProc, pShellCode, Shellcode, 0x1000, nullptr))) {
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	if (!InjectShellCode(hProc, pShellCode, MappingDataAlloc, pTargetBase)) { // create thread here
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
			return false;
	}

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		MANUAL_MAPPING_DATA_NEW data_checked{ 0 };

		if (!NT_SUCCESS(NtReadVirtualMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr)))
			return false;

		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
				return false;

			if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
				return false;

			if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
				return false;

			return false;
		}
		else if (hCheck == (HINSTANCE)0x505050) {

		}

		NtDelayExecution(FALSE, &interval); // who verifies this? tf
	}

	PVOID emptyBuffer = nullptr;
	SIZE_T sizeBuffer = 1024 * 1024 * 20;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc, &emptyBuffer, 0, &sizeBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		return false;

	memset(emptyBuffer, 0, sizeBuffer);

	if (ClearHeader) {
		NTSTATUS status = NtWriteVirtualMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr);
		if (!NT_SUCCESS(status)) {
			return false;
		}
	}

	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, skCrypt(".pdata")) == 0) ||
					strcmp((char*)pSectionHeader->Name, skCrypt(".rsrc")) == 0 ||
					strcmp((char*)pSectionHeader->Name, skCrypt(".reloc")) == 0) {

					PVOID cur_base = (PVOID)((uintptr_t)pTargetBase + pSectionHeader->VirtualAddress);
					SIZE_T cur_size = pSectionHeader->Misc.VirtualSize;

					NTSTATUS status = NtWriteVirtualMemory(hProc, cur_base, emptyBuffer, cur_size, nullptr);
					if (!NT_SUCCESS(status)) {
						return false;
					}
				}
			}
		}
	}

	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				PVOID cur_base = (PVOID)((uintptr_t)pTargetBase + pSectionHeader->VirtualAddress);
				SIZE_T cur_size = pSectionHeader->Misc.VirtualSize;
				if (!NT_SUCCESS(NtProtectVirtualMemory(hProc, &cur_base, &cur_size, newP, &oldp)))
					return false;
			}
		}

		DWORD old = 0;
		SIZE_T cur_size = IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress;
		if (!NT_SUCCESS(NtProtectVirtualMemory(hProc, &pTargetBase, &cur_size, PAGE_READONLY, &old)))
			return false;
	}

	if (!NT_SUCCESS(NtWriteVirtualMemory(hProc, pShellCode, emptyBuffer, 0x1000, nullptr)))
		return false;

	//if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
	//	return false; // idk why its not freeing correctly xd

	//if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
	//	return false; // idk why its not freeing correctly xd


	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void __stdcall Shellcode(MANUAL_MAPPING_DATA_NEW* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	PVOID pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>((uintptr_t)pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = (BYTE*)pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((uintptr_t)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>((uintptr_t)pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>((uintptr_t)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>((uintptr_t)pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>((uintptr_t)pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>((uintptr_t)pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>((uintptr_t)pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>((uintptr_t)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>((uintptr_t)pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

bool CreateRemoteThreadUsingNtCreateThreadEx(HANDLE hProc, LPVOID pShellCode, LPVOID MappingDataAlloc) {
	NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll_base, skCrypt("NtCreateThreadEx"));
	pfnNtFreeVirtualMemory NtFreeVirtualMemory = (pfnNtFreeVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtFreeVirtualMemory"));
	pfnNtClose NtClose = (pfnNtClose)GetProcAddress(ntdll_base, skCrypt("NtClose"));

	if (!NtCreateThreadEx) {
		return false;
	}

	HANDLE hThread = NULL;
	NTSTATUS status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProc,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode),
		MappingDataAlloc,
		FALSE,
		0,
		0,
		0,
		nullptr
	);

	if (!NT_SUCCESS(status) || !hThread) {
		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	NtClose(hThread);
	return true;
}

bool InjectShellCode(HANDLE hProc, LPVOID pShellCode, LPVOID MappingDataAlloc, LPVOID pTargetBase) {
	if (!CreateRemoteThreadUsingNtCreateThreadEx(hProc, pShellCode, MappingDataAlloc)) {
		pfnNtFreeVirtualMemory NtFreeVirtualMemory = (pfnNtFreeVirtualMemory)GetProcAddress(ntdll_base, skCrypt("NtFreeVirtualMemory"));

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pTargetBase, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &MappingDataAlloc, 0, MEM_RELEASE)))
			return false;

		if (!NT_SUCCESS(NtFreeVirtualMemory(hProc, &pShellCode, 0, MEM_RELEASE)))
			return false;

		return false;
	}

	return true;
}

void* memset(void* dest, register int val, register size_t len)
{
	register unsigned char* ptr = (unsigned char*)dest;
	while (len-- > 0)
		*ptr++ = val;
	return dest;
}

int strcmp(const char* s1, const char* s2)
{
	int ret = 0;

	while (!(ret = *(unsigned char*)s1 - *(unsigned char*)s2) && *s2) ++s1, ++s2;

	if (ret < 0)

		ret = -1;
	else if (ret > 0)

		ret = 1;

	return ret;
}