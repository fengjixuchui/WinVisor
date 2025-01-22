#include "WinVisorDLL.h"

DWORD FixModuleImports_ProcessModule(VOID *pModuleBase, char *pModuleName, DWORD dwFirstThunkOffset)
{
	IMAGE_THUNK_DATA64 *pCurrThunkData64 = NULL;
	DWORD dwCurrThunkOffset = 0;
	DWORD dwOrdinal = 0;
	IMAGE_IMPORT_BY_NAME *pImageImportByName = NULL;
	DWORD dwVirtualAddress = 0;
	HMODULE hModule = NULL;
	VOID *pCurrResolvedAddr = NULL;
	UINT64 *pImportPtr = NULL;

	// load target library
	hModule = LoadLibraryA(pModuleName);
	if(hModule == NULL)
	{
		WriteLog(LOG_ERROR, "Failed to load DLL: %s", pModuleName);
		return 1;
	}

	// process module imports
	dwCurrThunkOffset = dwFirstThunkOffset;
	for(;;)
	{
		// get current thunk ptr
		pCurrThunkData64 = (IMAGE_THUNK_DATA64*)((BYTE*)pModuleBase + dwCurrThunkOffset);
		if(pCurrThunkData64->u1.AddressOfData == 0)
		{
			// finished
			break;
		}

		// get virtual address of import entry
		dwVirtualAddress = (DWORD)((BYTE*)&pCurrThunkData64->u1.Function - (BYTE*)pModuleBase);

		// check import type
		if(pCurrThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
		{
			// resolve import by ordinal
			dwOrdinal = (DWORD)(pCurrThunkData64->u1.Ordinal & 0xFFFF);
			pCurrResolvedAddr = GetProcAddress(hModule, (char*)((SIZE_T)dwOrdinal));
			if(pCurrResolvedAddr == NULL)
			{
				WriteLog(LOG_ERROR, "Failed to locate import entry: %s!#%u", pModuleName, dwOrdinal);
				return 1;
			}
		}
		else
		{
			// get imported function name
			pImageImportByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)pModuleBase + (DWORD)pCurrThunkData64->u1.AddressOfData);

			pCurrResolvedAddr = GetProcAddress(hModule, (char*)pImageImportByName->Name);
			if(pCurrResolvedAddr == NULL)
			{
				WriteLog(LOG_ERROR, "Failed to locate import entry: %s!#%s", pModuleName, (char*)pImageImportByName->Name);
				return 1;
			}
		}

		// update address
		pImportPtr = (UINT64*)((BYTE*)pModuleBase + dwVirtualAddress);
		if(CopyMemoryAndRestoreProtection(pImportPtr, &pCurrResolvedAddr, sizeof(pCurrResolvedAddr)) != 0)
		{
			return 1;
		}

		// update thunk offset
		dwCurrThunkOffset += sizeof(IMAGE_THUNK_DATA64);
	}

	return 0;
}

DWORD FixModuleImports(VOID *pModuleBase)
{
	IMAGE_NT_HEADERS64 *pImageNtHeader = NULL;
	IMAGE_DATA_DIRECTORY *pImportDirectory = NULL;
	DWORD dwCurrImportBlockOffset = 0;
	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor = NULL;
	char *pCurrModuleName = NULL;
	DWORD dwFirstThunkOffset = 0;

	pImageNtHeader = (IMAGE_NT_HEADERS64*)GetNtHeader((HMODULE)pModuleBase);
	if(pImageNtHeader == NULL)
	{
		return 1;
	}

	// check if this module contains an import directory
	pImportDirectory = &pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(pImportDirectory->VirtualAddress != 0 && pImportDirectory->Size != 0)
	{
		// process import table
		dwCurrImportBlockOffset = pImportDirectory->VirtualAddress;
		for(;;)
		{
			pImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)pModuleBase + dwCurrImportBlockOffset);
			if(pImageImportDescriptor->Name == 0)
			{
				// finished
				break;
			}

			// get current module name
			pCurrModuleName = (char*)((BYTE*)pModuleBase + pImageImportDescriptor->Name);

			// process the imports for the current module
			dwFirstThunkOffset = pImageImportDescriptor->FirstThunk;
			if(FixModuleImports_ProcessModule(pModuleBase, pCurrModuleName, dwFirstThunkOffset) != 0)
			{
				return 1;
			}

			// update import block offset
			dwCurrImportBlockOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
	}

	return 0;
}
