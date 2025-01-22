#include "WinVisorDLL.h"

VOID *GetProcAddress_WoW64(VOID *pImageBase, char *pExportName)
{
	IMAGE_NT_HEADERS32 *pImageNtHeader32 = NULL;
	IMAGE_DATA_DIRECTORY *pExportDataDirectory = NULL;
	IMAGE_EXPORT_DIRECTORY *pExportHeader = NULL;
	char *pCurrExportName = NULL;
	WORD *pwAddressOfNameOrdinals = NULL;
	DWORD *pdwAddressOfNames = NULL;
	DWORD *pdwAddressOfFunctions = NULL;

	// get NT32 header
	pImageNtHeader32 = (IMAGE_NT_HEADERS32*)GetNtHeader(pImageBase);
	if(pImageNtHeader32 == NULL)
	{
		return NULL;
	}

	// get export directory
	pExportDataDirectory = &pImageNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if(pExportDataDirectory->VirtualAddress == 0 || pExportDataDirectory->Size == 0)
	{
		return NULL;
	}

	// get export directory
	pExportHeader = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pImageBase + pExportDataDirectory->VirtualAddress);
	if(pExportHeader == NULL)
	{
		return NULL;
	}

	// get export header virtual addresses
	pwAddressOfNameOrdinals = (WORD*)((BYTE*)pImageBase + pExportHeader->AddressOfNameOrdinals);
	pdwAddressOfNames = (DWORD*)((BYTE*)pImageBase + pExportHeader->AddressOfNames);
	pdwAddressOfFunctions = (DWORD*)((BYTE*)pImageBase + pExportHeader->AddressOfFunctions);

	// loop through all exports
	for(DWORD i = 0; i < pExportHeader->NumberOfNames; i++)
	{
		// get export name
		pCurrExportName = (char*)((BYTE*)pImageBase + pdwAddressOfNames[i]);
		if(strcmp(pCurrExportName, pExportName) == 0)
		{
			// found
			return (BYTE*)pImageBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]];
		}
	}

	// not found
	return NULL;
}

DWORD PopulateSyscallParamCounts(char *pModuleName, SyscallNameEntryStruct *pSyscallList, DWORD dwSyscallCount)
{
	char szSysWow64DirectoryPath[512];
	char szFullPath[512];
	BYTE *pEndOfSyscall = NULL;
	DWORD dwFound = 0;
	DWORD dwParamCount = 0;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	VOID *pMappedImage = NULL;
	VOID *pFuncAddr = NULL;

	// set initial values
	for(DWORD i = 0; i < dwSyscallCount; i++)
	{
		pSyscallList[i].dwParamCount = UNKNOWN_SYSCALL_PARAM_COUNT;
	}

	// get syswow64 directory
	memset(szSysWow64DirectoryPath, 0, sizeof(szSysWow64DirectoryPath));
	if(GetSystemWow64DirectoryA(szSysWow64DirectoryPath, sizeof(szSysWow64DirectoryPath) - 1) == 0)
	{
		return 1;
	}

	// open wow64 dll file
	memset(szFullPath, 0, sizeof(szFullPath));
	_snprintf(szFullPath, sizeof(szFullPath) - 1, "%s\\%s", szSysWow64DirectoryPath, pModuleName);
	hFile = CreateFileA(szFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// create section
	hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if(hSection == NULL)
	{
		CloseHandle(hFile);
		return 1;
	}

	// map section into memory
	pMappedImage = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
	if(pMappedImage == NULL)
	{
		CloseHandle(hSection);
		CloseHandle(hFile);
		return 1;
	}

	// populate param counts
	for(DWORD i = 0; i < dwSyscallCount; i++)
	{
		// find current function in wow64 module
		pFuncAddr = GetProcAddress_WoW64(pMappedImage, pSyscallList[i].szName);
		if(pFuncAddr == NULL)
		{
			continue;
		}

		// find end of syscall (ret / ret imm16).
		// the wow64 code uses callee-cleaned functions (stdcall) so we can use this to calculate the param count.
		// in most cases, the wow64 param count will match the native 64-bit functions.
		dwFound = 0;
		for(DWORD ii = 0; ii < 64; ii++)
		{
			pEndOfSyscall = (BYTE*)pFuncAddr + ii;

			// call edx
			if(*pEndOfSyscall == 0xFF && *(pEndOfSyscall + 1) == 0xD2)
			{
				if(*(pEndOfSyscall + 2) == 0xC2 && (*(pEndOfSyscall + 3) % 4) == 0 && *(pEndOfSyscall + 4) == 0)
				{
					// ret imm16
					dwParamCount = *(pEndOfSyscall + 3) / 4;
					dwFound = 1;
					break;
				}
				else if(*(pEndOfSyscall + 2) == 0xC3)
				{
					// ret
					dwParamCount = 0;
					dwFound = 1;
					break;
				}
			}
		}

		if(dwFound == 0)
		{
			// failed to find end of syscall
			continue;
		}

		// store param count
		pSyscallList[i].dwParamCount = dwParamCount;
	}

	// clean up
	UnmapViewOfFile(pMappedImage);
	CloseHandle(hSection);
	CloseHandle(hFile);

	return 0;
}
