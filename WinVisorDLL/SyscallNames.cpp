#include "WinVisorDLL.h"

SyscallNameEntryStruct *pGlobal_NtdllSyscallList = NULL;
DWORD dwGlobal_NtdllSyscallCount = 0;

SyscallNameEntryStruct *pGlobal_Win32uSyscallList = NULL;
DWORD dwGlobal_Win32uSyscallCount = 0;

int GenerateSyscallNameList_Compare(SyscallNameEntryStruct *pEntry1, SyscallNameEntryStruct *pEntry2)
{
	// compare virtual address values
	if(pEntry1->dwVirtualAddress > pEntry2->dwVirtualAddress)
	{
		return 1;
	}
	else if(pEntry1->dwVirtualAddress < pEntry2->dwVirtualAddress)
	{
		return -1;
	}

	return 0;
}

SyscallNameEntryStruct *GenerateSyscallNameList(HMODULE hModule, char *pExportNamePrefix, DWORD *pdwSyscallCount)
{
	IMAGE_NT_HEADERS *pImageNtHeader = NULL;
	IMAGE_DATA_DIRECTORY *pExportDataDirectory = NULL;
	IMAGE_EXPORT_DIRECTORY *pExportHeader = NULL;
	char *pExportName = NULL;
	WORD *pwAddressOfNameOrdinals = NULL;
	DWORD *pdwAddressOfNames = NULL;
	DWORD *pdwAddressOfFunctions = NULL;
	DWORD dwCount = 0;
	SyscallNameEntryStruct *pSyscallNameList = NULL;
	DWORD dwCurrIndex = 0;

	// get NT header for target module
	pImageNtHeader = GetNtHeader(hModule);
	if(pImageNtHeader == NULL)
	{
		return NULL;
	}

	// get export directory
	pExportDataDirectory = &pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if(pExportDataDirectory->VirtualAddress == 0 || pExportDataDirectory->Size == 0)
	{
		return NULL;
	}

	// get export directory
	pExportHeader = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + pExportDataDirectory->VirtualAddress);
	if(pExportHeader == NULL)
	{
		return NULL;
	}

	// get export header virtual addresses
	pwAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportHeader->AddressOfNameOrdinals);
	pdwAddressOfNames = (DWORD*)((BYTE*)hModule + pExportHeader->AddressOfNames);
	pdwAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportHeader->AddressOfFunctions);

	// loop through all exports
	for(DWORD i = 0; i < pExportHeader->NumberOfNames; i++)
	{
		// get export name
		pExportName = (char*)((BYTE*)hModule + pdwAddressOfNames[i]);
		if(strncmp(pExportName, pExportNamePrefix, strlen(pExportNamePrefix)) != 0)
		{
			continue;
		}

		// increase count
		dwCount++;
	}

	// allocate list
	pSyscallNameList = (SyscallNameEntryStruct*)VirtualAlloc(NULL, dwCount * sizeof(SyscallNameEntryStruct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pSyscallNameList == NULL)
	{
		return NULL;
	}

	// copy export names to list
	dwCurrIndex = 0;
	for(DWORD i = 0; i < pExportHeader->NumberOfNames; i++)
	{
		// get export name
		pExportName = (char*)((BYTE*)hModule + pdwAddressOfNames[i]);
		if(strncmp(pExportName, pExportNamePrefix, strlen(pExportNamePrefix)) != 0)
		{
			continue;
		}

		// store syscall name
		memset(&pSyscallNameList[dwCurrIndex], 0, sizeof(SyscallNameEntryStruct));
		strncpy(pSyscallNameList[dwCurrIndex].szName, pExportName, sizeof(pSyscallNameList[dwCurrIndex].szName) - 1);
		pSyscallNameList[dwCurrIndex].dwVirtualAddress = pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]];

		// fix syscall name (Zw - > Nt)
		pSyscallNameList[dwCurrIndex].szName[0] = 'N';
		pSyscallNameList[dwCurrIndex].szName[1] = 't';

		dwCurrIndex++;
	}

	// sort list by virtual address
	qsort(pSyscallNameList, dwCount, sizeof(SyscallNameEntryStruct), (int(*)(const void*,const void*))GenerateSyscallNameList_Compare);

	// store count
	*pdwSyscallCount = dwCount;

	return pSyscallNameList;
}

DWORD CreateSyscallLists()
{
	HMODULE hWin32u = NULL;

	// generate syscall name list for ntdll.dll (use "Zw" prefix to filter out non-syscalls such as NtdllDefWindowProc_A)
	pGlobal_NtdllSyscallList = GenerateSyscallNameList(hGlobal_NtdllBase, "Zw", &dwGlobal_NtdllSyscallCount);
	if(pGlobal_NtdllSyscallList == NULL)
	{
		DeleteSyscallLists();
		return 1;
	}

	// temporarily load win32u.dll
	hWin32u = LoadLibraryA("win32u.dll");
	if(hWin32u == NULL)
	{
		DeleteSyscallLists();
		return 1;
	}

	// generate syscall name list for win32u
	pGlobal_Win32uSyscallList = GenerateSyscallNameList(hWin32u, "Nt", &dwGlobal_Win32uSyscallCount);
	if(pGlobal_Win32uSyscallList == NULL)
	{
		FreeLibrary(hWin32u);
		DeleteSyscallLists();
		return 1;
	}

	// unload win32u.dll
	FreeLibrary(hWin32u);

	// attempt to populate param counts via wow64 - don't check for errors here, these param counts are used for display purposes only
	PopulateSyscallParamCounts("ntdll.dll", pGlobal_NtdllSyscallList, dwGlobal_NtdllSyscallCount);
	PopulateSyscallParamCounts("win32u.dll", pGlobal_Win32uSyscallList, dwGlobal_Win32uSyscallCount);

	return 0;
}

DWORD DeleteSyscallLists()
{
	if(pGlobal_NtdllSyscallList != NULL)
	{
		// free memory
		VirtualFree(pGlobal_NtdllSyscallList, 0, MEM_RELEASE);
	}

	if(pGlobal_Win32uSyscallList != NULL)
	{
		// free memory
		VirtualFree(pGlobal_Win32uSyscallList, 0, MEM_RELEASE);
	}

	return 0;
}

char *GetSyscallName(DWORD dwSyscallIndex, DWORD *pdwParamCount)
{
	DWORD dwTableIndex = 0;
	DWORD dwEntryIndex = 0;
	SyscallNameEntryStruct *pSyscallEntry = NULL;

	// extract table and entry index from syscall number
	dwTableIndex = (dwSyscallIndex >> 12) & 0x3;
	dwEntryIndex = dwSyscallIndex & 0xFFF;

	if(dwTableIndex == 0)
	{
		// ntdll / ntoskrnl
		if(dwEntryIndex >= dwGlobal_NtdllSyscallCount)
		{
			return NULL;
		}

		pSyscallEntry = &pGlobal_NtdllSyscallList[dwEntryIndex];
	}
	else if(dwTableIndex == 1)
	{
		// win32u / win32k
		if(dwEntryIndex >= dwGlobal_Win32uSyscallCount)
		{
			return NULL;
		}

		pSyscallEntry = &pGlobal_Win32uSyscallList[dwEntryIndex];
	}
	else
	{
		// invalid table index
		return NULL;
	}

	if(pdwParamCount != NULL)
	{
		// store param count (optional)
		*pdwParamCount = pSyscallEntry->dwParamCount;
	}

	return pSyscallEntry->szName;
}
