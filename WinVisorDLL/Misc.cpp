#include "WinVisorDLL.h"

IMAGE_NT_HEADERS *GetNtHeader(VOID *pModuleBase)
{
	IMAGE_DOS_HEADER *pImageDosHeader = NULL;
	IMAGE_NT_HEADERS *pImageNtHeader = NULL;

	// get dos header
	pImageDosHeader = (IMAGE_DOS_HEADER*)pModuleBase;
	if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	// get nt header
	pImageNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)pModuleBase + pImageDosHeader->e_lfanew);
	if(pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	return pImageNtHeader;
}

DWORD ValidateReadPointer(VOID *pAddress, SIZE_T dwLength)
{
	BYTE *pCurrPtr = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;

	pCurrPtr = (BYTE*)pAddress;
	for(SIZE_T i = 0; i < dwLength; i++)
	{
		if(i == 0 || ((UINT64)pCurrPtr % PAGE_SIZE) == 0)
		{
			memset(&MemoryBasicInfo, 0, sizeof(MemoryBasicInfo));
			if(VirtualQuery(pCurrPtr, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) != sizeof(MemoryBasicInfo))
			{
				return 1;
			}

			if(MemoryBasicInfo.State != MEM_COMMIT)
			{
				return 1;
			}

			if(MemoryBasicInfo.Protect & PAGE_NOACCESS)
			{
				return 1;
			}

			if(MemoryBasicInfo.Protect & PAGE_GUARD)
			{
				return 1;
			}
		}

		pCurrPtr++;
	}

	return 0;
}

DWORD CopyMemoryAndRestoreProtection(VOID *pDestination, VOID *pSource, DWORD dwLength)
{
	DWORD dwOrigProtect = 0;

	// make region writable
	if(VirtualProtect(pDestination, dwLength, PAGE_READWRITE, &dwOrigProtect) == 0)
	{
		return 1;
	}

	// copy data
	memcpy(pDestination, pSource, dwLength);

	// restore original protection
	if(VirtualProtect(pDestination, dwLength, dwOrigProtect, &dwOrigProtect) == 0)
	{
		return 1;
	}

	return 0;
}

DWORD AppendString(char *pString, SIZE_T dwMaxLength, char *pAppend)
{
	SIZE_T dwOrigLength = 0;
	SIZE_T dwAppendLength = 0;
	SIZE_T dwNewLength = 0;

	// get lengths
	dwOrigLength = strlen(pString);
	dwAppendLength = strlen(pAppend);

	// validate new length
	dwNewLength = dwOrigLength + dwAppendLength;
	if(dwNewLength > dwMaxLength)
	{
		return 1;
	}

	// append data
	memcpy((pString + dwOrigLength), pAppend, dwAppendLength);

	// add null terminator if the buffer is not full.
	// if the maximum length has been reached, it isn't necessary to add a null-terminator.
	// it is assumed that the maximum specified length is [sizeof(buffer)-1] and the final character is already a null.
	if(dwNewLength != dwMaxLength)
	{
		*(BYTE*)((BYTE*)pString + dwNewLength) = '\0';
	}

	return 0;
}

DWORD ExecXGETBV(DWORD dwIndex, QWORD *pqwReturnValue)
{
	VOID *pCode = NULL;
	UINT64 qwReturnValue = 0;
	BYTE bXGETBV[] =
	{
		// xgetbv
		0x0F, 0x01, 0xD0,
		// shl rdx, 0x20
		0x48, 0xC1, 0xE2, 0x20,
		// add rdx, rax
		0x48, 0x01, 0xC2,
		// mov rax, rdx
		0x48, 0x89, 0xD0,
		// ret
		0xC3
	};

	// allocate code
	pCode = VirtualAlloc(NULL, sizeof(bXGETBV), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pCode == NULL)
	{
		return 1;
	}

	// execute syscall
	memcpy(pCode, bXGETBV, sizeof(bXGETBV));
	qwReturnValue = ((UINT64(*)(DWORD))pCode)(dwIndex);

	// free temporary memory
	VirtualFree(pCode, 0, MEM_RELEASE);

	// store return value
	*pqwReturnValue = qwReturnValue;

	return 0;
}
