#include "WinVisorDLL.h"

DWORD gdwLoadedModuleImports = 0;

DWORD ExecuteTlsCallbacks(VOID *pModuleBase)
{
	IMAGE_NT_HEADERS64 *pImageNtHeader = NULL;
	IMAGE_DATA_DIRECTORY *pTlsDirectory = NULL;
	IMAGE_TLS_DIRECTORY *pImageTlsDirectory = NULL;
	UINT64 *pqwCurrCallbackEntry = NULL;

	pImageNtHeader = (IMAGE_NT_HEADERS64*)GetNtHeader((HMODULE)pModuleBase);
	if(pImageNtHeader == NULL)
	{
		return 1;
	}

	// check if this module contains a TLS directory
	pTlsDirectory = &pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if(pTlsDirectory->VirtualAddress != 0 && pTlsDirectory->Size != 0)
	{
		pImageTlsDirectory = (IMAGE_TLS_DIRECTORY*)((BYTE*)pModuleBase + pTlsDirectory->VirtualAddress);
		if(pImageTlsDirectory->AddressOfCallBacks != 0)
		{
			// execute all callbacks
			pqwCurrCallbackEntry = (UINT64*)pImageTlsDirectory->AddressOfCallBacks;
			for(;;)
			{
				if(*pqwCurrCallbackEntry == 0)
				{
					// end of list
					break;
				}

				// execute current callback function
				((PIMAGE_TLS_CALLBACK)*pqwCurrCallbackEntry)(pModuleBase, DLL_PROCESS_ATTACH, NULL);

				// move to next entry
				pqwCurrCallbackEntry++;
			}
		}
	}

	return 0;
}

DWORD HypervisorEntryPoint_StartExe(VOID *pExeEntryPoint, DWORD *pdwExitCode)
{
	DWORD dwExitCode = 0;

	// load EXE imports
	if(FixModuleImports(ghExeBase) != 0)
	{
		return 1;
	}

	// loaded imports - set flag for logging purposes
	gdwLoadedModuleImports = 1;

	// execute TLS callbacks
	if(ExecuteTlsCallbacks(ghExeBase) != 0)
	{
		return 1;
	}

	// execute original entry-point
	dwExitCode = ((DWORD(*)(VOID*))pExeEntryPoint)((VOID*)__readgsqword(0x60));

	// store exit code
	*pdwExitCode = dwExitCode;

	return 0;
}

DWORD HypervisorEntryPoint(VOID *pExeEntryPoint)
{
	DWORD dwExitCode = 0;

	// start exe
	HypervisorEntryPoint_StartExe(pExeEntryPoint, &dwExitCode);

	// ensure the current thread is terminated after the entry-point returns
	TerminateThread(GetCurrentThread(), dwExitCode);

	return 0;
}
