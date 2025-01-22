#include "WinVisorDLL.h"

CpuStateStruct *CreateCpuState(WinVisorStartDataStruct *pWinVisorStartData)
{
	CpuStateStruct *pCpuState = NULL;

	// allocate cpu state object
	pCpuState = (CpuStateStruct*)VirtualAlloc(NULL, sizeof(CpuStateStruct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pCpuState == NULL)
	{
		WriteLog(LOG_ERROR, "Failed to allocate CPU state object");
		return NULL;
	}

	// prepare CPL3 state
	if(PrepareCPL3(pCpuState, pWinVisorStartData) != 0)
	{
		WriteLog(LOG_ERROR, "Failed to prepare user-mode entry environment");
		DeleteCpuState(pCpuState);
		return NULL;
	}

	// prepare CPL0 bootloader
	if(PrepareCPL0(pCpuState) != 0)
	{
		WriteLog(LOG_ERROR, "Failed to prepare bootloader");
		DeleteCpuState(pCpuState);
		return NULL;
	}

	return pCpuState;
}

DWORD DeleteCpuState(CpuStateStruct *pCpuState)
{
	if(pCpuState != NULL)
	{
		if(pCpuState->pCPL0_Stack != NULL)
		{
			// free memory
			VirtualFree(pCpuState->pCPL0_Stack, 0, MEM_RELEASE);
		}

		if(pCpuState->pCPL3_Stack != NULL)
		{
			// free memory
			VirtualFree(pCpuState->pCPL3_Stack, 0, MEM_RELEASE);
		}

		if(pCpuState->hHostThread != NULL)
		{
			// terminate thread
			TerminateThread(pCpuState->hHostThread, 0);
			CloseHandle(pCpuState->hHostThread);
		}

		if(pCpuState->hSyscallProxyReadyEvent != NULL)
		{
			// delete event object
			CloseHandle(pCpuState->hSyscallProxyReadyEvent);
		}

		if(pCpuState->hSyscallWaitingEvent != NULL)
		{
			// delete event object
			CloseHandle(pCpuState->hSyscallWaitingEvent);
		}

		if(pCpuState->hSyscallCompleteEvent != NULL)
		{
			// delete event object
			CloseHandle(pCpuState->hSyscallCompleteEvent);
		}

		// free main object
		VirtualFree(pCpuState, 0, MEM_RELEASE);
	}

	return 0;
}
