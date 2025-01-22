#include "WinVisorDLL.h"

DWORD InterruptHandler_SingleStep(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState)
{
	void *pUserInstructionPtr = NULL;

	// get user-mode RIP from kernel stack
	pUserInstructionPtr = (void*)*(UINT64*)(pCpuRegisterState->RSP);

	WriteLog(LOG_INFO, "Single-step: 0x%p", pUserInstructionPtr);

	return 0;
}
