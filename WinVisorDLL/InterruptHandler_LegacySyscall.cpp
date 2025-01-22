#include "WinVisorDLL.h"

DWORD InterruptHandler_LegacySyscall(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState)
{
	void *pUserStackPtr = NULL;

	// get user-mode RSP from kernel stack
	pUserStackPtr = (void*)*(UINT64*)(pCpuRegisterState->RSP + 0x18);

	// handle legacy syscall
	if(HandleGuestSyscall(pCpuState, pCpuRegisterState, pUserStackPtr) != 0)
	{
		return 1;
	}

	return 0;
}
