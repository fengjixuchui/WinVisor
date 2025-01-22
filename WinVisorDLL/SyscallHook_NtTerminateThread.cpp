#include "WinVisorDLL.h"

DWORD SyscallHook_NtTerminateThread(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue)
{
	HANDLE hThread = NULL;
	DWORD dwExitCode = 0;

	// get params
	hThread = (HANDLE)pSyscallInfo->qwParamList[0];
	dwExitCode = (DWORD)pSyscallInfo->qwParamList[1];

	// check if the current thread is exiting
	if(hThread == NULL || hThread == GetCurrentThread())
	{
		// current thread is exiting - treat this as a process exit because winvisor currently only supports a single thread
		GuestProcessExited(dwExitCode);
		return 1;
	}

	return 0;
}
