#include "WinVisorDLL.h"

DWORD GuestProcessExited(DWORD dwExitCode)
{
	WriteLog(LOG_INFO, "** Guest process exited with code: %u **", dwExitCode);
	dwGlobal_StopLog = 1;

	return 0;
}

DWORD SyscallHook_NtTerminateProcess(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue)
{
	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;

	// get params
	hProcess = (HANDLE)pSyscallInfo->qwParamList[0];
	dwExitCode = (DWORD)pSyscallInfo->qwParamList[1];

	// check if the current process is exiting
	if(hProcess == NULL || hProcess == GetCurrentProcess())
	{
		GuestProcessExited(dwExitCode);
		return 1;
	}

	return 0;
}
