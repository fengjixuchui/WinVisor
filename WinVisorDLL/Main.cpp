#include "WinVisorDLL.h"

#ifndef _WIN64
#error Must be compiled as 64-bit
#endif

HMODULE hGlobal_NtdllBase = NULL;
DWORD (WINAPI *pNtQueryInformationThread)(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) = NULL;
DWORD (WINAPI *pNtQuerySystemInformation)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) = NULL;

DWORD StartHypervisor_Initialise(WinVisorStartDataStruct *pWinVisorStartData, CpuStateStruct **ppCpuState)
{
	CpuStateStruct *pCpuState = NULL;

	// check if the "debug" command-line switch was specified
	if(pWinVisorStartData->qwWinVisorFlags & WINVISOR_FLAG_DEBUG_LOG)
	{
		dwGlobal_DebugLogEnabled = 1;
	}

	// check if the "imports" command-line switch was specified
	if(pWinVisorStartData->qwWinVisorFlags & WINVISOR_FLAG_IMPORTS)
	{
		dwGlobal_LogImportSyscallsEnabled = 1;
	}

	// get ntdll base
	hGlobal_NtdllBase = GetModuleHandleA("ntdll.dll");

	// get NtQueryInformationThread ptr
	pNtQueryInformationThread = (DWORD(WINAPI*)(HANDLE,DWORD,PVOID,ULONG,PULONG))GetProcAddress(hGlobal_NtdllBase, "NtQueryInformationThread");
	if(pNtQueryInformationThread == NULL)
	{
		return 1;
	}

	// get NtQuerySystemInformation ptr
	pNtQuerySystemInformation = (DWORD(WINAPI*)(DWORD,PVOID,ULONG,PULONG))GetProcAddress(hGlobal_NtdllBase, "NtQuerySystemInformation");
	if(pNtQuerySystemInformation == NULL)
	{
		return 1;
	}

	// initialise log pipe
	if(InitialiseLogServer() != 0)
	{
		return 1;
	}

	WriteLog(LOG_INFO, "Starting...");

	// initialise hypervisor platform api
	if(HypervisorUtils_Initialise() != 0)
	{
		WriteLog(LOG_ERROR, "Failed to initialise Windows Hypervisor Platform API");
		return 1;
	}

	// initialise virtual CPU
	if(HypervisorUtils_CreateEnvironment() != 0)
	{
		WriteLog(LOG_ERROR, "Failed to create hypervisor environment");
		return 1;
	}

	// populate list of syscall names / param counts
	if(CreateSyscallLists() != 0)
	{
		WriteLog(LOG_ERROR, "Failed to create syscall lists");
		return 1;
	}

	// allocate page tables
	if(CreatePageTables() != 0)
	{
		WriteLog(LOG_ERROR, "Failed to create page tables");
		return 1;
	}

	// prepare environment
	pCpuState = CreateCpuState(pWinVisorStartData);
	if(pCpuState == NULL)
	{
		WriteLog(LOG_ERROR, "Failed to create initial CPU state");
		return 1;
	}

	// store cpu state object ptr
	*ppCpuState = pCpuState;

	return 0;
}

DWORD StartHypervisor_Cleanup(CpuStateStruct *pCpuState, DWORD dwIgnoreHypervisorEnvironment)
{
	// clean up - all of these functions must succeed even if they haven't yet been initialised
	DeleteCpuState(pCpuState);
	DeletePageTables();
	DeleteSyscallLists();
	if(dwIgnoreHypervisorEnvironment == 0)
	{
		HypervisorUtils_DeleteEnvironment();
	}
	CloseLogServer();

	return 0;
}

extern "C" __declspec(dllexport) DWORD StartHypervisor(WinVisorStartDataStruct *pWinVisorStartData)
{
	CpuStateStruct *pCpuState = NULL;
	CpuRegisterStateStruct CpuRegisterState;
	WHV_RUN_VP_EXIT_CONTEXT VmExitContext;

	// initialise hypervisor
	if(StartHypervisor_Initialise(pWinVisorStartData, &pCpuState) != 0)
	{
		WriteLog(LOG_ERROR, "Failed to start hypervisor");
		StartHypervisor_Cleanup(NULL, 0);
		return 1;
	}

	// begin execution
	WriteLog(LOG_INFO, "Launching virtual CPU...");
	for(;;)
	{
		// resume virtual CPU
		memset(&VmExitContext, 0, sizeof(VmExitContext));
		if(HypervisorUtils_ResumeExecution(&VmExitContext) != 0)
		{
			// error
			break;
		}

		// caught vmexit - get register values
		HypervisorUtils_GetRegisters(&CpuRegisterState);

		// handle vmexit
		if(HandleVmExit(pCpuState, &CpuRegisterState, &VmExitContext) != 0)
		{
			// error (or guest process exited)
			break;
		}

		// update register values
		HypervisorUtils_SetRegisters(&CpuRegisterState);
	}

	// clean up - HypervisorUtils_DeleteEnvironment is intentionally skipped here.
	// the guest process may have left the CRT in an unknown state after exiting which can lead to deadlocks within the hypervisor platform module.
	// clean up local objects and then terminate the process immediately to prevent any potential issues.
	StartHypervisor_Cleanup(pCpuState, 1);
	TerminateProcess(GetCurrentProcess(), 0);

	return 0;
}
