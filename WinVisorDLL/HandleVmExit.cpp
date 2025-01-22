#include "WinVisorDLL.h"

DWORD HandleVmExit(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, WHV_RUN_VP_EXIT_CONTEXT *pVmExitContext)
{
	// check vmexit reason
	if(pVmExitContext->ExitReason == WHvRunVpExitReasonMemoryAccess)
	{
		// invalid memory access
		WriteLog(LOG_ERROR, "Invalid physical memory access at 0x%p (RIP: 0x%p)", pVmExitContext->MemoryAccess.Gpa, pCpuRegisterState->RIP);
		return 1;
	}
	else if(pVmExitContext->ExitReason == WHvRunVpExitReasonException)
	{
		// exception
		if(pVmExitContext->VpException.ExceptionType == WHvX64ExceptionTypePageFault)
		{
			// page fault
			if(HandlePageFault(pCpuState, pCpuRegisterState, pVmExitContext->VpException.ExceptionParameter) != 0)
			{
				WriteLog(LOG_ERROR, "Failed to handle page fault (RIP: 0x%p)", pCpuRegisterState->RIP);
				return 1;
			}
		}
		else if(pVmExitContext->VpException.ExceptionType == WHvX64ExceptionTypeGeneralProtectionFault)
		{
			// general protection fault
			WriteLog(LOG_ERROR, "General protection fault (RIP: 0x%p)", pCpuRegisterState->RIP);
			return 1;
		}
		else
		{
			// unknown type
			WriteLog(LOG_ERROR, "Unhandled exception type: 0x%02X (RIP: 0x%p)", pVmExitContext->VpException.ExceptionType, pCpuRegisterState->RIP);
			return 1;
		}
	}
	else
	{
		// unknown vmexit reason
		WriteLog(LOG_ERROR, "Unhandled VmExit reason: 0x%08X (RIP: 0x%p)", pVmExitContext->ExitReason, pCpuRegisterState->RIP);
		return 1;
	}

	return 0;
}