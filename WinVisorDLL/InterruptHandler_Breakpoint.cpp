#include "WinVisorDLL.h"

DWORD InterruptHandler_Breakpoint(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState)
{
	// software breakpoint - skip over and continue
	WriteLog(LOG_INFO, "Caught breakpoint");

	return 0;
}
