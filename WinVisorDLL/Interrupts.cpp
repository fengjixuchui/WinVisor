#include "WinVisorDLL.h"

BYTE bGlobal_InterruptRet_ErrorCode[] =
{
	// (some interrupts push an error code onto the stack, this must be removed before returning)
	// add rsp, 8
	0x48, 0x83, 0xC4, 0x08,
	// iretq
	0x48, 0xCF
};

BYTE bGlobal_InterruptRet[] =
{
	// iretq
	0x48, 0xCF
};

InterruptHandlerEntryStruct Global_InterruptHandlerList[] =
{
	{ 0x01, InterruptHandler_SingleStep, 0 },
	{ 0x03, InterruptHandler_Breakpoint, 0 },
	{ 0x2E, InterruptHandler_LegacySyscall, 0 },
};

InterruptHandlerEntryStruct *GetInterruptHandler(BYTE bInterruptIndex)
{
	// find interrupt handler for this index
	for(DWORD i = 0; i < sizeof(Global_InterruptHandlerList) / sizeof(Global_InterruptHandlerList[0]); i++)
	{
		if(Global_InterruptHandlerList[i].bInterruptIndex == bInterruptIndex)
		{
			// found
			return &Global_InterruptHandlerList[i];
		}
	}

	// not found
	return NULL;
}

BYTE *GetInterruptReturn(InterruptHandlerEntryStruct *pInterruptHandlerEntry)
{
	if(pInterruptHandlerEntry->dwHasErrorCode != 0)
	{
		// this interrupt type has an error code - stack must be adjusted before returning
		return bGlobal_InterruptRet_ErrorCode;
	}

	// no error code
	return bGlobal_InterruptRet;
}
