#include "WinVisorDLL.h"

DWORD HandlePageFault_CheckSpecialAddress(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, DWORD *pdwHandled)
{
	DWORD dwHandled = 0;
	BYTE bInterruptIndex = 0;
	InterruptHandlerEntryStruct *pInterruptHandler = NULL;

	// check if the page-fault occurred on a special address
	dwHandled = 1;
	if(pCpuRegisterState->RIP == SYSCALL_VIRTUAL_ADDRESS)
	{
		// syscall instruction
		if(HandleSyscallInstruction(pCpuState, pCpuRegisterState) != 0)
		{
			WriteLog(LOG_ERROR, "Failed to handle syscall");
			return 1;
		}
	}
	else if(pCpuRegisterState->RIP == CPL3_ENTRY_VIRTUAL_ADDRESS)
	{
		WriteLog(LOG_INFO, "Bootloader complete, transitioning to CPL3...");

		// copy CPL3 entry context
		memcpy((void*)pCpuRegisterState, (void*)&pCpuState->CPL3_InitialCpuRegisterState, sizeof(pCpuState->CPL3_InitialCpuRegisterState));
	}
	else if((pCpuRegisterState->RIP >= INTERRUPT_HANDLER_VIRTUAL_ADDRESS) && (pCpuRegisterState->RIP < (INTERRUPT_HANDLER_VIRTUAL_ADDRESS + MAX_IDT_ENTRY_COUNT)))
	{
		// find interrupt handler
		bInterruptIndex = (BYTE)(pCpuRegisterState->RIP - INTERRUPT_HANDLER_VIRTUAL_ADDRESS);
		pInterruptHandler = GetInterruptHandler(bInterruptIndex);
		if(pInterruptHandler == NULL)
		{
			WriteLog(LOG_ERROR, "Unhandled interrupt: 0x%02X", bInterruptIndex);
			return 1;
		}

		// execute handler
		if(pInterruptHandler->pHandler(pCpuState, pCpuRegisterState) != 0)
		{
			WriteLog(LOG_ERROR, "Interrupt handler error: 0x%02X", bInterruptIndex);
			return 1;
		}

		// return from interrupt
		pCpuRegisterState->RIP = (UINT64)GetInterruptReturn(pInterruptHandler);
	}
	else
	{
		// not handled
		dwHandled = 0;
	}

	*pdwHandled = dwHandled;

	return 0;
}

DWORD HandlePageFault(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, UINT64 qwVirtualAddress)
{
	DWORD dwHandled = 0;

	// check if this is a special (reserved) address
	if(HandlePageFault_CheckSpecialAddress(pCpuState, pCpuRegisterState, &dwHandled) != 0)
	{
		return 1;
	}

	// if not, treat this as a standard page-fault and attempt to page it into memory
	if(dwHandled == 0)
	{
		// WHvMapGpaRange allows an invalid virtual address to be mapped into the guest without any errors - it will only throw an error when it attempts to read from it later.
		// manually validate the target address within the current process first - this makes it easier to debug.
		if(ValidateReadPointer((void*)qwVirtualAddress, 1) != 0)
		{
			WriteLog(LOG_ERROR, "Attempt to access invalid virtual address: 0x%p (RIP: 0x%p)", qwVirtualAddress, pCpuRegisterState->RIP);
			return 1;
		}

		WriteLog(LOG_DEBUG, "Caught page fault: 0x%p (RIP: 0x%p)", qwVirtualAddress, pCpuRegisterState->RIP);	

		// add this page to the mapped page table
		if(AddPagedVirtualAddress(qwVirtualAddress) != 0)
		{
			WriteLog(LOG_ERROR, "Failed to add paged virtual address: 0x%p (RIP: 0x%p)", qwVirtualAddress, pCpuRegisterState->RIP);
			return 1;
		}
	}
	
	return 0;
}
