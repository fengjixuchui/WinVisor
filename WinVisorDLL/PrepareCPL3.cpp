#include "WinVisorDLL.h"

HMODULE hGlobal_ExeBase = NULL;

DWORD PrepareCPL3_FixExecutable(WinVisorStartDataStruct *pWinVisorStartData, VOID **ppEntryPoint)
{
	IMAGE_NT_HEADERS64 *pExeNtHeader = NULL;
	VOID *pEntryPoint = NULL;
	IMAGE_DATA_DIRECTORY *pExeDataDirectory = NULL;
	IMAGE_DATA_DIRECTORY *pOrigExeDataDirectory = NULL;
	DWORD dwOrigProtect = 0;

	// get entry-point for main executable
	pExeNtHeader = GetNtHeader(hGlobal_ExeBase);
	if(pExeNtHeader == NULL)
	{
		return 1;
	}
	pEntryPoint = (BYTE*)hGlobal_ExeBase + pExeNtHeader->OptionalHeader.AddressOfEntryPoint;

	// check if the "nx" command-line switch was specified
	if(pWinVisorStartData->qwWinVisorFlags & WINVISOR_FLAG_NX)
	{
		// remove executable flag from all pages within the exe image
		if(VirtualProtect(hGlobal_ExeBase, pExeNtHeader->OptionalHeader.SizeOfImage, PAGE_READWRITE, &dwOrigProtect) == 0)
		{
			return 1;
		}
	}

	// restore original entry-point code (this was temporarily overwritten by the WinVisor exe to load this DLL)
	if(CopyMemoryAndRestoreProtection(pEntryPoint, pWinVisorStartData->bOrigEntryPointCode, sizeof(pWinVisorStartData->bOrigEntryPointCode)) != 0)
	{
		return 1;
	}

	// restore import table data directory entry
	pExeDataDirectory = &pExeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pOrigExeDataDirectory = &pWinVisorStartData->OrigNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if(CopyMemoryAndRestoreProtection(pExeDataDirectory, pOrigExeDataDirectory, sizeof(IMAGE_DATA_DIRECTORY)) != 0)
	{
		return 1;
	}

	// restore TLS data directory entry
	pExeDataDirectory = &pExeNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pOrigExeDataDirectory = &pWinVisorStartData->OrigNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if(CopyMemoryAndRestoreProtection(pExeDataDirectory, pOrigExeDataDirectory, sizeof(IMAGE_DATA_DIRECTORY)) != 0)
	{
		return 1;
	}

	// store entry-point address
	*ppEntryPoint = pEntryPoint;

	return 0;
}

DWORD PrepareCPL3_GetHostThreadStackInfo(CpuStateStruct *pCpuState, VOID **ppStackAllocBase, DWORD *pdwTotalStackSize)
{
	NT_TIB *pTIB = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;
	DWORD dwTotalStackSize = 0;

	// calculate total stack size
	pTIB = (NT_TIB*)pCpuState->pHostThreadTEB;
	memset(&MemoryBasicInfo, 0, sizeof(MemoryBasicInfo));
	if(VirtualQuery(pTIB->StackLimit, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) != sizeof(MemoryBasicInfo))
	{
		return 1;
	}

	// calculate total stack size
	dwTotalStackSize = (DWORD)((UINT64)pTIB->StackBase - (UINT64)MemoryBasicInfo.AllocationBase);

	// store base/size
	*ppStackAllocBase = MemoryBasicInfo.AllocationBase;
	*pdwTotalStackSize = dwTotalStackSize;

	return 0;
}

DWORD PrepareCPL3_CreateHostThread(CpuStateStruct *pCpuState)
{
	THREAD_BASIC_INFORMATION ThreadBasicInfo;

	// create thread for virtual CPU (entry-point will be overwritten later)
	pCpuState->hHostThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread, (VOID*)0, CREATE_SUSPENDED, NULL);
	if(pCpuState->hHostThread == NULL)
	{
		return 1;
	}

	// get TEB base
	memset(&ThreadBasicInfo, 0, sizeof(ThreadBasicInfo));
	if(pNtQueryInformationThread(pCpuState->hHostThread, ThreadBasicInformation, &ThreadBasicInfo, sizeof(ThreadBasicInfo), NULL) != 0)
	{
		return 1;
	}

	// store TEB ptr
	pCpuState->pHostThreadTEB = ThreadBasicInfo.TebBaseAddress;

	return 0;
}

DWORD PrepareCPL3_StoreInitialGuestContext(CpuStateStruct *pCpuState, VOID *pEntryPoint)
{
	CONTEXT Context;
	VOID *pStackAllocBase = NULL;
	DWORD dwTotalStackSize = 0;

	// get stack base/size for the new thread
	if(PrepareCPL3_GetHostThreadStackInfo(pCpuState, &pStackAllocBase, &dwTotalStackSize) != 0)
	{
		return 1;
	}

	// get thread context
	memset(&Context, 0, sizeof(Context));
	Context.ContextFlags = CONTEXT_FULL;
	if(GetThreadContext(pCpuState->hHostThread, &Context) == 0)
	{
		return 1;
	}

	// create a second stack to allow code to be executed in real thread without interfering with guest
	pCpuState->pCPL3_Stack = VirtualAlloc(NULL, dwTotalStackSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pCpuState->pCPL3_Stack == NULL)
	{
		return 1;
	}

	// set initial CPL3 register values
	memset(&pCpuState->CPL3_InitialCpuRegisterState, 0, sizeof(pCpuState->CPL3_InitialCpuRegisterState));
	pCpuState->CPL3_InitialCpuRegisterState.RAX = Context.Rax;
	pCpuState->CPL3_InitialCpuRegisterState.RCX = Context.Rcx;
	pCpuState->CPL3_InitialCpuRegisterState.RDX = Context.Rdx;
	pCpuState->CPL3_InitialCpuRegisterState.RBX = Context.Rbx;
	pCpuState->CPL3_InitialCpuRegisterState.RSP = Context.Rsp;
	pCpuState->CPL3_InitialCpuRegisterState.RBP = Context.Rbp;
	pCpuState->CPL3_InitialCpuRegisterState.RSI = Context.Rsi;
	pCpuState->CPL3_InitialCpuRegisterState.RDI = Context.Rdi;
	pCpuState->CPL3_InitialCpuRegisterState.R8 = Context.R8;
	pCpuState->CPL3_InitialCpuRegisterState.R9 = Context.R9;
	pCpuState->CPL3_InitialCpuRegisterState.R10 = Context.R10;
	pCpuState->CPL3_InitialCpuRegisterState.R11 = Context.R11;
	pCpuState->CPL3_InitialCpuRegisterState.R12 = Context.R12;
	pCpuState->CPL3_InitialCpuRegisterState.R13 = Context.R13;
	pCpuState->CPL3_InitialCpuRegisterState.R14 = Context.R14;
	pCpuState->CPL3_InitialCpuRegisterState.R15 = Context.R15;
	pCpuState->CPL3_InitialCpuRegisterState.RIP = Context.Rip;
	pCpuState->CPL3_InitialCpuRegisterState.RFLAGS = Context.EFlags | EFLAGS_RESERVED_ALWAYS_ON;

	// update virtual CPU entry-point: HypervisorEntryPoint(pEntryPoint)
	pCpuState->CPL3_InitialCpuRegisterState.RCX = (UINT64)pEntryPoint;
	pCpuState->CPL3_InitialCpuRegisterState.RIP = (UINT64)HypervisorEntryPoint;

	// update guest stack ptr
	pCpuState->CPL3_InitialCpuRegisterState.RSP -= (UINT64)pStackAllocBase;
	pCpuState->CPL3_InitialCpuRegisterState.RSP += (UINT64)pCpuState->pCPL3_Stack;

	return 0;
}

DWORD PrepareCPL3_BeginSyscallProxyThread(CpuStateStruct *pCpuState)
{
	CONTEXT Context;

	// get thread context
	memset(&Context, 0, sizeof(Context));
	Context.ContextFlags = CONTEXT_FULL;
	if(GetThreadContext(pCpuState->hHostThread, &Context) == 0)
	{
		return 1;
	}

	// update the entry-point of the host thread to: SyscallProxyThread(pCpuState)
	Context.Rcx = (UINT64)SyscallProxyThread;
	Context.Rdx = (UINT64)pCpuState;
	if(SetThreadContext(pCpuState->hHostThread, &Context) == 0)
	{
		return 1;
	}

	// create hSyscallProxyReadyEvent event object
	pCpuState->hSyscallProxyReadyEvent = CreateEvent(NULL, 0, 0, NULL);
	if(pCpuState->hSyscallProxyReadyEvent == NULL)
	{
		return 1;
	}

	// create hSyscallWaitingEvent event object
	pCpuState->hSyscallWaitingEvent = CreateEvent(NULL, 0, 0, NULL);
	if(pCpuState->hSyscallWaitingEvent == NULL)
	{
		return 1;
	}

	// create hSyscallCompleteEvent event object
	pCpuState->hSyscallCompleteEvent = CreateEvent(NULL, 0, 0, NULL);
	if(pCpuState->hSyscallCompleteEvent == NULL)
	{
		return 1;
	}

	// begin syscall proxy thread and wait for the "ready" event to be triggered
	ResumeThread(pCpuState->hHostThread);
	WaitForSingleObject(pCpuState->hSyscallProxyReadyEvent, INFINITE);

	return 0;
}

DWORD PrepareCPL3(CpuStateStruct *pCpuState, WinVisorStartDataStruct *pWinVisorStartData)
{
	VOID *pEntryPoint = NULL;

	// store exe base
	hGlobal_ExeBase = GetModuleHandleA(NULL);

	// fix target executable - restore original entry-point, and optionally set all pages to non-executable
	if(PrepareCPL3_FixExecutable(pWinVisorStartData, &pEntryPoint) != 0)
	{
		return 1;
	}

	// create suspended host thread at the original entry-point
	if(PrepareCPL3_CreateHostThread(pCpuState) != 0)
	{
		return 1;
	}

	// copy the initial thread state into a temporary structure which will be used by the virtual cpu later, and allocate a new stack for the guest
	if(PrepareCPL3_StoreInitialGuestContext(pCpuState, pEntryPoint) != 0)
	{
		return 1;
	}

	// convert the host thread into a syscall proxy thread - this will be used to forward syscalls from the guest to the host.
	// using the same thread ensures that the TEB and any thread-specific behaviour will remain consistent with the guest.
	// as mentioned above, a second stack has been allocated for the guest to prevent it from interfering with the native host thread.
	if(PrepareCPL3_BeginSyscallProxyThread(pCpuState) != 0)
	{
		return 1;
	}

	return 0;
}
