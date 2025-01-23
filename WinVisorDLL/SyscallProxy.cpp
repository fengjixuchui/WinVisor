#include "WinVisorDLL.h"

DWORD gdwLogImportSyscallsEnabled = 0;

SyscallHookEntryStruct gSyscallHookList[] =
{
	{ "NtTerminateThread", SyscallHook_NtTerminateThread },
	{ "NtTerminateProcess", SyscallHook_NtTerminateProcess },
};

BYTE gbSysRet[] =
{
	// sysret
	0x48, 0x0F, 0x07
};

DWORD ExecuteSyscall(SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue)
{
	VOID *pCode = NULL;
	UINT64 qwReturnValue = 0;
	BYTE bSyscallCode[] =
	{
		// sub rsp, 0x118
		0x48, 0x81, 0xEC, 0x18, 0x01, 0x00, 0x00,
		// mov rax, <PARAM_32>
		0x48, 0xB8, 0x28, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xF8], rax
		0x48, 0x89, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_31>
		0x48, 0xB8, 0x27, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xF0], rax
		0x48, 0x89, 0x84, 0x24, 0xF0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_30>
		0x48, 0xB8, 0x26, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xE8], rax
		0x48, 0x89, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_29>
		0x48, 0xB8, 0x25, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xE0], rax
		0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_28>
		0x48, 0xB8, 0x24, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xD8], rax
		0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_27>
		0x48, 0xB8, 0x23, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xD0], rax
		0x48, 0x89, 0x84, 0x24, 0xD0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_26>
		0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xC8], rax
		0x48, 0x89, 0x84, 0x24, 0xC8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_25>
		0x48, 0xB8, 0x21, 0x22, 0x22, 0x22, 0x04, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xC0], rax
		0x48, 0x89, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_24>
		0x48, 0xB8, 0x18, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xB8], rax
		0x48, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_23>
		0x48, 0xB8, 0x17, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xB0], rax
		0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_22>
		0x48, 0xB8, 0x16, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xA8], rax
		0x48, 0x89, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_21>
		0x48, 0xB8, 0x15, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0xA0], rax
		0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_20>
		0x48, 0xB8, 0x14, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x98], rax
		0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_19>
		0x48, 0xB8, 0x13, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x90], rax
		0x48, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_18>
		0x48, 0xB8, 0x12, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x88], rax
		0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_17>
		0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x03, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x80], rax
		0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,
		// mov rax, <PARAM_16>
		0x48, 0xB8, 0x28, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x78], rax
		0x48, 0x89, 0x44, 0x24, 0x78,
		// mov rax, <PARAM_15>
		0x48, 0xB8, 0x27, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x70], rax
		0x48, 0x89, 0x44, 0x24, 0x70,
		// mov rax, <PARAM_14>
		0x48, 0xB8, 0x26, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x68], rax
		0x48, 0x89, 0x44, 0x24, 0x68,
		// mov rax, <PARAM_13>
		0x48, 0xB8, 0x25, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x60], rax
		0x48, 0x89, 0x44, 0x24, 0x60,
		// mov rax, <PARAM_12>
		0x48, 0xB8, 0x24, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x58], rax
		0x48, 0x89, 0x44, 0x24, 0x58,
		// mov rax, <PARAM_11>
		0x48, 0xB8, 0x23, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x50], rax
		0x48, 0x89, 0x44, 0x24, 0x50,
		// mov rax, <PARAM_10>
		0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x48], rax
		0x48, 0x89, 0x44, 0x24, 0x48,
		// mov rax, <PARAM_9>
		0x48, 0xB8, 0x21, 0x22, 0x22, 0x22, 0x02, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x40], rax
		0x48, 0x89, 0x44, 0x24, 0x40,
		// mov rax, <PARAM_8>
		0x48, 0xB8, 0x18, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x38], rax
		0x48, 0x89, 0x44, 0x24, 0x38,
		// mov rax, <PARAM_7>
		0x48, 0xB8, 0x17, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x30], rax
		0x48, 0x89, 0x44, 0x24, 0x30,
		// mov rax, <PARAM_6>
		0x48, 0xB8, 0x16, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x28], rax
		0x48, 0x89, 0x44, 0x24, 0x28,
		// mov rax, <PARAM_5>
		0x48, 0xB8, 0x15, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov qword ptr [rsp+0x20], rax
		0x48, 0x89, 0x44, 0x24, 0x20,
		// mov r9, <PARAM_4>
		0x49, 0xB9, 0x14, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov r8, <PARAM_3>
		0x49, 0xB8, 0x13, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov rdx, <PARAM_2>
		0x48, 0xBA, 0x12, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// mov rcx, <PARAM_1>
		0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00,
		// call SYSCALL_STUB
		0xE8, 0x08, 0x00, 0x00, 0x00,
		// add rsp, 0x118
		0x48, 0x81, 0xC4, 0x18, 0x01, 0x00, 0x00,
		// ret
		0xC3,
		// SYSCALL_STUB:
		// mov r10, rcx
		0x49, 0x89, 0xCA,
		// mov eax, <SYSCALL_INDEX>
		0xB8, 0xF6, 0x00, 0x00, 0x00,
		// syscall
		0x0F, 0x05,
		// ret
		0xC3
	};

	// set syscall index
	*(DWORD*)&bSyscallCode[532] = pSyscallInfo->dwSyscallIndex;

	// set syscall param values
	*(UINT64*)&bSyscallCode[9] = pSyscallInfo->qwParamList[31];
	*(UINT64*)&bSyscallCode[27] = pSyscallInfo->qwParamList[30];
	*(UINT64*)&bSyscallCode[45] = pSyscallInfo->qwParamList[29];
	*(UINT64*)&bSyscallCode[63] = pSyscallInfo->qwParamList[28];
	*(UINT64*)&bSyscallCode[81] = pSyscallInfo->qwParamList[27];
	*(UINT64*)&bSyscallCode[99] = pSyscallInfo->qwParamList[26];
	*(UINT64*)&bSyscallCode[117] = pSyscallInfo->qwParamList[25];
	*(UINT64*)&bSyscallCode[135] = pSyscallInfo->qwParamList[24];
	*(UINT64*)&bSyscallCode[153] = pSyscallInfo->qwParamList[23];
	*(UINT64*)&bSyscallCode[171] = pSyscallInfo->qwParamList[22];
	*(UINT64*)&bSyscallCode[189] = pSyscallInfo->qwParamList[21];
	*(UINT64*)&bSyscallCode[207] = pSyscallInfo->qwParamList[20];
	*(UINT64*)&bSyscallCode[225] = pSyscallInfo->qwParamList[19];
	*(UINT64*)&bSyscallCode[243] = pSyscallInfo->qwParamList[18];
	*(UINT64*)&bSyscallCode[261] = pSyscallInfo->qwParamList[17];
	*(UINT64*)&bSyscallCode[279] = pSyscallInfo->qwParamList[16];
	*(UINT64*)&bSyscallCode[297] = pSyscallInfo->qwParamList[15];
	*(UINT64*)&bSyscallCode[312] = pSyscallInfo->qwParamList[14];
	*(UINT64*)&bSyscallCode[327] = pSyscallInfo->qwParamList[13];
	*(UINT64*)&bSyscallCode[342] = pSyscallInfo->qwParamList[12];
	*(UINT64*)&bSyscallCode[357] = pSyscallInfo->qwParamList[11];
	*(UINT64*)&bSyscallCode[372] = pSyscallInfo->qwParamList[10];
	*(UINT64*)&bSyscallCode[387] = pSyscallInfo->qwParamList[9];
	*(UINT64*)&bSyscallCode[402] = pSyscallInfo->qwParamList[8];
	*(UINT64*)&bSyscallCode[417] = pSyscallInfo->qwParamList[7];
	*(UINT64*)&bSyscallCode[432] = pSyscallInfo->qwParamList[6];
	*(UINT64*)&bSyscallCode[447] = pSyscallInfo->qwParamList[5];
	*(UINT64*)&bSyscallCode[462] = pSyscallInfo->qwParamList[4];
	*(UINT64*)&bSyscallCode[477] = pSyscallInfo->qwParamList[3];
	*(UINT64*)&bSyscallCode[487] = pSyscallInfo->qwParamList[2];
	*(UINT64*)&bSyscallCode[497] = pSyscallInfo->qwParamList[1];
	*(UINT64*)&bSyscallCode[507] = pSyscallInfo->qwParamList[0];

	// allocate temporary memory for syscall code
	pCode = VirtualAlloc(NULL, sizeof(bSyscallCode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pCode == NULL)
	{
		return 1;
	}

	// execute syscall
	memcpy(pCode, bSyscallCode, sizeof(bSyscallCode));
	qwReturnValue = ((UINT64(*)())pCode)();

	// free temporary memory
	VirtualFree(pCode, 0, MEM_RELEASE);

	// store return value
	*pqwReturnValue = qwReturnValue;

	return 0;
}

DWORD WINAPI SyscallProxyThread(CpuStateStruct *pCpuState)
{
	// syscall proxy thread ready
	SetEvent(pCpuState->hSyscallProxyReadyEvent);

	for(;;)
	{
		// wait for next syscall request
		WaitForSingleObject(pCpuState->hSyscallWaitingEvent, INFINITE);

		// execute received syscall request
		if(ExecuteSyscall(&pCpuState->SyscallInfo, &pCpuState->qwSyscallReturnValue) != 0)
		{
			WriteLog(LOG_ERROR, "Failed to execute syscall");
			return 1;
		}

		// syscall complete
		SetEvent(pCpuState->hSyscallCompleteEvent);
	}

	return 0;
}

DWORD ForwardSyscallToHost(CpuStateStruct *pCpuState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue)
{
	// request syscall from proxy thread
	memcpy(&pCpuState->SyscallInfo, pSyscallInfo, sizeof(SyscallInfoStruct));
	SetEvent(pCpuState->hSyscallWaitingEvent);

	// wait for syscall to return
	WaitForSingleObject(pCpuState->hSyscallCompleteEvent, INFINITE);
	*pqwReturnValue = pCpuState->qwSyscallReturnValue;

	return 0;
}

DWORD CheckSyscallLoggingEnabled()
{
	if(gdwLogImportSyscallsEnabled == 0)
	{
		// check if the EXE imports have been loaded
		if(gdwLoadedModuleImports == 0)
		{
			// imports not loaded yet - suppress syscall logging
			return 1;
		}
	}

	return 0;
}

DWORD LogSyscallStart(char *pSyscallName, DWORD dwSyscallParamCount, SyscallInfoStruct *pSyscallInfo)
{
	char szSyscallLog[1024];
	char szTemp[512];

	if(CheckSyscallLoggingEnabled() != 0)
	{
		// syscall logging suppressed
		return 1;
	}

	// initialise log string
	memset(szSyscallLog, 0, sizeof(szSyscallLog));

	// append syscall name
	memset(szTemp, 0, sizeof(szTemp));
	_snprintf(szTemp, sizeof(szTemp) - 1, "Caught syscall: %s(", pSyscallName);
	if(AppendString(szSyscallLog, sizeof(szSyscallLog) - 1, szTemp) != 0)
	{
		return 1;
	}

	// append param values
	for(DWORD i = 0; i < dwSyscallParamCount; i++)
	{
		if(i != 0)
		{
			if(AppendString(szSyscallLog, sizeof(szSyscallLog) - 1, ",") != 0)
			{
				return 1;
			}
		}

		// append current param value
		memset(szTemp, 0, sizeof(szTemp));
		_snprintf(szTemp, sizeof(szTemp) - 1, "0x%I64X", pSyscallInfo->qwParamList[i]);
		if(AppendString(szSyscallLog, sizeof(szSyscallLog) - 1, szTemp) != 0)
		{
			return 1;
		}
	}

	// end of param values
	if(AppendString(szSyscallLog, sizeof(szSyscallLog) - 1, ")") != 0)
	{
		return 1;
	}

	// write log entry
	WriteLog(LOG_INFO, "%s", szSyscallLog);

	return 0;
}

DWORD LogSyscallEnd(char *pSyscallName, DWORD dwSyscallParamCount, SyscallInfoStruct *pSyscallInfo, UINT64 qwReturnValue)
{
	if(CheckSyscallLoggingEnabled() != 0)
	{
		// syscall logging suppressed
		return 1;
	}

	// write syscall return value
	WriteLog(LOG_INFO, "                -> returned: 0x%I64X", qwReturnValue);

	return 0;
}

DWORD HandleGuestSyscall(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, VOID *pUserStackPtr)
{
	DWORD dwSyscallIndex = 0;
	UINT64 qwCurrParamValue = 0;
	UINT64 qwReturnValue = 0;
	UINT64 *pqwStackParamPtr = NULL;
	SyscallInfoStruct SyscallInfo;
	char *pSyscallName = NULL;
	DWORD dwSyscallParamCount = 0;
	SyscallHookEntryStruct *pSyscallHookEntry = NULL;

	// get syscall index
	dwSyscallIndex = (DWORD)pCpuRegisterState->RAX;

	// look-up syscall name
	pSyscallName = GetSyscallName(dwSyscallIndex, &dwSyscallParamCount);
	if(pSyscallName == NULL)
	{
		WriteLog(LOG_ERROR, "Invalid syscall: 0x%X", dwSyscallIndex);
		return 1;
	}

	// extract syscall params from guest - copy all values regardless of dwSyscallParamCount value.
	// the dwSyscallParamCount value is calculated via wow64 modules so the results may not be 100% accurate - it is used for display-purposes only.
	memset(&SyscallInfo, 0, sizeof(SyscallInfo));
	SyscallInfo.dwSyscallIndex = dwSyscallIndex;
	for(DWORD i = 0; i < MAX_SYSCALL_PARAM_COUNT; i++)
	{
		// get first 4 param values from registers
		if(i == 0)
		{
			// the syscall instruction overwrites rcx, so windows uses r10 for the first param value instead.
			// the legacy interrupt handler (KiSystemService) also copies r10 back into rcx so it doesn't need to be handled differently.
			qwCurrParamValue = pCpuRegisterState->R10;
		}
		else if(i == 1)
		{
			qwCurrParamValue = pCpuRegisterState->RDX;
		}
		else if(i == 2)
		{
			qwCurrParamValue = pCpuRegisterState->R8;
		}
		else if(i == 3)
		{
			qwCurrParamValue = pCpuRegisterState->R9;
		}
		else
		{
			// get param from stack
			pqwStackParamPtr = (UINT64*)((UINT64)pUserStackPtr + 0x28 + ((i - 4) * 8));
			if(ValidateReadPointer(pqwStackParamPtr, 8) == 0)
			{
				qwCurrParamValue = *pqwStackParamPtr;
			}
			else
			{
				// stack ptr out of range
				qwCurrParamValue = 0;
			}
		}

		// store current param value
		SyscallInfo.qwParamList[i] = qwCurrParamValue;
	}

	if(dwSyscallParamCount == UNKNOWN_SYSCALL_PARAM_COUNT)
	{
		// unknown param count - use default
		dwSyscallParamCount = 4;
	}

	// log syscall start
	LogSyscallStart(pSyscallName, dwSyscallParamCount, &SyscallInfo);

	// check if this syscall is hooked
	for(DWORD i = 0; i < sizeof(gSyscallHookList) / sizeof(gSyscallHookList[0]); i++)
	{
		if(strcmp(pSyscallName, gSyscallHookList[i].pSyscallName) == 0)
		{
			pSyscallHookEntry = &gSyscallHookList[i];
			break;
		}
	}

	if(pSyscallHookEntry != NULL)
	{
		// hooked - pass to handler
		if(pSyscallHookEntry->pHandler(pCpuState, pCpuRegisterState, &SyscallInfo, &qwReturnValue) != 0)
		{
			return 1;
		}
	}
	else
	{
		// not hooked - pass syscall directly to host via proxy thread
		if(ForwardSyscallToHost(pCpuState, &SyscallInfo, &qwReturnValue) != 0)
		{
			return 1;
		}
	}

	// log syscall end
	LogSyscallEnd(pSyscallName, dwSyscallParamCount, &SyscallInfo, qwReturnValue);

	// set return value
	pCpuRegisterState->RAX = qwReturnValue;

	// set RIP to sysret instruction
	pCpuRegisterState->RIP = (UINT64)gbSysRet;
	
	return 0;
}

DWORD HandleSyscallInstruction(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState)
{
	// handle fast syscall - rsp still points to user-mode stack
	if(HandleGuestSyscall(pCpuState, pCpuRegisterState, (void*)pCpuRegisterState->RSP) != 0)
	{
		return 1;
	}

	// set RIP to sysret instruction
	pCpuRegisterState->RIP = (UINT64)gbSysRet;

	return 0;
}
