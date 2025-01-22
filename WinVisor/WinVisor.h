#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <windows.h>
#include "..\Common\WinVisorCommon.h"

#define ProcessBasicInformation 0

#define SYSCALL_COPY_BYTE_COUNT 64

struct PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[1];
	PVOID ImageBaseAddress;
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PVOID PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
};

struct PROCESS_BASIC_INFORMATION
{
	DWORD ExitStatus;
	PEB *PebBaseAddress;
	ULONG_PTR AffinityMask;
	DWORD BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
};

extern DWORD StartLogClient(DWORD dwPID);
extern DWORD ParseCommandLine(char *pFirstParam, char **ppTargetCommandLine, UINT64 *pqwWinVisorFlags);
extern DWORD LaunchTargetProcess(char *pTargetCommandLine, UINT64 qwWinVisorFlags, DWORD *pdwPID);
