#include "WinVisor.h"

char gszDllPath[512];

DWORD GetDllPath()
{
	char szBaseDirectory[512];
	char *pLastSlash = NULL;

	// get full path of current exe
	memset(szBaseDirectory, 0, sizeof(szBaseDirectory));
	if(GetModuleFileNameA(NULL, szBaseDirectory, sizeof(szBaseDirectory) - 1) == 0)
	{
		return 1;
	}

	// terminate string at the last slash
	pLastSlash = strrchr(szBaseDirectory, '\\');
	if(pLastSlash == NULL)
	{
		return 1;
	}
	*pLastSlash = '\0';

	// append the dll name
	memset(gszDllPath, 0, sizeof(gszDllPath));
	_snprintf(gszDllPath, sizeof(gszDllPath) - 1, "%s\\WinVisorDLL.dll", szBaseDirectory);

	return 0;
}

DWORD GetStartHypervisorExportRVA(DWORD *pdwStartHypervisorExportRVA)
{
	HMODULE hWinVisorDLL = NULL;
	void *pStartHypervisorExport = NULL;
	DWORD dwStartHypervisorExportRVA = 0;

	// temporarily load WinVisor DLL
	hWinVisorDLL = LoadLibraryA(gszDllPath);
	if(hWinVisorDLL == NULL)
	{
		printf("Error: Failed to load DLL\n");
		return 1;
	}

	// get StartHypervisor function address
	pStartHypervisorExport = GetProcAddress(hWinVisorDLL, "StartHypervisor");
	if(pStartHypervisorExport == NULL)
	{
		FreeLibrary(hWinVisorDLL);
		return 1;
	}

	// calculate RVA
	dwStartHypervisorExportRVA = (DWORD)((UINT64)pStartHypervisorExport - (UINT64)hWinVisorDLL);

	// unload DLL
	FreeLibrary(hWinVisorDLL);

	// store RVA
	*pdwStartHypervisorExportRVA = dwStartHypervisorExportRVA;

	return 0;
}

DWORD PatchHypervisorSharedPage(HANDLE hProcess)
{
	VOID *pNtQuerySystemInformation = NULL;
	VOID *pRemoteNtQuerySystemInformationHook = NULL;
	BYTE bNtQuerySystemInformationHookPrefix[] =
	{
		// cmp rcx, 0xC5 <SystemHypervisorSharedPageInformation>
		0x48, 0x81, 0xF9, 0xC5, 0x00, 0x00, 0x00,
		// jnz call_original
		0x75, 0x06,
		// mov eax, 0xC0000003 <STATUS_INVALID_INFO_CLASS>
		0xB8, 0x03, 0x00, 0x00, 0xC0,
		// ret
		0xC3,
		// call_original:
		// ...
	};
	BYTE bJumpToHook[] =
	{
		// mov rax, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// jmp rax
		0xFF, 0xE0
	};

	// get NtQuerySystemInformation address
	pNtQuerySystemInformation = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if(pNtQuerySystemInformation == NULL)
	{
		return 1;
	}

	// allocate memory for NtQuerySystemInformation hook in remote process
	pRemoteNtQuerySystemInformationHook = VirtualAllocEx(hProcess, NULL, sizeof(bNtQuerySystemInformationHookPrefix) + SYSCALL_COPY_BYTE_COUNT, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pRemoteNtQuerySystemInformationHook == NULL)
	{
		return 1;
	}

	// copy hook prefix code
	if(WriteProcessMemory(hProcess, pRemoteNtQuerySystemInformationHook, bNtQuerySystemInformationHookPrefix, sizeof(bNtQuerySystemInformationHookPrefix), NULL) == 0)
	{
		return 1;
	}

	// append original syscall code
	if(WriteProcessMemory(hProcess, (BYTE*)pRemoteNtQuerySystemInformationHook + sizeof(bNtQuerySystemInformationHookPrefix), pNtQuerySystemInformation, SYSCALL_COPY_BYTE_COUNT, NULL) == 0)
	{
		return 1;
	}

	// patch NtQuerySystemInformation in remote process - jump to hook
	*(UINT64*)&bJumpToHook[2] = (UINT64)pRemoteNtQuerySystemInformationHook;
	if(WriteProcessMemory(hProcess, (BYTE*)pNtQuerySystemInformation, bJumpToHook, sizeof(bJumpToHook), NULL) == 0)
	{
		return 1;
	}

	return 0;
}

DWORD DisableParallelLoader(HANDLE hProcess)
{
	VOID *pNtOpenSection = NULL;
	BYTE bExpectedOrigBytes[] = 
	{
		// mov r10, rcx
		0x4C, 0x8B, 0xD1
	};
	BYTE bPushRcxPopR10[] = 
	{
		// push rcx
		0x51,
		// pop r10
		0x41, 0x5A
	};
	BYTE bOrigBytes[sizeof(bExpectedOrigBytes)];

	// get NtOpenSection address
	pNtOpenSection = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection");
	if(pNtOpenSection == NULL)
	{
		return 1;
	}

	// read original bytes from NtOpenSection
	if(ReadProcessMemory(hProcess, pNtOpenSection, bOrigBytes, sizeof(bOrigBytes), NULL) == 0)
	{
		return 1;
	}

	// ensure the first instruction is "mov r10, rcx"
	if(memcmp(bOrigBytes, bExpectedOrigBytes, sizeof(bOrigBytes)) != 0)
	{
		return 1;
	}

	// overwrite with "push rcx; pop r10".
	// this has the same effect as the original instruction, but will cause ntdll to set LdrpDetectDetour to 1 and therefore disable the parallel loader.
	if(WriteProcessMemory(hProcess, pNtOpenSection, bPushRcxPopR10, sizeof(bPushRcxPopR10), NULL) == 0)
	{
		return 1;
	}

	return 0;
}

VOID *GetRemoteExeBase(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;
	PEB RemotePEB;
	DWORD (WINAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) = NULL;

	// get NtQueryInformationProcess address
	pNtQueryInformationProcess = (DWORD(WINAPI*)(HANDLE,DWORD,PVOID,ULONG,PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if(pNtQueryInformationProcess == NULL)
	{
		return NULL;
	}

	// get PEB address
	memset(&ProcessBasicInfo, 0, sizeof(ProcessBasicInfo));
	if(pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof(ProcessBasicInfo), NULL) != 0)
	{
		return NULL;
	}

	// read PEB data from process
	memset(&RemotePEB, 0, sizeof(RemotePEB));
	if(ReadProcessMemory(hProcess, ProcessBasicInfo.PebBaseAddress, &RemotePEB, sizeof(RemotePEB), NULL) == 0)
	{
		return NULL;
	}
	
	return RemotePEB.ImageBaseAddress;
}

VOID *GetRemoteModuleNtHeaderAddress(HANDLE hProcess, VOID *pRemoteModuleBase)
{
	IMAGE_DOS_HEADER RemoteDosHeader;

	// read DOS header
	memset(&RemoteDosHeader, 0, sizeof(RemoteDosHeader));
	if(ReadProcessMemory(hProcess, pRemoteModuleBase, &RemoteDosHeader, sizeof(RemoteDosHeader), NULL) == 0)
	{
		return NULL;
	}

	// return NT header address
	return (BYTE*)pRemoteModuleBase + RemoteDosHeader.e_lfanew;
}

DWORD ReadRemoteModuleNtHeader(HANDLE hProcess, VOID *pRemoteModuleBase, IMAGE_NT_HEADERS64 *pRemoteNtHeader)
{
	VOID *pRemoteNtHeaderAddress = NULL;
	IMAGE_NT_HEADERS64 RemoteNtHeader;

	// get NT header address for remote module
	pRemoteNtHeaderAddress = GetRemoteModuleNtHeaderAddress(hProcess, pRemoteModuleBase);
	if(pRemoteNtHeaderAddress == NULL)
	{
		return 1;
	}

	// read NT header
	memset(&RemoteNtHeader, 0, sizeof(RemoteNtHeader));
	if(ReadProcessMemory(hProcess, pRemoteNtHeaderAddress, &RemoteNtHeader, sizeof(RemoteNtHeader), NULL) == 0)
	{
		return 1;
	}

	// ensure this is a 64-bit module
	if(RemoteNtHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || RemoteNtHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		return 1;
	}

	if(pRemoteNtHeader != NULL)
	{
		// copy headers
		memcpy(pRemoteNtHeader, &RemoteNtHeader, sizeof(RemoteNtHeader));
	}

	return 0;
}

DWORD WriteRemoteModuleNtHeader(HANDLE hProcess, VOID *pRemoteModuleBase, IMAGE_NT_HEADERS64 *pRemoteNtHeader)
{
	VOID *pRemoteExeNtHeaderAddress = NULL;
	DWORD dwOrigProtect = 0;

	// get NT header address for remote EXE
	pRemoteExeNtHeaderAddress = GetRemoteModuleNtHeaderAddress(hProcess, pRemoteModuleBase);
	if(pRemoteExeNtHeaderAddress == NULL)
	{
		return 1;
	}

	if(VirtualProtectEx(hProcess, pRemoteExeNtHeaderAddress, sizeof(IMAGE_NT_HEADERS64), PAGE_READWRITE, &dwOrigProtect) == 0)
	{
		return 1;
	}

	if(WriteProcessMemory(hProcess, pRemoteExeNtHeaderAddress, pRemoteNtHeader, sizeof(IMAGE_NT_HEADERS64), NULL) == 0)
	{
		return 1;
	}
	
	if(VirtualProtectEx(hProcess, pRemoteExeNtHeaderAddress, sizeof(IMAGE_NT_HEADERS64), dwOrigProtect, &dwOrigProtect) == 0)
	{
		return 1;
	}

	return 0;
}

DWORD PatchRemoteExeDataDirectories(HANDLE hProcess, VOID *pRemoteExeModuleBase)
{
	IMAGE_NT_HEADERS64 RemoteNtHeader;

	// read NT header
	if(ReadRemoteModuleNtHeader(hProcess, pRemoteExeModuleBase, &RemoteNtHeader) != 0)
	{
		return 1;
	}

	// remove import directories
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

	// remove TLS directory
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	RemoteNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;

	// write NT header
	if(WriteRemoteModuleNtHeader(hProcess, pRemoteExeModuleBase, &RemoteNtHeader) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD PatchRemoteExeEntryPoint(HANDLE hProcess, VOID *pRemoteExeModuleBase, IMAGE_NT_HEADERS64 *pOrigRemoteExeNtHeader, UINT64 qwWinVisorFlags)
{
	VOID *pRemoteEntryPoint = NULL;
	VOID *pRemoteDllPath = NULL;
	VOID *pRemoteWinVisorStartData = NULL;
	VOID *pLoadWinVisorDllCode = NULL;
	DWORD dwStartHypervisorExportRVA = 0;
	WinVisorStartDataStruct WinVisorStartData;
	BYTE bOrigEntryPointCode[HOOK_ENTRY_POINT_CODE_SIZE];
	BYTE bHookEntryPointCode[HOOK_ENTRY_POINT_CODE_SIZE] = 
	{
		// mov rax, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// jmp rax
		0xFF, 0xE0,
		// (padding)
		0x90, 0x90, 0x90, 0x90
	};
	BYTE bLoadWinVisorDllCode[] =
	{
		// sub rsp, 0x28
		0x48, 0x83, 0xEC, 0x28,

		// mov rcx, <DLLPath>
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// mov rax, <LoadLibraryA>
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// call rax
		0xFF, 0xD0,
		// test rax, rax
		0x48, 0x85, 0xC0,
		// jz <LoadLibraryFailed>
		0x74, 0x26,
		// add rax, <StartHypervisorExportRVA>
		0x48, 0x05, 0x00, 0x00, 0x00, 0x00,
		// mov rcx, <WinVisorStartData>
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// call rax
		0xFF, 0xD0,

		// LoadLibraryFailed:
		// add rsp, 0x28
		0x48, 0x83, 0xC4, 0x28,
		// ret
		0xC3
	};

	// get entry-point
	pRemoteEntryPoint = (BYTE*)pRemoteExeModuleBase + pOrigRemoteExeNtHeader->OptionalHeader.AddressOfEntryPoint;

	// allocate memory in remote process for winvisor dll path
	pRemoteDllPath = VirtualAllocEx(hProcess, NULL, sizeof(gszDllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pRemoteDllPath == NULL)
	{
		return 1;
	}

	// allocate memory in remote process for winvisor start data
	pRemoteWinVisorStartData = VirtualAllocEx(hProcess, NULL, sizeof(WinVisorStartData), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pRemoteWinVisorStartData == NULL)
	{
		return 1;
	}

	// allocate memory in remote process for winvisor loader code
	pLoadWinVisorDllCode = VirtualAllocEx(hProcess, NULL, sizeof(bLoadWinVisorDllCode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pLoadWinVisorDllCode == NULL)
	{
		return 1;
	}

	// calculate RVA of StartHypervisor export in winvisor dll
	if(GetStartHypervisorExportRVA(&dwStartHypervisorExportRVA) != 0)
	{
		return 1;
	}

	// store original entry-point code (first 16 bytes)
	memset(bOrigEntryPointCode, 0, sizeof(bOrigEntryPointCode));
	if(ReadProcessMemory(hProcess, pRemoteEntryPoint, bOrigEntryPointCode, sizeof(bOrigEntryPointCode), NULL) == 0)
	{
		return 1;
	}

	// copy full dll path to remote process
	if(WriteProcessMemory(hProcess, pRemoteDllPath, gszDllPath, sizeof(gszDllPath), NULL) == 0)
	{
		return 1;
	}

	// copy start data to remote process
	memset(&WinVisorStartData, 0, sizeof(WinVisorStartData));
	memcpy(WinVisorStartData.bOrigEntryPointCode, bOrigEntryPointCode, sizeof(WinVisorStartData.bOrigEntryPointCode));
	WinVisorStartData.qwWinVisorFlags = qwWinVisorFlags;
	memcpy(&WinVisorStartData.OrigNtHeader, pOrigRemoteExeNtHeader, sizeof(WinVisorStartData.OrigNtHeader));
	if(WriteProcessMemory(hProcess, pRemoteWinVisorStartData, &WinVisorStartData, sizeof(WinVisorStartData), NULL) == 0)
	{
		return 1;
	}

	// populate values/pointers in winvisor loader code and copy to remote process
	*(UINT64*)&bLoadWinVisorDllCode[6] = (UINT64)pRemoteDllPath;
	*(UINT64*)&bLoadWinVisorDllCode[16] = (UINT64)LoadLibraryA;
	*(DWORD*)&bLoadWinVisorDllCode[33] = dwStartHypervisorExportRVA;
	*(UINT64*)&bLoadWinVisorDllCode[39] = (UINT64)pRemoteWinVisorStartData;
	if(WriteProcessMemory(hProcess, pLoadWinVisorDllCode, bLoadWinVisorDllCode, sizeof(bLoadWinVisorDllCode), NULL) == 0)
	{
		return 1;
	}

	// temporarily overwrite the entry-point to load the winvisor dll on startup
	*(UINT64*)&bHookEntryPointCode[2] = (UINT64)pLoadWinVisorDllCode;
	if(WriteProcessMemory(hProcess, pRemoteEntryPoint, bHookEntryPointCode, sizeof(bHookEntryPointCode), NULL) == 0)
	{
		return 1;
	}

	return 0;
}

DWORD AttachWinVisor(HANDLE hProcess, UINT64 qwWinVisorFlags)
{
	VOID *pRemoteExeModuleBase = NULL;
	IMAGE_NT_HEADERS64 OrigRemoteExeNtHeader;

	// get remote EXE base address
	pRemoteExeModuleBase = GetRemoteExeBase(hProcess);
	if(pRemoteExeModuleBase == NULL)
	{
		return 1;
	}

	// store original NT headers for remote exe
	if(ReadRemoteModuleNtHeader(hProcess, pRemoteExeModuleBase, &OrigRemoteExeNtHeader) != 0)
	{
		printf("Error: Target is not a valid x64 executable\n");
		return 1;
	}

	// hook the entry-point of the remote process - load WinVisor DLL
	if(PatchRemoteExeEntryPoint(hProcess, pRemoteExeModuleBase, &OrigRemoteExeNtHeader, qwWinVisorFlags) != 0)
	{
		return 1;
	}

	// temporarily remove the import and TLS data directories for the remote exe.
	// this prevents any DLL dependencies and TLS callbacks from executing before the hypervisor takes over.
	// these will be restored later, and the virtual CPU will load DLL dependencies and execute TLS callbacks manually before executing the entry-point.
	if(PatchRemoteExeDataDirectories(hProcess, pRemoteExeModuleBase) != 0)
	{
		return 1;
	}

	// windows 10 introduced a new shared page which is located close to KUSER_SHARED_DATA.
	// the exact address can be retrieved with NtQuerySystemInformation(SystemHypervisorSharedPageInformation).
	// this page is used by timing-related functions such as RtlQueryPerformanceCounter / RtlGetMultiTimePrecise.
	// the hypervisor platform api contains a bug which causes WHvRunVirtualProcessor to get stuck in an infinite loop if the guest attempts to access this shared page.
	// to work around this bug, NtQuerySystemInformation will be patched to return STATUS_INVALID_INFO_CLASS for SystemHypervisorSharedPageInformation requests.
	// this causes the code in ntdll to fall back to traditional methods.
	// it needs to be patched early as LdrpInitializeProcess stores the address of this page in a global variable (ntdll!RtlpHypervisorSharedUserVa).
	if(PatchHypervisorSharedPage(hProcess) != 0)
	{
		return 1;
	}

	// windows 10 added a parallel loader which loads DLL dependencies using multiple background threads via a thread-pool.
	// as this emulator currently only virtualizes a single thread, this behaviour should be disabled to ensure DLL loads are all performed by the calling thread.
	// it is possible to disable the parallel loader by setting PEB->ProcessParameters->LoaderThreads to 1 before resuming the process, but this value can still be
	// overridden by the MaxLoaderThreads IFEO value.
	// the windows loader also checks for inline patches within a hardcoded list of functions (LdrpCriticalLoaderFunctions), and if any patches are
	// detected, parallel loading is disabled for stability reasons.
	// this function patches the first instruction (mov r10, rcx) of a known LdrpCriticalLoaderFunctions entry (NtOpenSection) to an equivalent operation
	// of the same size (push rcx; pop r10), which forces the parallel loader to be disabled without affecting any other functionality.
	if(DisableParallelLoader(hProcess) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD LaunchTargetProcess(char *pTargetCommandLine, UINT64 qwWinVisorFlags, DWORD *pdwPID)
{
	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	printf("Launching target process: %s...\n", pTargetCommandLine);

	// get full WinVisor DLL path
	if(GetDllPath() != 0)
	{
		return 1;
	}

	// create suspended process
	memset(&StartupInfo, 0, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);
	if(CreateProcessA(NULL, pTargetCommandLine, NULL, NULL, 0, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo) == 0)
	{
		printf("Error: Failed to launch target process\n");
		return 1;
	}

	// attach WinVisor to remote process
	if(AttachWinVisor(ProcessInfo.hProcess, qwWinVisorFlags) != 0)
	{
		printf("Error: Failed to attach WinVisor to remote process\n");
		TerminateProcess(ProcessInfo.hProcess, 0);
		CloseHandle(ProcessInfo.hProcess);
		CloseHandle(ProcessInfo.hThread);
		return 1;
	}

	// start remote process
	ResumeThread(ProcessInfo.hThread);

	// close handles
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);

	// store PID
	*pdwPID = ProcessInfo.dwProcessId;

	return 0;
}
