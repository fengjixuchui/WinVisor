#define _WIN32_WINNT 0x0600
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <windows.h>
#include "WinHvApi.h"
#include "..\Common\WinVisorCommon.h"

#define ThreadBasicInformation 0

#define PAGE_SIZE 0x1000

#define CR0_PROTECTED_MODE 0x1
#define CR0_COPROCESSOR_MONITORING 0x2
#define CR0_PAGING 0x80000000

#define CR4_PAE 0x20
#define CR4_OSFXSR 0x200
#define CR4_OSXSAVE 0x40000

#define EFER_SYSCALL_ENABLE 0x1
#define EFER_LONG_MODE_ENABLE 0x100
#define EFER_LONG_MODE_ACTIVE 0x400
#define EFER_NX_ENABLE 0x800

#define EFLAGS_RESERVED_ALWAYS_ON 0x2

#define PAGE_PRESENT 0x1
#define PAGE_WRITABLE 0x2
#define PAGE_USER 0x4

#define QWORD UINT64

#define SEGMENT_SELECTOR_CODE_CPL0 0x10
#define SEGMENT_SELECTOR_CODE_CPL3 0x33
#define SEGMENT_SELECTOR_DATA_CPL0 0x18
#define SEGMENT_SELECTOR_DATA_CPL3 0x2B
#define SEGMENT_SELECTOR_TSS 0x40

#define PAGE_TABLE_BASE_PHYSICAL_ADDRESS 0x0

#define SYSCALL_VIRTUAL_ADDRESS 0xFFFF800000000000
#define CPL3_ENTRY_VIRTUAL_ADDRESS 0xFFFF900000000000
#define INTERRUPT_HANDLER_VIRTUAL_ADDRESS 0xFFFFA00000000000

#define CPL3_INITIAL_RFLAGS 0x202

#define MAX_SYSCALL_PARAM_COUNT 32

#define MAX_MAPPED_PAGE_COUNT 256

#define MAX_GDT_ENTRY_COUNT 0xB
#define MAX_IDT_ENTRY_COUNT 0x100
#define TSS_SIZE 0x68

#define GDT_PRESENT 0x800000000000
#define GDT_DPL0 0x0
#define GDT_DPL3 0x600000000000
#define GDT_NON_SYSTEM 0x100000000000
#define GDT_CODE 0x80000000000
#define GDT_DATA 0x0
#define GDT_CODE_READ 0x20000000000
#define GDT_DATA_WRITE 0x20000000000
#define GDT_ACCESSED 0x10000000000
#define GDT_LONG 0x20000000000000
#define GDT_TSS 0x90000000000
#define GDT_DB 0x40000000000000

#define IDT_INTERRUPT_GATE 0xE0000000000
#define IDT_DPL3 0x600000000000
#define IDT_PRESENT 0x800000000000

#define CPL0_STACK_SIZE PAGE_SIZE

#define LOG_INFO 0
#define LOG_ERROR 1
#define LOG_DEBUG 2

#define UNKNOWN_SYSCALL_PARAM_COUNT 0xFFFFFFFF

#define TABLE_REGISTER_LIMIT_SHIFT 48

struct CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

struct THREAD_BASIC_INFORMATION
{
	DWORD ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	DWORD Priority;
	LONG BasePriority;
};

struct SyscallNameEntryStruct
{
	char szName[128];
	DWORD dwVirtualAddress;
	DWORD dwParamCount;
};

struct MappedVirtualAddressStruct
{
	DWORD dwInUse;
	QWORD qwCreationIndex;

	UINT64 qwVirtualAddress;
	UINT64 qwPhysicalAddress;
};

struct PageTableStruct
{
	UINT64 qwEntries[512];
};

struct VirtualAddressTableIndexesStruct
{
	WORD wPML4;
	WORD wPDPT;
	WORD wPD;
	WORD wPT;
	WORD wOffset;
};

struct PagingStateStruct
{
	DWORD dwTotalEntryCount;
	DWORD dwNextEntryIndex;
};

struct SyscallInfoStruct
{
	DWORD dwSyscallIndex;
	UINT64 qwParamList[MAX_SYSCALL_PARAM_COUNT];
};

struct CpuRegisterStateStruct
{
	QWORD RAX;
	QWORD RCX;
	QWORD RDX;
	QWORD RBX;
	QWORD RSP;
	QWORD RBP;
	QWORD RSI;
	QWORD RDI;
	QWORD R8;
	QWORD R9;
	QWORD R10;
	QWORD R11;
	QWORD R12;
	QWORD R13;
	QWORD R14;
	QWORD R15;
	QWORD RIP;
	QWORD RFLAGS;
};

struct ImportFunctionStruct
{
	char *pName;
	void **pFunctionPtrAddr;
};

struct UINT128
{
	UINT64 Low;
	UINT64 High;
};

struct CpuStateStruct
{
	UINT64 GDT[MAX_GDT_ENTRY_COUNT];
	BYTE TSS[TSS_SIZE];
	UINT128 IDT[MAX_IDT_ENTRY_COUNT];

	VOID *pCPL0_Stack;
	VOID *pCPL3_Stack;

	HANDLE hHostThread;
	VOID *pHostThreadTEB;

	HANDLE hSyscallProxyReadyEvent;
	HANDLE hSyscallWaitingEvent;
	HANDLE hSyscallCompleteEvent;
	SyscallInfoStruct SyscallInfo;
	UINT64 qwSyscallReturnValue;

	CpuRegisterStateStruct CPL3_InitialCpuRegisterState;
};

struct InterruptHandlerEntryStruct
{
	BYTE bInterruptIndex;
	DWORD (*pHandler)(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState);
	DWORD dwHasErrorCode;
};

struct SyscallHookEntryStruct
{
	char *pSyscallName;
	DWORD (*pHandler)(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue);
};

struct BootloaderParamsStruct
{
	UINT64 qwGDT_Limit;
	UINT64 qwGDT_Base;
	UINT64 qwIDT_Limit;
	UINT64 qwIDT_Base;
	UINT64 qwTSS_Selector;
	UINT64 qwXCR0;
	UINT64 qwCPL3_DataSelector;
	UINT64 qwCPL3_RFLAGS;
	UINT64 qwCPL3_EntryPlaceholderAddress;
};

extern DWORD InitialiseLogServer();
extern DWORD CloseLogServer();
extern DWORD WriteLog(DWORD dwLogType, char *pStringFormat, ...);
extern BYTE *LoadExecutable(char *pExeFilePath);
extern DWORD ExecuteSyscall(SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue);
extern DWORD HypervisorUtils_Initialise();
extern DWORD HypervisorUtils_GetRegisterValue_U64(WHV_REGISTER_NAME RegisterName, QWORD *pqwRegisterValue);
extern DWORD HypervisorUtils_SetRegisterValue_U64(WHV_REGISTER_NAME RegisterName, QWORD qwRegisterValue);
extern DWORD HypervisorUtils_SetRegisterValue_Segment(WHV_REGISTER_NAME RegisterName, WORD wSelector, DWORD dwCode);
extern DWORD HypervisorUtils_CreateEnvironment();
extern DWORD HypervisorUtils_DeleteEnvironment();
extern DWORD HypervisorUtils_ResumeExecution(WHV_RUN_VP_EXIT_CONTEXT *pVmExitContext);
extern DWORD HypervisorUtils_FlushTLB();
extern DWORD HypervisorUtils_UnmapGuestMemory(void *pGuestPhysicalAddress, DWORD dwSize);
extern DWORD HypervisorUtils_MapGuestMemory(void *pHostVirtualAddress, void *pGuestPhysicalAddress, DWORD dwSize);
extern DWORD PrepareCPL0(CpuStateStruct *pCpuState);
extern DWORD WINAPI SyscallProxyThread(CpuStateStruct *pCpuState);
extern InterruptHandlerEntryStruct *GetInterruptHandler(BYTE bInterruptIndex);
extern DWORD InterruptHandler_Breakpoint(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState);
extern DWORD InterruptHandler_SingleStep(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState);
extern BYTE *GetInterruptReturn(InterruptHandlerEntryStruct *pInterruptHandlerEntry);
extern DWORD AddPagedVirtualAddress(UINT64 qwVirtualAddress);
extern DWORD CreatePageTables();
extern DWORD CreateSyscallLists();
extern char *GetSyscallName(DWORD dwSyscallIndex, DWORD *pdwParamCount);
extern DWORD HandleVmExit(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, WHV_RUN_VP_EXIT_CONTEXT *pVmExitContext);
extern DWORD HandlePageFault(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, UINT64 qwVirtualAddress);
extern DWORD HandleSyscallInstruction(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState);
extern DWORD SyscallHook_NtTerminateThread(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue);
extern DWORD SyscallHook_NtTerminateProcess(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue);
extern DWORD ForwardSyscallToHost(CpuStateStruct *pCpuState, SyscallInfoStruct *pSyscallInfo, UINT64 *pqwReturnValue);
extern DWORD InterruptHandler_LegacySyscall(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState);
extern DWORD HandleGuestSyscall(CpuStateStruct *pCpuState, CpuRegisterStateStruct *pCpuRegisterState, VOID *pUserStackPtr);
extern IMAGE_NT_HEADERS *GetNtHeader(VOID *pModuleBase);
extern DWORD dwGlobal_StopLog;
extern DWORD FixNtdllHypervisorSharedPagePtr();
extern HMODULE hGlobal_NtdllBase;
extern DWORD (WINAPI *pNtQueryInformationThread)(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
extern DWORD (WINAPI *pNtQuerySystemInformation)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern DWORD GuestProcessExited(DWORD dwExitCode);
extern DWORD ValidateReadPointer(VOID *pAddress, SIZE_T dwLength);
extern DWORD dwGlobal_DebugLogEnabled;
extern DWORD PopulateSyscallParamCounts(char *pModuleName, SyscallNameEntryStruct *pSyscallList, DWORD dwSyscallCount);
extern DWORD AppendString(char *pString, SIZE_T dwMaxLength, char *pAppend);
extern DWORD HypervisorUtils_GetRegisters(CpuRegisterStateStruct *pCpuRegisterState);
extern DWORD HypervisorUtils_SetRegisters(CpuRegisterStateStruct *pCpuRegisterState);
extern DWORD PrepareCPL3(CpuStateStruct *pCpuState, WinVisorStartDataStruct *pWinVisorStartData);
extern CpuStateStruct *CreateCpuState(WinVisorStartDataStruct *pWinVisorStartData);
extern DWORD DeleteCpuState(CpuStateStruct *pCpuState);
extern DWORD DeleteSyscallLists();
extern DWORD DeletePageTables();
extern DWORD ExecXGETBV(DWORD dwIndex, QWORD *pqwReturnValue);
extern DWORD FixModuleImports(VOID *pModuleBase);
extern DWORD HypervisorEntryPoint(VOID *pExeEntryPoint);
extern HMODULE hGlobal_ExeBase;
extern DWORD CopyMemoryAndRestoreProtection(VOID *pDestination, VOID *pSource, DWORD dwLength);
extern DWORD dwGlobal_LoadedModuleImports;
extern DWORD dwGlobal_LogImportSyscallsEnabled;
