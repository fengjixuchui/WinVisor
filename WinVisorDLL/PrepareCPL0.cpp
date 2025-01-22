#include "WinVisorDLL.h"

BootloaderParamsStruct Global_CPL0_BootloaderParams;

BYTE bGlobal_CPL0_BootloaderCode[] =
{
	// (store BootloaderParams ptr)
	// mov rdi, rcx
	0x48, 0x89, 0xCF,

	// lgdt tword ptr [rdi + 0x06] (BootloaderParams.qwGDT_Limit + BootloaderParams.qwGDT_Base)
	0x0F, 0x01, 0x57, 0x06,

	// lidt tword ptr [rdi + 0x16] (BootloaderParams.qwIDT_Limit + BootloaderParams.qwIDT_Base)
	0x0F, 0x01, 0x5F, 0x16,

	// (set TSS selector index)
	// mov ax, word ptr [rdi + 0x20] (BootloaderParams.qwTSS_Selector)
	0x66, 0x8B, 0x47, 0x20,
	// ltr ax
	0x0F, 0x00, 0xD8,

	// (update XCR0 value to match host - this enables AVX etc)
	// xor rcx, rcx
	0x48, 0x31, 0xC9,
	// mov edx, dword ptr [rdi + 0x2C] (BootloaderParams.qwXCR0 - HIGH)
	0x8B, 0x57, 0x2C,
	// mov eax, dword ptr [rdi + 0x28] (BootloaderParams.qwXCR0 - LOW)
	0x8B, 0x47, 0x28,
	// xsetbv
	0x0F, 0x01, 0xD1,

	// (enter CPL3 code)
	// mov ax, word ptr [rdi + 0x30] (BootloaderParams.qwCPL3_DataSelector)
	0x66, 0x8B, 0x47, 0x30,
	// mov ds, ax
	0x66, 0x8E, 0xD8,
	// mov es, ax
	0x66, 0x8E, 0xC0,
	// mov gs, ax
	0x66, 0x8E, 0xE8,
	// swapgs
	0x0F, 0x01, 0xF8,
	// mov rcx, qword ptr [rdi + 0x40] (BootloaderParams.qwCPL3_EntryPlaceholderAddress)
	0x48, 0x8B, 0x4F, 0x40,
	// mov r11, qword ptr [rdi + 0x38] (BootloaderParams.qwCPL3_RFLAGS)
	0x4C, 0x8B, 0x5F, 0x38,
	// sysret
	0x48, 0x0F, 0x07
};

DWORD PrepareCPL0(CpuStateStruct *pCpuState)
{
	CpuRegisterStateStruct InitialCpuRegisterState;
	WORD wCodeSelector = 0;
	UINT64 qwHandlerAddress = 0;
	UINT64 qwXCR0 = 0;

	// allocate CPL0 stack
	pCpuState->pCPL0_Stack = VirtualAlloc(NULL, CPL0_STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pCpuState->pCPL0_Stack == NULL)
	{
		return 1;
	}

	// create GDT
	// 0 / 0x0000 (null)
	// 1 / 0x0008 (reserved)
	// 2 / 0x0010 (ring0 code)
	// 3 / 0x0018 (ring0 data)
	// 4 / 0x0020 (reserved - wow64)
	// 5 / 0x0028 (ring3 data)
	// 6 / 0x0030 (ring3 code)
	// 7 / 0x0038 (reserved)
	// 8 / 0x0040 (TSS)
	// 9 / 0x0048 (TSS continued)
	// 10 / 0x0050 (reserved - wow64)
	pCpuState->GDT[0] = 0;
	pCpuState->GDT[1] = 0;
	pCpuState->GDT[2] = GDT_PRESENT | GDT_DPL0 | GDT_NON_SYSTEM | GDT_CODE | GDT_CODE_READ | GDT_ACCESSED | GDT_LONG;
	pCpuState->GDT[3] = GDT_PRESENT | GDT_DPL0 | GDT_NON_SYSTEM | GDT_DATA | GDT_DATA_WRITE | GDT_ACCESSED;
	pCpuState->GDT[4] = 0;
	pCpuState->GDT[5] = GDT_PRESENT | GDT_DPL3 | GDT_NON_SYSTEM | GDT_DATA | GDT_DATA_WRITE | GDT_ACCESSED;
	pCpuState->GDT[6] = GDT_PRESENT | GDT_DPL3 | GDT_NON_SYSTEM | GDT_CODE | GDT_CODE_READ | GDT_ACCESSED | GDT_LONG;
	pCpuState->GDT[7] = 0;
	pCpuState->GDT[8] = GDT_PRESENT | GDT_TSS | GDT_DB | (sizeof(pCpuState->TSS) - 1) | (((UINT64)&pCpuState->TSS[0] & 0xFFFFFF) << 16) | ((((UINT64)&pCpuState->TSS[0] >> 24) & 0xFF) << 56);
	pCpuState->GDT[9] = ((UINT64)&pCpuState->TSS[0] >> 32);
	pCpuState->GDT[10] = 0;

	// create IDT - set all interrupts to placeholder address (INTERRUPT_HANDLER_VIRTUAL_ADDRESS + index)
	for(DWORD i = 0; i < MAX_IDT_ENTRY_COUNT; i++)
	{
		// set current entry
		wCodeSelector = SEGMENT_SELECTOR_CODE_CPL0;
		qwHandlerAddress = INTERRUPT_HANDLER_VIRTUAL_ADDRESS + i;
		pCpuState->IDT[i].Low = (qwHandlerAddress & 0xFFFF) | (((qwHandlerAddress >> 16) & 0xFFFF) << 48) | (wCodeSelector << 16) | IDT_INTERRUPT_GATE | IDT_DPL3 | IDT_PRESENT;
		pCpuState->IDT[i].High = (qwHandlerAddress >> 32);
	}

	// set TSS values (RSP0 only)
	memset(pCpuState->TSS, 0, sizeof(pCpuState->TSS));
	*(UINT64*)&pCpuState->TSS[4] = (UINT64)pCpuState->pCPL0_Stack + CPL0_STACK_SIZE;

	// set control registers
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterCr0, CR0_PROTECTED_MODE | CR0_PAGING | CR0_COPROCESSOR_MONITORING);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterCr3, PAGE_TABLE_BASE_PHYSICAL_ADDRESS);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterCr4, CR4_PAE | CR4_OSFXSR | CR4_OSXSAVE);

	// set EFER
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterEfer, EFER_SYSCALL_ENABLE | EFER_LONG_MODE_ENABLE | EFER_LONG_MODE_ACTIVE | EFER_NX_ENABLE);

	// set STAR/LSTAR MSRs for syscalls
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterStar, ((UINT64)SEGMENT_SELECTOR_CODE_CPL0 << 32) | ((UINT64)(SEGMENT_SELECTOR_CODE_CPL3 - 0x10) << 48));
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterLstar, SYSCALL_VIRTUAL_ADDRESS);

	// set KERNEL_GS_BASE to TEB base (swapgs will swap this value to user-mode later)
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterKernelGsBase, (UINT64)pCpuState->pHostThreadTEB);

	// set CPL0 selectors
	HypervisorUtils_SetRegisterValue_Segment(WHvX64RegisterCs, SEGMENT_SELECTOR_CODE_CPL0, 1);
	HypervisorUtils_SetRegisterValue_Segment(WHvX64RegisterSs, SEGMENT_SELECTOR_DATA_CPL0, 0);

	// get XCR0 from host
	if(ExecXGETBV(0, &qwXCR0) != 0)
	{
		return 1;
	}

	// set bootloader params
	memset(&Global_CPL0_BootloaderParams, 0, sizeof(Global_CPL0_BootloaderParams));
	Global_CPL0_BootloaderParams.qwGDT_Limit = (sizeof(pCpuState->GDT) - 1) << TABLE_REGISTER_LIMIT_SHIFT;
	Global_CPL0_BootloaderParams.qwGDT_Base = (UINT64)&pCpuState->GDT[0];
	Global_CPL0_BootloaderParams.qwIDT_Limit = (sizeof(pCpuState->IDT) - 1) << TABLE_REGISTER_LIMIT_SHIFT;
	Global_CPL0_BootloaderParams.qwIDT_Base = (UINT64)&pCpuState->IDT[0];
	Global_CPL0_BootloaderParams.qwTSS_Selector = SEGMENT_SELECTOR_TSS;
	Global_CPL0_BootloaderParams.qwCPL3_DataSelector = SEGMENT_SELECTOR_DATA_CPL3;
	Global_CPL0_BootloaderParams.qwCPL3_RFLAGS = CPL3_INITIAL_RFLAGS;
	Global_CPL0_BootloaderParams.qwCPL3_EntryPlaceholderAddress = CPL3_ENTRY_VIRTUAL_ADDRESS;
	Global_CPL0_BootloaderParams.qwXCR0 = qwXCR0;

	// execute CPL0 bootloader first
	memset(&InitialCpuRegisterState, 0, sizeof(InitialCpuRegisterState));
	InitialCpuRegisterState.RFLAGS = EFLAGS_RESERVED_ALWAYS_ON;
	InitialCpuRegisterState.RIP = (UINT64)bGlobal_CPL0_BootloaderCode;
	InitialCpuRegisterState.RCX = (UINT64)&Global_CPL0_BootloaderParams;

	// set initial registers
	HypervisorUtils_SetRegisters(&InitialCpuRegisterState);

	return 0;
}
