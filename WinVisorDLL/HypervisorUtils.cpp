#include "WinVisorDLL.h"

HRESULT (WINAPI *WHvCreatePartition)(WHV_PARTITION_HANDLE* Partition) = NULL;
HRESULT (WINAPI *WHvDeletePartition)(WHV_PARTITION_HANDLE Partition) = NULL;
HRESULT (WINAPI *WHvMapGpaRange)(WHV_PARTITION_HANDLE Partition, VOID* SourceAddress, WHV_GUEST_PHYSICAL_ADDRESS GuestAddress, UINT64 SizeInBytes, WHV_MAP_GPA_RANGE_FLAGS Flags) = NULL;
HRESULT (WINAPI *WHvUnmapGpaRange)(WHV_PARTITION_HANDLE Partition, WHV_GUEST_PHYSICAL_ADDRESS GuestAddress, UINT64 SizeInBytes);
HRESULT (WINAPI *WHvSetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, const WHV_REGISTER_VALUE* RegisterValues) = NULL;
HRESULT (WINAPI *WHvRunVirtualProcessor)(WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, VOID* ExitContext, UINT32 ExitContextSizeInBytes) = NULL;
HRESULT (WINAPI *WHvSetPartitionProperty)(WHV_PARTITION_HANDLE Partition, WHV_PARTITION_PROPERTY_CODE PropertyCode, const VOID* PropertyBuffer, UINT32 PropertyBufferSizeInBytes) = NULL;
HRESULT (WINAPI *WHvSetupPartition)(WHV_PARTITION_HANDLE Partition) = NULL;
HRESULT (WINAPI *WHvCreateVirtualProcessor)(WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, UINT32 Flags) = NULL;
HRESULT (WINAPI *WHvGetVirtualProcessorRegisters)(WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, WHV_REGISTER_VALUE* RegisterValues) = NULL;
HRESULT (WINAPI *WHvGetCapability)(WHV_CAPABILITY_CODE CapabilityCode, VOID* CapabilityBuffer, UINT32 CapabilityBufferSizeInBytes, UINT32 *WrittenSizeInBytes) = NULL;

ImportFunctionStruct Global_ImportHypervisorPlatformFunctionList[] =
{
	{ "WHvCreatePartition", (void**)&WHvCreatePartition },
	{ "WHvDeletePartition", (void**)&WHvDeletePartition },
	{ "WHvMapGpaRange", (void**)&WHvMapGpaRange },
	{ "WHvUnmapGpaRange", (void**)&WHvUnmapGpaRange },
	{ "WHvSetVirtualProcessorRegisters", (void**)&WHvSetVirtualProcessorRegisters },
	{ "WHvRunVirtualProcessor", (void**)&WHvRunVirtualProcessor },
	{ "WHvSetPartitionProperty", (void**)&WHvSetPartitionProperty },
	{ "WHvSetupPartition", (void**)&WHvSetupPartition },
	{ "WHvCreateVirtualProcessor", (void**)&WHvCreateVirtualProcessor },
	{ "WHvGetVirtualProcessorRegisters", (void**)&WHvGetVirtualProcessorRegisters },
	{ "WHvGetCapability", (void**)&WHvGetCapability },
};

HANDLE hGlobal_PartitionHandle = NULL;

DWORD HypervisorUtils_Initialise()
{
	HMODULE hModule = NULL;
	void *pImportAddr = NULL;
	DWORD dwFunctionCount = 0;
	WHV_CAPABILITY HypervisorCapability;
	UINT32 dwHypervisorCapabilitySize = 0;

	// load hypervisor module
	hModule = LoadLibraryA("winhvplatform.dll");
	if(hModule == NULL)
	{
		return 1;
	}

	// resolve imported functions
	dwFunctionCount = sizeof(Global_ImportHypervisorPlatformFunctionList) / sizeof(Global_ImportHypervisorPlatformFunctionList[0]);
	for(DWORD i = 0; i < dwFunctionCount; i++)
	{
		// resolve current function
		pImportAddr = GetProcAddress(hModule, Global_ImportHypervisorPlatformFunctionList[i].pName);
		if(pImportAddr == NULL)
		{
			return 1;
		}

		// store function ptr
		*Global_ImportHypervisorPlatformFunctionList[i].pFunctionPtrAddr = pImportAddr;
	}

	// ensure the hypervisor platform is enabled
	memset(&HypervisorCapability, 0, sizeof(HypervisorCapability));
	if(WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &HypervisorCapability, sizeof(HypervisorCapability), &dwHypervisorCapabilitySize) != S_OK)
	{
		return 1;
	}
	if(HypervisorCapability.HypervisorPresent == 0)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_CreateEnvironment()
{
	WHV_PARTITION_HANDLE hPartitionHandle = NULL;
	WHV_PARTITION_PROPERTY PartitionPropertyData;
	WHV_EXTENDED_VM_EXITS ExtendedVmExits;
	UINT64 qwExceptionExitBitmap = 0;

	// create hypervisor partition
	if(WHvCreatePartition(&hPartitionHandle) != S_OK)
	{
		return 1;
	}

	// single processor
	memset(&PartitionPropertyData, 0, sizeof(PartitionPropertyData));
	PartitionPropertyData.ProcessorCount = 1;
	if(WHvSetPartitionProperty(hPartitionHandle, WHvPartitionPropertyCodeProcessorCount, &PartitionPropertyData, sizeof(PartitionPropertyData)) != S_OK)
	{
		WHvDeletePartition(hPartitionHandle);
		return 1;
	}

	// enable vmexit for exceptions
	memset(&ExtendedVmExits, 0, sizeof(ExtendedVmExits));
	ExtendedVmExits.ExceptionExit = 1;
	if(WHvSetPartitionProperty(hPartitionHandle, WHvPartitionPropertyCodeExtendedVmExits, &ExtendedVmExits, sizeof(ExtendedVmExits)) != S_OK)
	{
		WHvDeletePartition(hPartitionHandle);
		return 1;
	}

	// update exception bitmap to catch page faults and general protection faults
	qwExceptionExitBitmap = (1 << WHvX64ExceptionTypePageFault) | (1 << WHvX64ExceptionTypeGeneralProtectionFault);
	if(WHvSetPartitionProperty(hPartitionHandle, WHvPartitionPropertyCodeExceptionExitBitmap, &qwExceptionExitBitmap, sizeof(qwExceptionExitBitmap)) != S_OK)
	{
		WHvDeletePartition(hPartitionHandle);
		return 1;
	}

	// hypervisor partition ready
	if(WHvSetupPartition(hPartitionHandle) != S_OK)
	{
		WHvDeletePartition(hPartitionHandle);
		return 1;
	}

	// create virtual CPU
	if(WHvCreateVirtualProcessor(hPartitionHandle, 0, 0) != S_OK)
	{
		WHvDeletePartition(hPartitionHandle);
		return 1;
	}

	// store handle
	hGlobal_PartitionHandle = hPartitionHandle;

	return 0;
}

DWORD HypervisorUtils_DeleteEnvironment()
{
	if(hGlobal_PartitionHandle != NULL)
	{
		WHvDeletePartition(hGlobal_PartitionHandle);
	}

	return 0;
}

DWORD HypervisorUtils_GetRegisterValue_U64(WHV_REGISTER_NAME RegisterName, QWORD *pqwRegisterValue)
{
	WHV_REGISTER_VALUE RegisterValue;

	// get uint64 register value
	memset(&RegisterValue, 0, sizeof(RegisterValue));
	if(WHvGetVirtualProcessorRegisters(hGlobal_PartitionHandle, 0, &RegisterName, 1, &RegisterValue) != S_OK)
	{
		return 1;
	}

	*pqwRegisterValue = RegisterValue.Reg64;

	return 0;
}

DWORD HypervisorUtils_SetRegisterValue_U64(WHV_REGISTER_NAME RegisterName, QWORD qwRegisterValue)
{
	WHV_REGISTER_VALUE RegisterValue;

	// set uint64 register value
	memset(&RegisterValue, 0, sizeof(RegisterValue));
	RegisterValue.Reg64 = qwRegisterValue;
	if(WHvSetVirtualProcessorRegisters(hGlobal_PartitionHandle, 0, &RegisterName, 1, &RegisterValue) != S_OK)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_SetRegisterValue_Segment(WHV_REGISTER_NAME RegisterName, WORD wSelector, DWORD dwCode)
{
	WHV_REGISTER_VALUE RegisterValue;

	// set segment register value
	memset(&RegisterValue, 0, sizeof(RegisterValue));
	RegisterValue.Segment.Selector = wSelector;
	RegisterValue.Segment.NonSystemSegment = 1;
	RegisterValue.Segment.DescriptorPrivilegeLevel = wSelector & 0x3;
	RegisterValue.Segment.Present = 1;
	if(dwCode == 0)
	{
		// data (write, accessed)
		RegisterValue.Segment.SegmentType = 0x3;
	}
	else
	{
		// code (execute, read, accessed)
		RegisterValue.Segment.SegmentType = 0xB;
		RegisterValue.Segment.Long = 1;
	}
	if(WHvSetVirtualProcessorRegisters(hGlobal_PartitionHandle, 0, &RegisterName, 1, &RegisterValue) != S_OK)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_GetRegisters(CpuRegisterStateStruct *pCpuRegisterState)
{
	CpuRegisterStateStruct CpuRegisterState;

	// get register values
	memset(&CpuRegisterState, 0, sizeof(CpuRegisterState));
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRax, &CpuRegisterState.RAX);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRcx, &CpuRegisterState.RCX);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRdx, &CpuRegisterState.RDX);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRbx, &CpuRegisterState.RBX);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRsp, &CpuRegisterState.RSP);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRbp, &CpuRegisterState.RBP);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRsi, &CpuRegisterState.RSI);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRdi, &CpuRegisterState.RDI);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR8, &CpuRegisterState.R8);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR9, &CpuRegisterState.R9);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR10, &CpuRegisterState.R10);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR11, &CpuRegisterState.R11);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR12, &CpuRegisterState.R12);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR13, &CpuRegisterState.R13);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR14, &CpuRegisterState.R14);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterR15, &CpuRegisterState.R15);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRip, &CpuRegisterState.RIP);
	HypervisorUtils_GetRegisterValue_U64(WHvX64RegisterRflags, &CpuRegisterState.RFLAGS);
	memcpy(pCpuRegisterState, &CpuRegisterState, sizeof(CpuRegisterState));

	return 0;
}

DWORD HypervisorUtils_SetRegisters(CpuRegisterStateStruct *pCpuRegisterState)
{
	// set register values
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRax, pCpuRegisterState->RAX);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRcx, pCpuRegisterState->RCX);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRdx, pCpuRegisterState->RDX);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRbx, pCpuRegisterState->RBX);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRsp, pCpuRegisterState->RSP);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRbp, pCpuRegisterState->RBP);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRsi, pCpuRegisterState->RSI);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRdi, pCpuRegisterState->RDI);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR8, pCpuRegisterState->R8);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR9, pCpuRegisterState->R9);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR10, pCpuRegisterState->R10);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR11, pCpuRegisterState->R11);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR12, pCpuRegisterState->R12);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR13, pCpuRegisterState->R13);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR14, pCpuRegisterState->R14);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterR15, pCpuRegisterState->R15);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRip, pCpuRegisterState->RIP);
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterRflags, pCpuRegisterState->RFLAGS);

	return 0;
}

DWORD HypervisorUtils_MapGuestMemory(void *pHostVirtualAddress, void *pGuestPhysicalAddress, DWORD dwSize)
{
	// map virtual memory region from host process into the guest
	if(WHvMapGpaRange(hGlobal_PartitionHandle, pHostVirtualAddress, (WHV_GUEST_PHYSICAL_ADDRESS)pGuestPhysicalAddress, dwSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute) != S_OK)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_UnmapGuestMemory(void *pGuestPhysicalAddress, DWORD dwSize)
{
	// unmap region
	if(WHvUnmapGpaRange(hGlobal_PartitionHandle, (WHV_GUEST_PHYSICAL_ADDRESS)pGuestPhysicalAddress, dwSize) != S_OK)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_ResumeExecution(WHV_RUN_VP_EXIT_CONTEXT *pVmExitContext)
{
	// resume cpu execution until next vmexit event
	if(WHvRunVirtualProcessor(hGlobal_PartitionHandle, 0, pVmExitContext, sizeof(WHV_RUN_VP_EXIT_CONTEXT)) != S_OK)
	{
		return 1;
	}

	return 0;
}

DWORD HypervisorUtils_FlushTLB()
{
	// reset cr3 register to force a TLB flush
	HypervisorUtils_SetRegisterValue_U64(WHvX64RegisterCr3, PAGE_TABLE_BASE_PHYSICAL_ADDRESS);

	return 0;
}
