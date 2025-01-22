#define LOG_PIPE_NAME "\\\\.\\pipe\\WinVisorLog"

#define HOOK_ENTRY_POINT_CODE_SIZE 16

#define WINVISOR_FLAG_DEBUG_LOG 0x1
#define WINVISOR_FLAG_NX 0x2
#define WINVISOR_FLAG_IMPORTS 0x4

struct WinVisorStartDataStruct
{
	BYTE bOrigEntryPointCode[HOOK_ENTRY_POINT_CODE_SIZE];
	UINT64 qwWinVisorFlags;
	IMAGE_NT_HEADERS64 OrigNtHeader;
};
