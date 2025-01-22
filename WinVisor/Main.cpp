#include "WinVisor.h"

#ifndef _WIN64
#error Must be compiled as 64-bit
#endif

int main(int argc, char *argv[])
{
	char *pTargetCommandLine = NULL;
	UINT64 qwWinVisorFlags = 0;
	DWORD dwPID = 0;

	printf("WinVisor\n");
	printf(" - x86matthew\n\n");

	// validate params
	if(argc < 2)
	{
		printf("Usage: %s [-debug] [-nx] <exe_name> [exe_params]\n", argv[0]);
		printf("   -debug    : Enable debug logging\n");
		printf("   -nx       : Set entire EXE image to non-executable in host process\n");
		printf("   -imports  : Include syscall logging for initial imported modules\n");
		return 1;
	}

	// parse command-line
	if(ParseCommandLine(argv[0], &pTargetCommandLine, &qwWinVisorFlags) != 0)
	{
		printf("Error: Invalid parameters\n");
		return 1;
	}

	// launch target process and attach WinVisor
	if(LaunchTargetProcess(pTargetCommandLine, qwWinVisorFlags, &dwPID) != 0)
	{
		printf("Error: Failed to launch WinVisor\n");
		return 1;
	}

	// read log messages
	if(StartLogClient(dwPID) != 0)
	{
		return 1;
	}

	return 0;
}
