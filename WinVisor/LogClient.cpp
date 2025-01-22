#include "WinVisor.h"

DWORD StartLogClient(DWORD dwPID)
{
	BYTE bByte = 0;
	DWORD dwRead = 0;
	HANDLE hPipe = NULL;
	char szPipeName[512];

	// append target PID to pipe name to allow multiple instances
	memset(szPipeName, 0, sizeof(szPipeName));
	_snprintf(szPipeName, sizeof(szPipeName) - 1, "%s_%u", LOG_PIPE_NAME, dwPID);

	for(;;)
	{
		// open named pipe from parent process
		hPipe = CreateFileA(szPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if(hPipe == INVALID_HANDLE_VALUE)
		{
			Sleep(100);
			continue;
		}

		break;
	}

	// read from pipe and print to console
	for(;;)
	{
		// get next character
		if(ReadFile(hPipe, &bByte, 1, &dwRead, NULL) == 0)
		{
			break;
		}

		if(dwRead == 0)
		{
			break;
		}

		printf("%c", bByte);
	}

	// finished
	CloseHandle(hPipe);

	return 0;
}
