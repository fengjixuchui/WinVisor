#include "WinVisorDLL.h"

DWORD dwGlobal_StopLog = 0;
DWORD dwGlobal_DebugLogEnabled = 0;
HANDLE hGlobal_LogPipe = NULL;

DWORD InitialiseLogServer()
{
	char szPipeName[512];

	// append PID to pipe name to allow multiple instances
	memset(szPipeName, 0, sizeof(szPipeName));
	_snprintf(szPipeName, sizeof(szPipeName) - 1, "%s_%u", LOG_PIPE_NAME, GetCurrentProcessId());

	// create logging pipe
	hGlobal_LogPipe = CreateNamedPipeA(szPipeName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 0, 0, 0, NULL);
	if(hGlobal_LogPipe == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// wait for child process to connect
	ConnectNamedPipe(hGlobal_LogPipe, NULL);

	return 0;
}

DWORD CloseLogServer()
{
	if(hGlobal_LogPipe != NULL)
	{
		// close log pipe
		CloseHandle(hGlobal_LogPipe);
	}

	return 0;
}

DWORD WriteLog(DWORD dwLogType, char *pStringFormat, ...)
{
	va_list VaList;
	char szFormattedString[1024];
	char szFullMsg[2048];
	DWORD dwWritten = 0;
	char *pLogType = NULL;

	// format string
	va_start(VaList, pStringFormat);
	memset(szFormattedString, 0, sizeof(szFormattedString));
	_vsnprintf(szFormattedString, sizeof(szFormattedString) - 1, pStringFormat, VaList);
	va_end(VaList);

	// check type
	if(dwLogType == LOG_INFO)
	{
		pLogType = "INFO";
	}
	else if(dwLogType == LOG_ERROR)
	{
		pLogType = "ERROR";
	}
	else if(dwLogType == LOG_DEBUG)
	{
		if(dwGlobal_DebugLogEnabled == 0)
		{
			// debug logging disabled
			return 1;
		}

		pLogType = "DEBUG";
	}
	else
	{
		return 1;
	}

	// generate full log message
	memset(szFullMsg, 0, sizeof(szFullMsg));
	_snprintf(szFullMsg, sizeof(szFullMsg) - 1, "[%s] %s\n", pLogType, szFormattedString);

	if(dwGlobal_StopLog == 0)
	{
		// write to pipe
		WriteFile(hGlobal_LogPipe, szFullMsg, (DWORD)strlen(szFullMsg), &dwWritten, NULL);
	}

	return 0;
}
