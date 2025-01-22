#include "WinVisor.h"

char *SkipWhitespace(char *pString)
{
	char *pCurrPtr = NULL;

	// find first non-space character
	pCurrPtr = pString;
	for(;;)
	{
		if(*pCurrPtr != ' ')
		{
			break;
		}
		pCurrPtr++;
	}

	return pCurrPtr;
}

DWORD CheckCommandLineSwitch(char *pCommandLinePtr, char *pSwitchName, char **ppUpdatedCommandLinePtr)
{
	char szTemp[64];
	char *pUpdatedCommandLinePtr = NULL;

	// check if this is the specified command-line switch
	memset(szTemp, 0, sizeof(szTemp));
	_snprintf(szTemp, sizeof(szTemp) - 1, "-%s ", pSwitchName);
	if(strncmp(pCommandLinePtr, szTemp, strlen(szTemp)) != 0)
	{
		return 1;
	}

	// update command line ptr
	pUpdatedCommandLinePtr = pCommandLinePtr;
	pUpdatedCommandLinePtr += strlen(szTemp);
	pUpdatedCommandLinePtr = SkipWhitespace(pUpdatedCommandLinePtr);

	// store ptr
	*ppUpdatedCommandLinePtr = pUpdatedCommandLinePtr;

	return 0;
}

DWORD ParseCommandLine(char *pFirstParam, char **ppTargetCommandLine, UINT64 *pqwWinVisorFlags)
{
	DWORD dwIgnoreCharCount = 0;
	char *pTargetCommandLine = NULL;
	UINT64 qwWinVisorFlags = 0;

	// skip the first param (this exe)
	dwIgnoreCharCount = (DWORD)strlen(pFirstParam);
	pTargetCommandLine = GetCommandLineA();
	if(*pTargetCommandLine == '\"')
	{
		dwIgnoreCharCount += 2;
	}
	pTargetCommandLine += dwIgnoreCharCount;

	// ignore leading spaces
	pTargetCommandLine = SkipWhitespace(pTargetCommandLine);

	for(;;)
	{
		// check if this is a command-line switch
		if(*pTargetCommandLine == '-')
		{
			// check switch type
			if(CheckCommandLineSwitch(pTargetCommandLine, "debug", &pTargetCommandLine) == 0)
			{
				qwWinVisorFlags |= WINVISOR_FLAG_DEBUG_LOG;
			}
			else if(CheckCommandLineSwitch(pTargetCommandLine, "nx", &pTargetCommandLine) == 0)
			{
				qwWinVisorFlags |= WINVISOR_FLAG_NX;
			}
			else if(CheckCommandLineSwitch(pTargetCommandLine, "imports", &pTargetCommandLine) == 0)
			{
				qwWinVisorFlags |= WINVISOR_FLAG_IMPORTS;
			}
			else
			{
				// unknown switch
				return 1;
			}
		}
		else
		{
			break;
		}
	}

	// store cmdline ptr and flags
	*ppTargetCommandLine = pTargetCommandLine;
	*pqwWinVisorFlags = qwWinVisorFlags;

	return 0;
}
