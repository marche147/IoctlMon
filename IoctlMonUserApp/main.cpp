/*!
 * \file main.cpp
 * \date 2017/08/24 1:01
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * command utility for IoctlMon
 *
 * \note
*/

#define STRSAFE_NO_CCH_FUNCTIONS
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <Windows.h>
#include <stdlib.h>
#include <strsafe.h>
#include <time.h>
#include "../Common/common.h"

#pragma warning(disable:4267)

CHAR* LOG_SEP = "---------------------------------------------------------------------------------\r\n";

//////////////////////////////////////////////////////////////////////////
// Structures

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
	PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

//////////////////////////////////////////////////////////////////////////
// Globals

HANDLE g_IoctlMonDevice = INVALID_HANDLE_VALUE;
HANDLE g_OutputFile = INVALID_HANDLE_VALUE;
HANDLE g_Thread = NULL;
BOOL g_Run = TRUE;

//////////////////////////////////////////////////////////////////////////
// Utility Functions

void __declspec(noreturn) Fatal(char* msg) {
	fprintf(stderr, "[-] FatalError : %s, GetLastError() = %d\n", msg, GetLastError());
	exit(-1);
}

VOID DbgPrint(char* format, ...) {
	CHAR Buffer[512];
	va_list args;

	va_start(args, format);
	vsprintf_s(Buffer, format, args);
	va_end(args);

#ifdef USE_WINAPI
	OutputDebugStringA(Buffer);
#else
	fputs(Buffer, stderr);
#endif

	return;
}

BOOL UnloadDriver(LPCWSTR driverName)
{
	BOOL result = FALSE;
	SC_HANDLE scm = NULL, scService = NULL;
	SERVICE_STATUS s;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm) return FALSE;

	scService = OpenService(scm, driverName, SERVICE_ALL_ACCESS);
	if (scService) {
		ControlService(scService, SERVICE_CONTROL_STOP, &s);
		if (DeleteService(scService))	result = TRUE;
	}

	if (scm)		CloseServiceHandle(scm);
	if (scService)	CloseServiceHandle(scService);
	return result;
}

BOOL LoadDriver(LPCWSTR driverName, LPCWSTR driverPath, BOOL forceOverride)
{
	SC_HANDLE scm;
	SC_HANDLE scService;
	BOOL result = FALSE;
	TCHAR FilePath[MAX_PATH];

	GetFullPathName(driverPath, MAX_PATH, FilePath, NULL);
	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)	return FALSE;

	scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, FilePath, NULL, NULL, NULL, NULL, NULL);
	if (!scService) {
		if (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_SERVICE_EXISTS) {
			scService = OpenService(scm, driverName, SERVICE_ALL_ACCESS);
			if (!scService) goto Finish;
			if (forceOverride) {	// recreate
				if (!DeleteService(scService)) goto Finish;
				scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, NULL, NULL, NULL, NULL, NULL);
				if (!scService)	goto Finish;
			}
		}
		else goto Finish;
	}
	if (!StartService(scService, 0, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) result = TRUE;
	}
	result = TRUE;

Finish:
	if (scm) CloseServiceHandle(scm);
	if (scService) CloseServiceHandle(scService);
	return result;
}

//////////////////////////////////////////////////////////////////////////
// Ioctl Functions

BOOL SetMonitorState(BOOL Activated) {
	ULONG temp = (ULONG)(Activated);
	ULONG retlen;
	BOOL result = DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_SET_MONITOR_ACTIVE, &temp, sizeof(ULONG), &temp, sizeof(ULONG), &retlen, NULL);

	return result;
}

BOOL SetMonitoringPID(HANDLE Pid) {
	HANDLE temp = Pid;
	ULONG retlen;
	BOOL result = DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_SET_CAPTURED_PID, &temp, sizeof(HANDLE), &temp, sizeof(HANDLE), &retlen, NULL);

	return result;
}

BOOL SetMonitoringDevice(PWSTR DevicePath) {
	UNICODE_STRING temp;
	ULONG retlen;

	temp.Length = temp.MaximumLength = (USHORT)(wcslen(DevicePath) * 2);
	temp.Buffer = DevicePath;
	BOOL result = DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_SET_CAPTURED_DEVICE, &temp, sizeof(UNICODE_STRING), &temp, sizeof(UNICODE_STRING), &retlen, NULL);

	return result;
}

BOOL GetCurrentLogCount(LPDWORD ReturnValue) {
	ULONG retlen;
	return DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_GET_CURRENT_LOG_COUNT, ReturnValue, sizeof(DWORD), ReturnValue, sizeof(DWORD), &retlen, NULL);
}

BOOL GetFirstLogInfo(PIO_LOG_INFO LogInfo) {
	ULONG retlen;
	return DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_GET_FIRST_LOG_INFO, LogInfo, sizeof(IO_LOG_INFO), LogInfo, sizeof(IO_LOG_INFO), &retlen, NULL);
}

BOOL GetFirstLogData(PIO_LOG_DATA LogData) {
	ULONG retlen;
	return DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_GET_FIRST_LOG_DATA, LogData, sizeof(IO_LOG_DATA), LogData, sizeof(IO_LOG_DATA), &retlen, NULL);
}

BOOL RemoveFirstLog(void) {
	ULONG retval;
	return DeviceIoControl(g_IoctlMonDevice, IOCTL_IM_REMOVE_FIRST_LOG, &retval, 0, &retval, 0, &retval, NULL);
}

//////////////////////////////////////////////////////////////////////////
// Functionality

static VOID WriteHexDump(BYTE* data, ULONG len) {
	CHAR LineBuffer[512];
	CHAR PrintableBuf[32];
	ULONG offset = 0;

	while (1) {
		sprintf_s(LineBuffer, "%08X: ", offset);
		CHAR* ptr = LineBuffer + strlen(LineBuffer);
		CHAR* ptr2 = PrintableBuf;
		for (ULONG i = 0; i < 0x10; i++) {
			if (i + offset >= len) break;
			ptr += sprintf_s(ptr, sizeof(LineBuffer) - strlen(LineBuffer), "%02X ", data[i + offset]);
			*ptr2 = isprint(data[i + offset]) ? data[i + offset] : '.';
			ptr2++;
		}
		*ptr2 = 0;
		for (ULONG i = strlen(LineBuffer); i < 80; i++) {
			LineBuffer[i] = ' ';
		}
		ptr = LineBuffer + 80;
		sprintf_s(ptr, sizeof(LineBuffer) - 80, "%s\r\n", PrintableBuf);

		WriteFile(g_OutputFile, LineBuffer, strlen(LineBuffer), NULL, NULL);

		offset += 0x10;
		if (offset >= len) break;
	}
	return;
}

static VOID LogToFile(PIO_LOG_INFO LogInfo, PIO_LOG_DATA LogData) {
	CHAR Buffer[512];
	CHAR timebuf[128];
	struct tm t;
	time_t time_val;
	CHAR* LOG_INPUT = "Input bytedump :\r\n";
	CHAR* LOG_OUTPUT = "Output bytedump :\r\n";

	WriteFile(g_OutputFile, LOG_SEP, strlen(LOG_SEP), NULL, NULL);

	time_val = time(NULL);
	if (localtime_s(&t, &time_val)) {
		DbgPrint("Get time failed");
		return;
	}

	strftime(timebuf, sizeof(timebuf), "[%Y-%m-%d %H:%M:%S]", &t);
	sprintf_s(Buffer, "%s ImageName : %16s, Async : %s, IoControlCode : %08x, InputLen : %d, OutputLen : %d\r\n", timebuf, LogInfo->ProcessName, LogInfo->Async ? "Yes": "No", LogInfo->IoControlCode, LogInfo->InputBufferLength, LogInfo->OutputBufferLength);
	WriteFile(g_OutputFile, Buffer, strlen(Buffer), NULL, NULL);

	/* Write hexdump to file */
	WriteFile(g_OutputFile, LOG_INPUT, strlen(LOG_INPUT), NULL, NULL);
	WriteHexDump((BYTE*)LogData->InputBuffer, LogInfo->InputBufferLength);

	if (!LogInfo->Async) {
		WriteFile(g_OutputFile, LOG_OUTPUT, strlen(LOG_OUTPUT), NULL, NULL);
		WriteHexDump((BYTE*)LogData->OutputBuffer, LogInfo->OutputBufferLength);
	}

	return;
}

static DWORD WINAPI LogThread(PVOID Context) {
	IO_LOG_INFO logInfo;
	IO_LOG_DATA logData;

	DbgPrint("LogThread started\n");

	while (g_Run) {
		ULONG logCount;
		if (!GetCurrentLogCount(&logCount)) {
			goto Bed;
		}

		//DbgPrint("LogCount = %d\n", logCount);
		for (ULONG i = 0; i < logCount; i++) {
			//DbgPrint("Capturing...\n");
			if (!GetFirstLogInfo(&logInfo)) {
				goto Remove;
			}

			logData.InputBuffer = HeapAlloc(GetProcessHeap(), 0, logInfo.InputBufferLength);
			if(!logInfo.Async)
				logData.OutputBuffer = HeapAlloc(GetProcessHeap(), 0, logInfo.OutputBufferLength);

			if (!GetFirstLogData(&logData)) {
				HeapFree(GetProcessHeap(), 0, logData.InputBuffer);
				if(!logInfo.Async)
					HeapFree(GetProcessHeap(), 0, logData.OutputBuffer);
				logData.InputBuffer = logData.OutputBuffer = NULL;
				goto Remove;
			}

			/* log to file */
			LogToFile(&logInfo, &logData);
			//DbgPrint("Input Len = %d, Output Len = %d\n", logInfo.InputBufferLength, logInfo.OutputBufferLength);

			HeapFree(GetProcessHeap(), 0, logData.InputBuffer);
			if (!logInfo.Async)
				HeapFree(GetProcessHeap(), 0, logData.OutputBuffer);
			logData.InputBuffer = logData.OutputBuffer = NULL;

		Remove:
			RemoveFirstLog();
		}
	Bed:
		Sleep(1000); // and sleep
	}

	DbgPrint("LogThread stopped\n");

	return 0;
}

static BOOL WINAPI CtrlHandler(DWORD CtrlType) {
	/* do cleanup */
	printf("Detected Ctrl-C Event, Cleaning up...\n");

	g_Run = FALSE;

	WaitForSingleObject(g_Thread, INFINITE);

	FlushFileBuffers(g_OutputFile);
	CloseHandle(g_OutputFile);

	SetMonitorState(FALSE);
	UnloadDriver(TEXT("IoctlMon"));

	ExitProcess(0);
	return TRUE;
}

static void __declspec(noreturn) usage(char* exe)
{
	printf("Usage : %s [-l] [-u] [-p PID] [-d DevicePath]\n", exe);
	puts("-l\tload driver");
	puts("-u\tunload driver");
	puts("-p\tset monitored process");
	puts("-d\tset monitored device");

	ExitProcess(-1);
}

//////////////////////////////////////////////////////////////////////////
// Entry point

int main(int argc, char* argv[]) {
	BOOL s = FALSE;

	struct {
		HANDLE Pid;
		CHAR* DeviceName;
		CHAR* OutputFile;
		BOOL Load;
		BOOL Unload;
	} Args = { INVALID_HANDLE_VALUE, NULL, "dump.log", FALSE, FALSE };
	WCHAR Buffer[512];

	RtlZeroMemory(Buffer, sizeof(Buffer));
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0) {
			if (i == argc - 1) {
				puts("Missing argument PID");
				exit(-1);
			}
			Args.Pid = (HANDLE)(atoll(argv[++i]));
		}
		else if (strcmp(argv[i], "-d") == 0) {
			if (i == argc - 1) {
				puts("Missing argument DeviceName");
				exit(-1);
			}
			Args.DeviceName = argv[++i];
		}
		else if (strcmp(argv[i], "-d") == 0) {
			if (i == argc - 1) {
				puts("Missing argument OutputFile");
				exit(-1);
			}
			Args.OutputFile = argv[++i];
		}
		else if (strcmp(argv[i], "-l") == 0) {
			Args.Load = TRUE;
		}
		else if (strcmp(argv[i], "-u") == 0) {
			Args.Unload = TRUE;
		}
		else {
			usage(argv[0]);
		}
	}

	if (Args.Load) {
		if (LoadDriver(TEXT("IoctlMon"), TEXT("DdiMon.sys"), FALSE)) {
			printf("Driver successfully loaded\n");
		}
		else {
			Fatal("LoadDriver");
		}
		return 0;
	}

	if (Args.Unload) {
		if (UnloadDriver(TEXT("IoctlMon"))) {
			printf("Driver successfully removed\n");
		}
		else {
			Fatal("UnloadDriver");
		}
		return 0;
	}

	if (Args.Pid == INVALID_HANDLE_VALUE && Args.DeviceName == NULL) {
		puts("No argument provided");
		exit(-1);
	}

	g_OutputFile = CreateFileA(Args.OutputFile, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_OutputFile == INVALID_HANDLE_VALUE) {
		Fatal("CreateOutputFile");
	}

	g_IoctlMonDevice = CreateFile(TEXT("\\\\.\\IoctlMon"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (g_IoctlMonDevice == INVALID_HANDLE_VALUE) {
		Fatal("OpenDevice");
	}

	if (!SetMonitoringPID(Args.Pid)) {
		Fatal("SetMonitorPID");
	}
	if (Args.DeviceName != NULL) {
		MultiByteToWideChar(CP_OEMCP, MB_ERR_INVALID_CHARS, Args.DeviceName, -1, Buffer, ARRAYSIZE(Buffer));
		if (!SetMonitoringDevice(Buffer)) { Fatal("SetMonitorDevice"); }
	}
	else {
		SetMonitoringDevice(L"NoDevice");
	}
	if (!SetMonitorState(TRUE)) { Fatal("SetMonitorState"); }

	g_Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LogThread, NULL, 0, NULL);
	if (!g_Thread) {
		Fatal("CreateThread");
	}
	puts("Logging Ioctl Events...");
	WaitForSingleObject(g_Thread, INFINITE);
	
	return 0;
}