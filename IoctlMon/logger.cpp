/*!
 * \file logger.cpp
 * \date 2017/08/23 19:19
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * logging functions
 *
 * \note
*/

#include <ntddk.h>
#include <sal.h>
#include "logger.h"

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, LoggerInitialize)
#pragma alloc_text(PAGE, LoggerTermination)
#endif

EXTERN_C NTKERNELAPI CHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

//////////////////////////////////////////////////////////////////////////
// Globals

LOG g_Logs = { 0, {NULL, NULL} };
KMUTEX g_LogMutex;

//////////////////////////////////////////////////////////////////////////
// Functions

EXTERN_C
VOID
NTAPI
LoggerInitialize( void ) {
	g_Logs.Count = 0;
	InitializeListHead(&(g_Logs.LogList));
	KeInitializeMutex(&g_LogMutex, 0);
	return;
}

EXTERN_C
VOID
NTAPI
LoggerTermination( void ) {
	// destroy all logs
	PLOG_ENTRY ptr;
	PLIST_ENTRY list_ptr = g_Logs.LogList.Flink;

	KeWaitForMutexObject(&g_LogMutex, Executive, KernelMode, FALSE, NULL);
	while (list_ptr != &g_Logs.LogList) {
		ptr = CONTAINING_RECORD(list_ptr, LOG_ENTRY, LogList);
		list_ptr = list_ptr->Flink;

		ExFreePool(ptr->InputBufferData);
		ExFreePool(ptr->OutputBufferData);

		RemoveEntryList(&(ptr->LogList));
		ExFreePool(ptr);
	}
	KeReleaseMutex(&g_LogMutex, FALSE);
	return;
}

EXTERN_C
PLOG_ENTRY
NTAPI
LoggerPut(
	__in BOOLEAN Async,
	__in ULONG IoControlCode,
	__in ULONG InputBufferLength,
	__in PVOID InputBuffer,
	__in ULONG OutputBufferLength,
	__in PVOID OutputBuffer
	) {
	PLOG_ENTRY log_entry = NULL;
	CHAR* imageFileName = NULL;

	imageFileName = PsGetProcessImageFileName(PsGetCurrentProcess());

	KeWaitForMutexObject(&g_LogMutex, UserRequest, KernelMode, FALSE, NULL);

	if (g_Logs.Count >= LOGGER_MAX_ENTRIES) {
		goto BailOut;
	}

	log_entry = reinterpret_cast<PLOG_ENTRY>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LOG_ENTRY), 'LogE'));
	if (!log_entry) {
		goto BailOut;
	}

	log_entry->Async = Async;
	log_entry->IoControlCode = IoControlCode;
	log_entry->InputBufferLength = InputBufferLength;
	log_entry->InputBufferData = InputBuffer;
	log_entry->OutputBufferLength = OutputBufferLength;
	log_entry->OutputBufferData = OutputBuffer;
	RtlCopyMemory(log_entry->ImageName, imageFileName, 16);	

	InsertTailList(&(g_Logs.LogList), &(log_entry->LogList));
	g_Logs.Count++;

BailOut:
	KeReleaseMutex(&g_LogMutex, FALSE);
	return log_entry;
}

EXTERN_C
ULONG
NTAPI
LoggerGetEntryCount( void ) {
	return g_Logs.Count;
}

EXTERN_C
PLOG_ENTRY
NTAPI
LoggerGetFirstEntry( void ) {
	PLOG_ENTRY result = NULL;

	KeWaitForMutexObject(&g_LogMutex, UserRequest, KernelMode, FALSE, NULL);
	if (g_Logs.Count == 0 || IsListEmpty(&g_Logs.LogList)) {
		goto BailOut;
	}
	result = CONTAINING_RECORD(g_Logs.LogList.Flink, LOG_ENTRY, LogList);
BailOut:
	KeReleaseMutex(&g_LogMutex, FALSE);
	return result;
}

EXTERN_C
BOOLEAN
NTAPI
LoggerRemoveFirstEntry( void ) {
	BOOLEAN result = FALSE;
	PLOG_ENTRY ptr = NULL;

	KeWaitForMutexObject(&g_LogMutex, UserRequest, KernelMode, FALSE, NULL);
	if (g_Logs.Count == 0 || IsListEmpty(&g_Logs.LogList)) {
		goto BailOut;
	}
	ptr = CONTAINING_RECORD(g_Logs.LogList.Flink, LOG_ENTRY, LogList);
	RemoveEntryList(&(ptr->LogList));
	ExFreePool(ptr->InputBufferData);
	ExFreePool(ptr->OutputBufferData);
	ExFreePool(ptr);
	g_Logs.Count--;

BailOut:
	KeReleaseMutex(&g_LogMutex, FALSE);
	return result;
}