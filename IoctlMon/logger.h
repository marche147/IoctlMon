/*!
 * \file logger.h
 * \date 2017/08/23 21:28
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * logger functions
 *
 * \note
*/

#ifndef _IOCTLMON_LOGGER_H
#define _IOCTLMON_LOGGER_H

//////////////////////////////////////////////////////////////////////////
// Macros

#define LOGGER_MAX_ENTRIES 1000

//////////////////////////////////////////////////////////////////////////
// Structures

typedef struct _LOG_ENTRY {
	LIST_ENTRY LogList;
	ULONG IoControlCode;
	BOOLEAN Async;
	CHAR ImageName[16];
	ULONG InputBufferLength;
	ULONG OutputBufferLength;
	PVOID InputBufferData;
	PVOID OutputBufferData;
} LOG_ENTRY, *PLOG_ENTRY;

typedef struct _LOG {
	ULONG Count;
	LIST_ENTRY LogList;
} LOG, *PLOG;

//////////////////////////////////////////////////////////////////////////
// Functions

EXTERN_C_START

VOID
NTAPI
LoggerInitialize(void);

VOID
NTAPI
LoggerTermination(void);

PLOG_ENTRY
NTAPI
LoggerPut(
	__in BOOLEAN Async,
	__in ULONG IoControlCode,
	__in ULONG InputBufferLength,
	__in PVOID InputBuffer,
	__in ULONG OutputBufferLength,
	__in PVOID OutputBuffer
	);

ULONG
NTAPI
LoggerGetEntryCount(void);

PLOG_ENTRY
NTAPI
LoggerGetFirstEntry(void);

BOOLEAN
NTAPI
LoggerRemoveFirstEntry(void);

EXTERN_C_END

#endif