/*!
 * \file IoctlMon.h
 * \date 2017/08/22 22:14
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * IoctlMon header file
 *
 * \note
*/

#ifndef _IOCTLMON_H
#define _IOCTLMON_H

EXTERN_C
NTSTATUS
NTAPI
IoctlMonNtDeviceIoControlFileHook(
	__in PVOID OriginalHandler,
	__in HANDLE FileHandle,
	__in_opt HANDLE Event,
	__in_opt PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcContext,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in ULONG IoControlCode,
	__in_bcount_opt(InputBufferLength) PVOID InputBuffer,
	__in ULONG InputBufferLength,
	__out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferLength
	);

EXTERN_C
VOID
NTAPI
IoctlMonRemoveDevice(PDRIVER_OBJECT pDrvObj);

EXTERN_C
NTSTATUS
NTAPI
IoctlMonCreateDevice(PDRIVER_OBJECT pDrvObj);

//////////////////////////////////////////////////////////////////////////
// Init & Fini

EXTERN_C
NTSTATUS
NTAPI
IoctlMonInitialization(
	__in PDRIVER_OBJECT pDrvObj
	);

EXTERN_C
VOID
NTAPI
IoctlMonTermination(
	__in PDRIVER_OBJECT pDrvObj
	);

#endif