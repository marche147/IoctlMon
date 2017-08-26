/*!
 * \file hook_handler.cpp
 * \date 2017/08/22 2:55
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * Handler for hooked system routines.
 *
 * \note
*/

#define NTSTRSAFE_NO_CCH_FUNCTIONS

#include "ddi_mon.h"
#include <ntstrsafe.h>
#include <sal.h>
#include "log.h"
#include "logger.h"

//////////////////////////////////////////////////////////////////////////
// Globals

extern BOOLEAN g_MonActivated;
extern HANDLE g_PIDFilter;
extern PDEVICE_OBJECT g_DevFilter;

static
BOOLEAN
NTAPI
IoctlMonShouldCaptureEvent(
	__in HANDLE FileHandle
	) {
	BOOLEAN bResult = FALSE;
	PFILE_OBJECT pFileObj = NULL;
	PDEVICE_OBJECT pDevObj = NULL;
	NTSTATUS s;
	OBJECT_HANDLE_INFORMATION handleInformation;

	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
	/* Don't hold mutex for less impact on performance */

	if (g_MonActivated) {
		/* check by PID */
		bResult = TRUE;

		if (g_PIDFilter == (HANDLE)-1 && g_DevFilter == NULL) {
			bResult = FALSE;
		}

		if (g_PIDFilter != (HANDLE)-1 && bResult) {
			if (PsGetCurrentProcessId() != g_PIDFilter) bResult = FALSE;
		}

		/* check by device pointer */
		if (g_DevFilter != NULL && bResult) {
			/* Reference the device */
			s = ObReferenceObjectByHandle(FileHandle, 0L, *IoFileObjectType, ExGetPreviousMode(), reinterpret_cast<PVOID*>(&pFileObj), &handleInformation);
			if (NT_SUCCESS(s)) {
				if (!(pFileObj->Flags & FO_DIRECT_DEVICE_OPEN)) {
					pDevObj = IoGetRelatedDeviceObject(pFileObj);
				}
				else {
					pDevObj = IoGetAttachedDevice(pFileObj->DeviceObject);
				}
				/* TODO : Maybe compare object name is better? */
				if (pDevObj != g_DevFilter) {
					bResult = FALSE;
				}
				ObDereferenceObject(pFileObj);
			}
		}
	}

	return bResult;
}

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
	) {

	using FuncType = NTSTATUS(
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

	FuncType* original = reinterpret_cast<FuncType*>(OriginalHandler);
	const bool isAsync = (Event != NULL);
	NTSTATUS s = STATUS_NOT_SUPPORTED;
	BOOLEAN shouldCapture = FALSE;
	PVOID capturedInput = NULL, capturedOutput = NULL;
	DWORD outputLength = 0;

	shouldCapture = IoctlMonShouldCaptureEvent(FileHandle);
	if (shouldCapture) {
		/* capture this Ioctl event */
		HYPERPLATFORM_LOG_INFO("Capturing Ioctl Event... input %d output %d\n", InputBufferLength, OutputBufferLength);

		__try {
			// copy input buffer
			ProbeForRead(InputBuffer, InputBufferLength, sizeof(UCHAR));
			capturedInput = ExAllocatePoolWithTag(NonPagedPoolNx, InputBufferLength, 'Cdib');
			if (capturedInput) {
				RtlCopyMemory(capturedInput, InputBuffer, InputBufferLength);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HYPERPLATFORM_LOG_INFO("Error when copying input from usermode %x\n", GetExceptionCode());
		}

		s = original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

		__try {
			if (isAsync) {
				HYPERPLATFORM_LOG_INFO("Async I/O, Output omitted.\n");
			}
			else {
				ProbeForRead(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(UCHAR));
				outputLength = (DWORD)IoStatusBlock->Information;
				ProbeForRead(OutputBuffer, outputLength, sizeof(UCHAR));

				capturedOutput = ExAllocatePoolWithTag(NonPagedPoolNx, outputLength, 'Cdob');
				if (capturedOutput) {
					RtlCopyMemory(capturedOutput, OutputBuffer, outputLength);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HYPERPLATFORM_LOG_INFO("Error when copying output from usermode %x\n", GetExceptionCode());
		}

		/* put it into the logger queue */
		if ((capturedInput || (InputBufferLength == 0)) && (capturedOutput || (outputLength == 0))) {
			LoggerPut(isAsync, IoControlCode, InputBufferLength, capturedInput, outputLength, capturedOutput);
		}
	}
	else {
		/* pass through */
		s = original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	}

	return s;
}