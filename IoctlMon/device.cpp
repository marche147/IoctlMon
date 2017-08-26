/*!
 * \file device.cpp
 * \date 2017/08/22 2:58
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * Device for communicate with userspace
 *
 * \note
*/

#include "log.h"
#include "../Common/common.h"
#include <wdmsec.h>
#include "logger.h"

#pragma comment(lib, "wdmsec.lib")
//////////////////////////////////////////////////////////////////////////
// Prototypes

EXTERN_C
static
NTSTATUS
NTAPI
IoctlMonGeneralDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp);

EXTERN_C
static
NTSTATUS
NTAPI
IoctlMonDeviceIoctlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp);

EXTERN_C
NTSTATUS
NTAPI
IoctlMonCreateDevice(PDRIVER_OBJECT pDrvObj);

EXTERN_C
VOID
NTAPI
IoctlMonRemoveDevice(PDRIVER_OBJECT pDrvObj);

//////////////////////////////////////////////////////////////////////////
// Globals 

extern BOOLEAN g_MonActivated;
extern HANDLE g_PIDFilter;
extern PDEVICE_OBJECT g_DevFilter;
extern KMUTEX g_Mutex;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, IoctlMonCreateDevice)
#pragma alloc_text(PAGE, IoctlMonGeneralDispatch)
#pragma alloc_text(PAGE, IoctlMonRemoveDevice)
#endif

// {49BE6D6C-8946-48CB-B00D-ACA4257C4740}
static const GUID IOCTLMON_GUID =
{ 0x49be6d6c, 0x8946, 0x48cb,{ 0xb0, 0xd, 0xac, 0xa4, 0x25, 0x7c, 0x47, 0x40 } };

static
NTSTATUS
NTAPI
IoctlMonCaptureUnicodeString(
	__in PUNICODE_STRING ustrTarget,
	__in BOOLEAN bBuffered,
	__out PUNICODE_STRING ustrCaptured
	) {
	
	PWSTR userBuffer = NULL;
	UNICODE_STRING temp;

	ustrCaptured->Buffer = NULL;
	__try {
		if (!bBuffered) {
			ProbeForRead(ustrTarget, sizeof(UNICODE_STRING), sizeof(ULONG_PTR));
		}
		if (ustrTarget->Length & 1) {
			return STATUS_INVALID_PARAMETER;
		}
		temp.Length = temp.MaximumLength = ustrTarget->Length;
		userBuffer = ustrTarget->Buffer;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	temp.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, temp.Length + sizeof(WCHAR), 'Uscp'));
	if (!temp.Buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(temp.Buffer, temp.Length + sizeof(WCHAR));
	__try {
		ProbeForRead(userBuffer, temp.Length, sizeof(WCHAR));
		RtlCopyMemory(temp.Buffer, userBuffer, temp.Length);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	*ustrCaptured = temp;
	return STATUS_SUCCESS;
}

static
VOID
NTAPI
IoctlMonFreeCapturedUnicodeString(
	__in PUNICODE_STRING ustrCaptured
	) {
	if (ustrCaptured->Buffer) {
		ExFreePool(ustrCaptured->Buffer);
	}
	return;
}

static
NTSTATUS
NTAPI
IoctlMonSetCaptureByDevice(
	__in PUNICODE_STRING IoBuffer
	) {
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	UNICODE_STRING ustrCaptured, ustrNoDevice;
	PFILE_OBJECT pFileObj = NULL;
	PDEVICE_OBJECT pDevObj = NULL;

	s = IoctlMonCaptureUnicodeString(IoBuffer, TRUE, &ustrCaptured);
	if (!NT_SUCCESS(s)) {
		HYPERPLATFORM_LOG_INFO("Failed capture string");
		goto Bailout;
	}

	RtlInitUnicodeString(&ustrNoDevice, L"NoDevice");
	if (RtlCompareUnicodeString(&ustrCaptured, &ustrNoDevice, TRUE) == 0) {
		KeWaitForMutexObject(&g_Mutex, UserRequest, KernelMode, FALSE, NULL);
		g_DevFilter = NULL; /* set device pointer  */
		KeReleaseMutex(&g_Mutex, FALSE);
		goto Bailout;
	}

	s = IoGetDeviceObjectPointer(&ustrCaptured, FILE_READ_DATA, &pFileObj, &pDevObj);
	if (!NT_SUCCESS(s)) {
		DbgPrint("Failed open device %ws, s = %08X\n", ustrCaptured.Buffer, s);
		goto Bailout;
	}

	KeWaitForMutexObject(&g_Mutex, UserRequest, KernelMode, FALSE, NULL);
	g_DevFilter = pDevObj; /* set device pointer  */
	KeReleaseMutex(&g_Mutex, FALSE);

Bailout:
	if (pFileObj) {
		ObDereferenceObject(pFileObj);
	}
	IoctlMonFreeCapturedUnicodeString(&ustrCaptured);
	return s;
}

EXTERN_C
static
NTSTATUS
NTAPI
IoctlMonGeneralDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS s = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStack = NULL;
	ULONG majorFunction = 0xFFFFFFFF;

	UNREFERENCED_PARAMETER(pDevObj);

	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	majorFunction = pIoStack->MajorFunction;
	if (
		majorFunction == IRP_MJ_CLOSE ||
		majorFunction == IRP_MJ_CREATE ||
		majorFunction == IRP_MJ_CLEANUP) {
		s = STATUS_SUCCESS;
	}

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = s;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return s;
}

EXTERN_C
static
NTSTATUS
NTAPI
IoctlMonDeviceIoctlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION pIoStack = NULL;
	ULONG ioControlCode, inBufLen, outBufLen;
	PVOID ioBuf;
	PLOG_ENTRY logEntry = NULL;
	PIO_LOG_INFO info = NULL;
	PIO_LOG_DATA data = NULL;
	
	UNREFERENCED_PARAMETER(pDevObj);
	
	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ioControlCode = pIoStack->Parameters.DeviceIoControl.IoControlCode;
	inBufLen = pIoStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLen = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioBuf = pIrp->AssociatedIrp.SystemBuffer;	/* we use buffered I/O */

	switch (ioControlCode) {
	case IOCTL_IM_SET_CAPTURED_PID:
		/* set capture-by-process PID */
		outBufLen = 0;
		if (inBufLen < sizeof(HANDLE)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}

		KeWaitForMutexObject(&g_Mutex, UserRequest, KernelMode, FALSE, NULL);
		g_PIDFilter = *(HANDLE*)(ioBuf);
		KeReleaseMutex(&g_Mutex, FALSE);

		s = STATUS_SUCCESS;

		HYPERPLATFORM_LOG_INFO("Set captured PID = %d\n", g_PIDFilter);

		break;
	case IOCTL_IM_SET_CAPTURED_DEVICE:
		/* set capture-by-device */
		outBufLen = 0;
		if (inBufLen < sizeof(UNICODE_STRING)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}
		s = IoctlMonSetCaptureByDevice((PUNICODE_STRING)ioBuf);
		break;
	case IOCTL_IM_SET_MONITOR_ACTIVE:
		outBufLen = 0;
		if (inBufLen < sizeof(ULONG)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}

		KeWaitForMutexObject(&g_Mutex, UserRequest, KernelMode, FALSE, NULL);
		g_MonActivated = *(BOOLEAN*)ioBuf;
		KeReleaseMutex(&g_Mutex, FALSE);

		s = STATUS_SUCCESS;

		HYPERPLATFORM_LOG_INFO("Mon Activated = %d\n", g_MonActivated);
		break;
	case IOCTL_IM_GET_CURRENT_LOG_COUNT:
		if (outBufLen < sizeof(ULONG)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}

		*(PULONG)ioBuf = LoggerGetEntryCount();
		outBufLen = sizeof(ULONG);
		s = STATUS_SUCCESS;
		break;
	case IOCTL_IM_GET_FIRST_LOG_INFO:
		if (outBufLen < sizeof(IO_LOG_INFO)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}

		logEntry = LoggerGetFirstEntry();
		if (!logEntry) {
			s = STATUS_UNSUCCESSFUL;
			outBufLen = 0;
			break;
		}

		info = reinterpret_cast<PIO_LOG_INFO>(ioBuf);
		info->Async = logEntry->Async;
		info->IoControlCode = logEntry->IoControlCode;
		info->InputBufferLength = logEntry->InputBufferLength;
		info->OutputBufferLength = logEntry->OutputBufferLength;
		RtlCopyMemory(info->ProcessName, logEntry->ImageName, 16);

		s = STATUS_SUCCESS;
		break;
	case IOCTL_IM_GET_FIRST_LOG_DATA:
		if (inBufLen < sizeof(IO_LOG_DATA) || outBufLen < sizeof(IO_LOG_DATA)) {
			s = STATUS_INVALID_PARAMETER;
			break;
		}
		data = reinterpret_cast<PIO_LOG_DATA>(ioBuf);

		logEntry = LoggerGetFirstEntry();
		if (!logEntry) {
			s = STATUS_UNSUCCESSFUL;
			outBufLen = 0;
		}

		__try {
			ProbeForWrite(data->InputBuffer, logEntry->InputBufferLength, sizeof(UCHAR));
			ProbeForWrite(data->OutputBuffer, logEntry->OutputBufferLength, sizeof(UCHAR));
			RtlCopyMemory(data->InputBuffer, logEntry->InputBufferData, logEntry->InputBufferLength);
			RtlCopyMemory(data->OutputBuffer, logEntry->OutputBufferData, logEntry->OutputBufferLength);
			s = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			outBufLen = 0;
			s = GetExceptionCode();
		}

		break;
	case IOCTL_IM_REMOVE_FIRST_LOG:

		outBufLen = 0;
		if (LoggerRemoveFirstEntry()) {
			s = STATUS_SUCCESS;
		}
		else {
			s = STATUS_UNSUCCESSFUL;
		}

		break;
	default:
		s = STATUS_NOT_SUPPORTED;
		outBufLen = 0;
		break;
	}

	pIrp->IoStatus.Status = s;
	pIrp->IoStatus.Information = (ULONG_PTR)outBufLen;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return s;
}

EXTERN_C
NTSTATUS 
NTAPI 
IoctlMonCreateDevice( PDRIVER_OBJECT pDrvObj ) {
	PDEVICE_OBJECT pDevObj = NULL;
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	UNICODE_STRING ustrDevName, ustrSymName;

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDrvObj->MajorFunction[i] = IoctlMonGeneralDispatch;
	}
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlMonDeviceIoctlDispatch;

	RtlInitUnicodeString(&ustrDevName, IOCTLMON_DEVICE_NAME);
	s = IoCreateDeviceSecure(pDrvObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, &IOCTLMON_GUID, &pDevObj);
	if (!NT_SUCCESS(s)) {
		goto Bailout;
	}

	RtlInitUnicodeString(&ustrSymName, IOCTLMON_DOSDEVICE_NAME);
	s = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
	if (!NT_SUCCESS(s)) {
		IoDeleteDevice(pDevObj);
		goto Bailout;
	}

	ClearFlag(pDevObj->Flags, DO_DEVICE_INITIALIZING);

Bailout:
	return s;
}

EXTERN_C
VOID
NTAPI
IoctlMonRemoveDevice( PDRIVER_OBJECT pDrvObj ) {
	PDEVICE_OBJECT pDevObj = pDrvObj->DeviceObject;
	UNICODE_STRING ustrSymName;

	RtlInitUnicodeString(&ustrSymName, IOCTLMON_DOSDEVICE_NAME);
	IoDeleteSymbolicLink(&ustrSymName);
	IoDeleteDevice(pDevObj);

	return;
}
