/*!
 * \file main.cpp
 * \date 2017/08/24 1:44
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * test driver with user interaction
 *
 * \note
*/

#include <ntifs.h>

#define TEST_DEVNAME L"\\Device\\TestDevice"
#define TEST_DOSDEVNAME L"\\DosDevices\\TestDevice"

static
NTSTATUS
NTAPI
TestGeneralDispatch(
	__in PDEVICE_OBJECT pDevObj,
	__in PIRP pIrp
	) {
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION pIoStack = NULL;
	ULONG majorFunction;

	UNREFERENCED_PARAMETER(pDevObj);

	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	majorFunction = pIoStack->MajorFunction;

	if (majorFunction == IRP_MJ_CREATE ||
		majorFunction == IRP_MJ_CLOSE ||
		majorFunction == IRP_MJ_CLEANUP) {
		s = STATUS_SUCCESS;
	}

	pIrp->IoStatus.Status = s;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return s;
}

static
NTSTATUS
NTAPI
TestDeviceIoctlDispatch(
	__in PDEVICE_OBJECT pDevObj,
	__in PIRP pIrp
	) {
	NTSTATUS s = STATUS_SUCCESS;
	ULONG ioControlCode;
	PIO_STACK_LOCATION pIoStack = NULL;

	UNREFERENCED_PARAMETER(pDevObj);

	pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ioControlCode = pIoStack->Parameters.DeviceIoControl.IoControlCode;
	DbgPrint("Ioctl dispatch %x\n", ioControlCode);

	pIrp->IoStatus.Status = s;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return s;
}

static
VOID
NTAPI
TestUnload(
	__in PDRIVER_OBJECT pDrvObj
	) {
	PDEVICE_OBJECT pDevObj = NULL;
	UNICODE_STRING ustrSymName;

	RtlInitUnicodeString(&ustrSymName, TEST_DOSDEVNAME);
	IoDeleteSymbolicLink(&ustrSymName);

	pDevObj = pDrvObj->DeviceObject;
	IoDeleteDevice(pDevObj);

	DbgPrint("Driver unloaded\n");
	
	return;
}

EXTERN_C
NTSTATUS
NTAPI
DriverEntry(
	__in PDRIVER_OBJECT pDrvObj,
	__in PUNICODE_STRING pRegPath
	) {
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	UNICODE_STRING ustrDevName, ustrSymName;
	PDEVICE_OBJECT pDevObj = NULL;

	UNREFERENCED_PARAMETER(pRegPath);

	RtlInitUnicodeString(&ustrDevName, TEST_DEVNAME);
	s = IoCreateDevice(pDrvObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);
	if (!NT_SUCCESS(s)) {
		DbgPrint("Cannot create device %08x\n", s);
		return s;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDrvObj->MajorFunction[i] = TestGeneralDispatch;
	}
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TestDeviceIoctlDispatch;
	pDrvObj->DriverUnload = TestUnload;

	RtlInitUnicodeString(&ustrSymName, TEST_DOSDEVNAME);
	s = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
	if (!NT_SUCCESS(s)) {
		DbgPrint("Cannot create symlink %08x\n", s);
		IoDeleteDevice(pDevObj);
		return s;
	}

	ClearFlag(pDevObj->Flags, DO_DEVICE_INITIALIZING);
	DbgPrint("Device ready\n");

	return s;
}

