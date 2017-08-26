/*!
 * \file IoctlMon.cpp
 * \date 2017/08/22 22:12
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * IoctlMon source file
 *
 * \note
*/

#include <ntddk.h>
#include <sal.h>
#include "IoctlMon.h"
#include "logger.h"

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, IoctlMonInitialization)
#pragma alloc_text(PAGE, IoctlMonTermination)
#endif

//////////////////////////////////////////////////////////////////////////
// Globals

BOOLEAN g_MonActivated = FALSE; /* IoctlMon activated */
HANDLE g_PIDFilter = (HANDLE)-1; /* Filter by PID */
PDEVICE_OBJECT g_DevFilter = (PDEVICE_OBJECT)NULL; /* Filter by Device Object */
KMUTEX g_Mutex; /* Global mutex */

EXTERN_C
NTSTATUS
NTAPI
IoctlMonInitialization(
	__in PDRIVER_OBJECT pDrvObj
	) {
	NTSTATUS s = STATUS_UNSUCCESSFUL;

	s = IoctlMonCreateDevice(pDrvObj);
	KeInitializeMutex(&g_Mutex, 0);

	LoggerInitialize();

	return s;
}

EXTERN_C
VOID
NTAPI
IoctlMonTermination(
	__in PDRIVER_OBJECT pDrvObj
	) {
	PAGED_CODE();

	IoctlMonRemoveDevice(pDrvObj);
	LoggerTermination();
	return;
}