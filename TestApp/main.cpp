/*!
 * \file main.cpp
 * \date 2017/08/24 22:10
 *
 * \author marche147
 * Contact: bitmarche@gmail.com
 *
 * \brief 
 *
 * test app
 *
 * \note
*/

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "../Common/common.h"

#define IOCTL_RANDOM CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char* argv[]) {
	HANDLE hFile = CreateFile(TEXT("\\\\.\\TestDevice"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("CreateFile() = %d\n", GetLastError());
		return -1;
	}

	getchar();

	ULONG buf, retlen;
	buf = 0x41424344;
	if (!DeviceIoControl(hFile, IOCTL_RANDOM, &buf, 4, &buf, 4, &retlen, NULL)) {
		printf("DeviceIoControl() = %d\n", GetLastError());
	}

	CloseHandle(hFile);
	return 0;
}