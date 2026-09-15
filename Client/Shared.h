#pragma once

//
// IOCTL CODES
//
// CTL_CODE(DeviceType, Function, Method, Access)

#if defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_WDMDDK_)
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#endif

#define ROOTKIT_DEVICE_TYPE 0x8000

// Basic control
#define IOCTL_PING                                                             \
  CTL_CODE(ROOTKIT_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VERSION                                                      \
  CTL_CODE(ROOTKIT_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Sus zone
// TODO: add some fishy stuff

//
// Exchange data struct
//
// TODO: Struct for control fishy stuff

// Struct for default reponse
typedef struct _DRIVER_RESPONSE {
  NTSTATUS Status;
  ULONG Data;
} DRIVER_RESPONSE, *PDRIVER_RESPONSE;