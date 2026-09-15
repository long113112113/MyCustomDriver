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

#define DRIVER_DEVICE_TYPE 0x8000

// Basic control
#define IOCTL_PING                                                             \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VERSION                                                      \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Sus zone
// TODO: add some fishy stuff

// Process DKOM (hide / reveal / list hidden)
#define IOCTL_HIDE_PROCESS                                                      \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_PROCESS                                                    \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_HIDDEN_PROCESSES                                             \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Exchange data struct
//

// Max number of processes tracked in the hidden registry.
#define MAX_HIDDEN_PROCESSES 64

// Input of IOCTL_HIDE_PROCESS / IOCTL_UNHIDE_PROCESS.
typedef struct _PROCESS_REQUEST {
  ULONG ProcessId;
} PROCESS_REQUEST, *PPROCESS_REQUEST;

// Output of IOCTL_LIST_HIDDEN_PROCESSES.
typedef struct _PROCESS_LIST_RESPONSE {
  ULONG Count;
  ULONG ProcessIds[MAX_HIDDEN_PROCESSES];
} PROCESS_LIST_RESPONSE, *PPROCESS_LIST_RESPONSE;

// default response
typedef struct _DRIVER_RESPONSE {
  NTSTATUS Status;
  ULONG Data;
} DRIVER_RESPONSE, *PDRIVER_RESPONSE;