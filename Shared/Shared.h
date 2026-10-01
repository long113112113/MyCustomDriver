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

#define IOCTL_TASK_CONTROL                                                     \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TASK_SET_IMAGE_PATH                                              \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x907, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS                                                  \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x908, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNPROTECT_PROCESS                                                \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_PROTECTED_PROCESSES                                         \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x90A, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// Reports whether anti-kill is armed, and if not, why. Output
// PROTECT_STATUS_RESPONSE.
//
#define IOCTL_GET_PROTECT_STATUS                                               \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x90B, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Code 0x90C is retired: it was IOCTL_PROBE_CALLBACK_MODULES, the callback
// module scanner. That direction produced no usable gadget and the gate is now
// relaxed directly in ObRegisterCallbacks, so the operation and its response
// structure were removed. The slot stays reserved rather than being reused, so
// a stale client cannot accidentally reach a different handler.
//
#define IOCTL_RETIRED_PROBE_CALLBACK_MODULES 0x90C

//
// Elevate / unelevate / query the calling client thread's token. All three
// take no input and answer ELEVATE_STATUS_RESPONSE.
//
// The target is always the thread that issued the call - there is no PID
// parameter anywhere in this group, so the driver cannot be pointed at another
// process.
//
#define IOCTL_ELEVATE_SELF                                                       \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x90D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNELEVATE_SELF                                                     \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x90E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_ELEVATION                                                    \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x90F, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Disable / restore / query the Microsoft-Windows-Threat-Intelligence (ETW-TI)
// provider. DISABLE and ENABLE take no input; STATUS answers
// ETWTI_STATUS_RESPONSE.
//
#define IOCTL_ETWTI_DISABLE                                                      \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ETWTI_ENABLE                                                       \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ETWTI_STATUS                                                       \
  CTL_CODE(DRIVER_DEVICE_TYPE, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Codes 0x913 upward are free. Allocate the next new operation from 0x913 to
// keep the driver's dispatch table contiguous.
//

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

// Lowest PID that is a real user process. PIDs 0-4 are the idle process,
// the System process and its threads, none of which may be hidden or
// protected.
#define SYSTEM_PROCESS_PID 4

// Max number of processes tracked in the hidden registry.
#define MAX_HIDDEN_PROCESSES 64

// Max number of threads tracked in the hidden registry.
#define MAX_HIDDEN_THREADS 64

// Max number of processes tracked in the anti-kill registry.
#define MAX_PROTECTED_PROCESSES 64

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
// Output of IOCTL_LIST_PROTECTED_PROCESSES.
typedef struct _PROTECTED_PROCESS_LIST_RESPONSE {
  ULONG Count;
  ULONG ProcessIds[MAX_PROTECTED_PROCESSES];
} PROTECTED_PROCESS_LIST_RESPONSE,
    *PPROTECTED_PROCESS_LIST_RESPONSE;

// Output of IOCTL_GET_PROTECT_STATUS.
typedef struct _PROTECT_STATUS_RESPONSE {
  // Status the module returned from ProcessProtectInitialize. STATUS_SUCCESS
  // means the Ob callback is registered.
  NTSTATUS InitStatus;
  // 1 when the callback handle is live, 0 otherwise.
  ULONG CallbackActive;
  // Number of PIDs currently in the protected registry.
  ULONG Count;
  // Status ObGatePatchApply returned before registration was attempted. This
  // separates "the gate was never relaxed" from "the gate was relaxed and still
  // refused": STATUS_REVISION_MISMATCH means the ntoskrnl bytes did not match
  // the recorded signature, STATUS_DEVICE_CONFIGURATION_ERROR means the patch
  // was deliberately declined (PatchGuard inactive, or memory integrity
  // enforced), STATUS_NOT_FOUND means ntoskrnl could not be located.
  NTSTATUS GatePatchStatus;
  // 1 while the patched bytes are installed in ntoskrnl, 0 otherwise.
  ULONG GatePatchApplied;
  // Pre-operation callback traffic. Total counts every invocation; Hits counts
  // those whose object was a protected PID; Stripped counts those where access
  // rights were actually reduced. A Total that grows while Protected stays 0
  // means the callback is live but the consumer is reusing a handle it opened
  // before the PID was protected, which stripping cannot revoke.
  ULONG PreOpTotal;
  ULONG PreOpProtectedHits;
  ULONG PreOpStripped;
} PROTECT_STATUS_RESPONSE, *PPROTECT_STATUS_RESPONSE;

// Output of IOCTL_ELEVATE_SELF / IOCTL_UNELEVATE_SELF / IOCTL_QUERY_ELEVATION.
typedef struct _ELEVATE_STATUS_RESPONSE {
  // STATUS_SUCCESS once the requested state change has been applied, otherwise
  // the reason it was refused.
  NTSTATUS Status;
  // 1 when the calling thread carries an impersonation token, 0 when it does
  // not. Reported after the operation, so the client can confirm the result
  // rather than infer it from the absence of an error.
  ULONG Elevated;
  // TID of the thread the IOCTL was dispatched on, i.e. the thread these three
  // fields describe. Echoed so a client that spawns threads can tell which one
  // ended up elevated.
  ULONG ThreadId;
} ELEVATE_STATUS_RESPONSE, *PELEVATE_STATUS_RESPONSE;

//
// Output of IOCTL_ETWTI_DISABLE / IOCTL_ETWTI_ENABLE / IOCTL_ETWTI_STATUS.
//
// The resolved chain is reported verbatim so a failed run can be diagnosed from
// a debugger dump without re-running the resolution. Addresses are reported as
// raw virtual addresses of the running kernel, not as offsets, because the
// object they point at lives in a pool allocation whose address moves with the
// boot.
//
typedef struct _ETWTI_STATUS_RESPONSE {
  // STATUS_SUCCESS when the requested operation completed. On DISABLE and ENABLE
  // this is the module's result; on STATUS it is the resolution result, so a
  // failure there means the chain could not be walked at all rather than that
  // the provider is enabled.
  NTSTATUS Status;
  // 1 while this module holds ETW-TI disabled, 0 otherwise.
  ULONG Disabled;
  // Value of IsEnabled captured by the last successful DISABLE, i.e. the value
  // ENABLE puts back.
  ULONG SavedValue;
  // Live IsEnabled value. Read-only for STATUS.
  ULONG CurrentValue;
  // Address of the global that EtwRegister fills with the provider handle.
  ULONGLONG SlotAddress;
  // Address of the ETW_REGISTRY_ENTRY that handle refers to.
  ULONGLONG EntryAddress;
  // Address of the enable record; IsEnabled is CurrentValue's location.
  ULONGLONG EnableInfoAddress;
  // Number of times the auto-apply worker has tried since driver load. A counter
  // that keeps climbing means the provider had not registered yet; a counter
  // frozen below the last successful Disable means the worker thread is gone.
  ULONG ArmAttempts;
} ETWTI_STATUS_RESPONSE, *PETWTI_STATUS_RESPONSE;

//
// The CALLBACK_MODULE_HIT / CALLBACK_MODULE_PROBE_RESPONSE structures that
// accompanied IOCTL_PROBE_CALLBACK_MODULES were removed together with it.
//

// default response
typedef struct _DRIVER_RESPONSE {
  NTSTATUS Status;
  ULONG Data;
} DRIVER_RESPONSE, *PDRIVER_RESPONSE;