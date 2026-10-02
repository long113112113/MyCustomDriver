#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// The shell image this module is built to locate. Kept as a macro so the
// intended target is visible at the call site instead of being buried in the
// .c.
//
#define PROCESS_LOOKUP_EXPLORER L"explorer.exe"

// Room for the NT device path of an image, e.g.
// \Device\HarddiskVolume3\Windows\explorer.exe
#define PROCESS_LOOKUP_PATH_MAX 320

//
// Output of FindExplorerProcessInfo. Everything is resolved by a single walk
// of the process list, so the struct describes one instance rather than a
// snapshot taken across several calls.
//
typedef struct _PROCESS_LOOKUP_INFO {
  // STATUS_SUCCESS when ProcessObject holds a live EPROCESS address,
  // STATUS_NOT_FOUND when no live process carried the image name.
  NTSTATUS Status;
  // PID of the resolved instance.
  ULONG ProcessId;
  // How many live instances carried the name. Anything above 1 means the box
  // runs more than one shell (extra sessions, a leftover from a fast-user
  // switch); only the first is returned.
  ULONG InstanceCount;
  // EPROCESS address of the resolved instance. Reported as a raw number, not a
  // pointer, so the value survives being copied into a user-mode reply buffer.
  ULONGLONG ProcessObject;
  // Image path as the kernel reports it for that process.
  CHAR ImagePath[PROCESS_LOOKUP_PATH_MAX];
} PROCESS_LOOKUP_INFO, *PPROCESS_LOOKUP_INFO;

//
// Resolves the PID of the first live process whose image file name is
// ImageName, compared case-insensitively against the trailing path component
// only, so both L"explorer.exe" and a full device path are accepted.
//
// Nothing is retained: no EPROCESS is handed back and no reference is held, so
// there is nothing to release. ProcessId is written on every path, including
// failures, so a caller that only checks the write cannot mistake a failure for
// PID 0 in use.
//
// Returns STATUS_SUCCESS, STATUS_NOT_FOUND (no live match),
// STATUS_INVALID_PARAMETER, or a failure from the system snapshot query.
//
NTSTATUS FindProcessIdByName(PCWSTR ImageName, PULONG ProcessId);

//
// FindProcessIdByName for PROCESS_LOOKUP_EXPLORER.
//
NTSTATUS FindExplorerProcessId(PULONG ProcessId);

//
// Resolves the EPROCESS of the first live process matching ImageName.
//
// The returned object is referenced by this call and stays valid after it
// returns; it must be handed back to ReleaseLookupProcess. ProcessOut is set
// to NULL on every failure path, so the caller never has to guess whether it
// owns a reference. Prefer FindProcessIdByName when the PID is all that is
// needed: this entry point exists for the case where the caller must act on the
// object itself.
//
// Returns STATUS_SUCCESS, STATUS_NOT_FOUND, or STATUS_INVALID_PARAMETER.
//
NTSTATUS FindProcessByName(PCWSTR ImageName, PEPROCESS *ProcessOut);

//
// FindProcessByName for PROCESS_LOOKUP_EXPLORER. Reference handling is
// identical.
//
NTSTATUS FindExplorerProcess(PEPROCESS *ProcessOut);

//
// Same lookup, reported as data rather than as a handle. Useful while wiring
// the feature up: it names the PID and the image path, so a miss says "not
// running" and a hit can be confirmed against Task Manager without a
// debugger. Takes no reference that outlives the call.
//
NTSTATUS FindExplorerProcessInfo(PPROCESS_LOOKUP_INFO Info);

//
// Drops a reference obtained from FindProcessByName / FindExplorerProcess.
// Tolerates NULL so an error path needs no separate guard.
//
VOID ReleaseLookupProcess(PEPROCESS Process);

//
// Copies up to Capacity thread IDs of ProcessId out of a fresh system
// snapshot. Count receives how many were written.
//
// Used by the APC injector: having the TIDs lets it pin each thread through
// PsLookupThreadByThreadId instead of walking ETHREAD lists and referencing
// nodes that may be exiting.
//
// Returns STATUS_SUCCESS, STATUS_NOT_FOUND (the process had no threads in the
// snapshot), STATUS_INVALID_PARAMETER, or a snapshot failure.
//
NTSTATUS ProcessLookupGetThreadIds(ULONG ProcessId, PULONG ThreadIds,
                                   ULONG Capacity, PULONG Count);

#ifdef __cplusplus
}
#endif