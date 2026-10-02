#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// User-mode APC delivery.
//
// Queues a user-mode routine into every thread of a target process. This is
// the execution half of the reflective load: the routine is the target's own
// ReflectiveLoader address, so nothing of the driver runs in the target.
//
// Delivery model
// --------------
// A user-mode APC only runs when its thread enters an alertable wait. That is
// why the routine is queued to all threads rather than one: any of them
// reaching an alertable wait is enough, and a single busy thread would
// otherwise strand the APC forever.
//
// Lifecycle
// ---------
// Each queued APC is a nonpaged KAPC. The kernel routine frees it on delivery
// and the rundown routine frees it if the thread exits first. ApcInjectCleanup
// claims whatever is still queued and waits for in-flight ones, so unloading
// the driver cannot leave a queued APC pointing at freed code.
//
// All entry points require IRQL <= APC_LEVEL; a dispatch-level caller is
// refused rather than allowed to corrupt the target's APC state.
//

//
// One-time module state. ApcInjectInitialize is idempotent; ApcInjectCleanup
// drains and may be called once from DriverUnload.
//
NTSTATUS ApcInjectInitialize(VOID);
VOID ApcInjectCleanup(VOID);

//
// Queues UserRoutine into every thread of TargetPid.
//
// UserRoutine must be a user-mode address valid in the target's address space;
// UserContext is passed through as the routine's first argument.
//
// Always queues to every thread reachable in one walk. ThreadsQueued is
// optional and receives the number of successful insertions; zero with
// STATUS_SUCCESS means the process had no threads, which is not an error.
//
// Returns STATUS_SUCCESS, STATUS_INVALID_PARAMETER (null routine),
// STATUS_NOT_FOUND (the snapshot listed no threads for the process),
// STATUS_PROCESS_IS_TERMINATING, the snapshot/lookup status, or
// STATUS_DELETE_PENDING while the module is shutting down.
//
NTSTATUS ApcInjectQueueToProcess(ULONG TargetPid, PVOID UserRoutine,
                                 PVOID UserContext, PULONG ThreadsQueued);

#ifdef __cplusplus
}
#endif