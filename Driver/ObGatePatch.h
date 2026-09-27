#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Relaxes the two "callback must live in an allowed module" gates inside
// ObRegisterCallbacks on ntoskrnl 10.0.26100.4351.
//
// ObRegisterCallbacks validates PreOperation/PostOperation by calling the
// shared helper FUN_1404fbf34(callback, 0x20), which resolves the callback
// address through the loader database. The driver is manually mapped, so that
// lookup fails and registration is rejected with STATUS_ACCESS_DENIED even
// though the gate is the only thing standing in the way.
//
// The patch is applied at the two call sites inside ObRegisterCallbacks rather
// than at the helper's entry: the helper has four callers (including
// PsSetCreateThreadNotifyRoutineEx) and rewriting it would silently disable
// validation for unrelated process/thread notification consumers.
//
// Nothing is written until the bytes at the target match the recorded 26100.4351
// signature exactly, so a different kernel build fails closed instead of
// corrupting ntoskrnl.
//
NTSTATUS ObGatePatchApply(VOID);

//
// Restores the original bytes. Safe to call when nothing was patched.
//
VOID ObGatePatchRevert(VOID);

//
// TRUE while the patched bytes are installed.
//
BOOLEAN ObGatePatchIsApplied(VOID);

#ifdef __cplusplus
}
#endif
