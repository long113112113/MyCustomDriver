#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN BypassPatchGuard(void);

extern BOOLEAN g_PatchGuardBypassed;

//
// Runtime ntoskrnl image base/size, resolved through the loader list rather
// than assumed, so callers can anchor RVA-based work on the kernel that is
// actually running.
//
BOOLEAN BypassGetKernelBaseNSize(PVOID *OutBase, ULONG *OutSize);

#ifdef __cplusplus
}
#endif