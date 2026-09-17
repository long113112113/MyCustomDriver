#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN BypassPatchGuard(void);

extern BOOLEAN g_PatchGuardBypassed;

#ifdef __cplusplus
}
#endif