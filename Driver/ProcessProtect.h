#pragma once
#include "Shared.h"

//
// Altitude the Ob callback is registered at. Kept as a macro because Windows
// assigns callback order by altitude string, and changing it changes where this
// filter sits relative to other registered filters.
//
#define PROCESS_PROTECT_ALTITUDE L"31105.6171"

//
// Process anti-kill module. Invoked from DriverEntry / DriverUnload.
//
NTSTATUS ProcessProtectInitialize(VOID);
VOID ProcessProtectCleanup(VOID);

NTSTATUS ProcessProtect(ULONG ProcessId);
NTSTATUS ProcessUnprotect(ULONG ProcessId);

//
// Fills Response with the PIDs currently protected.
//
NTSTATUS ProcessListProtected(PPROTECTED_PROCESS_LIST_RESPONSE Response);

//
// TRUE when the Ob callback is registered and protection is armed.
//
BOOLEAN ProcessProtectAvailable(VOID);

//
// Fills Response with the module's registration outcome.
//
NTSTATUS ProcessProtectQueryStatus(PPROTECT_STATUS_RESPONSE Response);
