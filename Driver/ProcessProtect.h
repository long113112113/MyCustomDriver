#pragma once
#include "Shared.h"

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
