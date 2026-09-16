#pragma once
#include <ntddk.h>
#include "Shared.h"

//
// DKOM thread module lifecycle. Invoked from DriverEntry / DriverUnload.
//
NTSTATUS ThreadModuleInitialize(VOID);
VOID ThreadModuleCleanup(VOID);

NTSTATUS ThreadHide(ULONG ThreadId);
NTSTATUS ThreadUnhide(ULONG ThreadId);

//
// Fills Response with the TIDs currently hidden.
//
NTSTATUS ThreadListHidden(PTHREAD_LIST_RESPONSE Response);