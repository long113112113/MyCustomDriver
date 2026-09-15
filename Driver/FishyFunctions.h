#pragma once
#include <ntddk.h>

NTSTATUS RootkitInitialize(VOID);
VOID RootkitCleanup(VOID);

// TODO: