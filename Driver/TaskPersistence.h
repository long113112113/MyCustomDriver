#pragma once
#include "Shared.h"
#include <ntddk.h>

NTSTATUS TaskPersistenceInitialize(VOID);

VOID TaskPersistenceCleanup(VOID);

NTSTATUS TaskPersistenceControl(ULONG Operation, PULONG State);

NTSTATUS TaskPersistenceSetImagePath(PWCHAR Path, ULONG CharCount);