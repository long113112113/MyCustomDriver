#pragma once
#include <ntddk.h>

//
// Writes raw bytes into read-only / execute-disabled memory by temporarily
// clearing the CR0 write-protect bit at DPC_LEVEL with interrupts masked.
// Used to patch win32kfull code pages and to seed the executable trampoline
// buffer that lives in the driver's .text section.
//
NTSTATUS KernelWrite(PVOID Destination, PVOID Source, SIZE_T Size);