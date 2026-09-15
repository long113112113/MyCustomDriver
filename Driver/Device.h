#pragma once
#include <ntddk.h>

extern PDEVICE_OBJECT g_DeviceObject;

// Prototype of DriverUnload (DriverEntry.c)
VOID DriverUnload(PDRIVER_OBJECT DriverObject);