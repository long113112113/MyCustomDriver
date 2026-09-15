#pragma once
#include <ntddk.h>

NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);