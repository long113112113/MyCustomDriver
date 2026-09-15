#include "Device.h"
#include "Dispatch.h"
#include <ntddk.h>

// Symlink and device name.
#define DEVICE_NAME L"\\Device\\LongsDriver"
#define SYMLINK_NAME L"\\DosDevices\\LongsDriver"

PDEVICE_OBJECT g_DeviceObject = NULL;

//
// LOAD DRIVER function
//
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS status;
  UNICODE_STRING deviceName, symlinkName;

  DbgPrint("DriverEntry start\n");

  // Init unload
  DriverObject->DriverUnload = DriverUnload;

  // Init Device Object
  RtlInitUnicodeString(&deviceName, DEVICE_NAME);
  status = IoCreateDevice(DriverObject,
                          0, // DeviceExtension size
                          &deviceName, FILE_DEVICE_UNKNOWN,
                          FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

  if (!NT_SUCCESS(status)) {
    DbgPrint("IoCreateDevice failed: 0x%X\n", status);
    return status;
  }

  // Init Symbolic Link
  RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
  status = IoCreateSymbolicLink(&symlinkName, &deviceName);

  if (!NT_SUCCESS(status)) {
    DbgPrint("IoCreateSymbolicLink failed: 0x%X\n", status);
    IoDeleteDevice(g_DeviceObject);
    return status;
  }

  // Regis Dispatch Routines
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

  // TODO: Init kernel model
  // DriverInitialize();

  DbgPrint("Driver loaded successfully.\n");
  return STATUS_SUCCESS;
}

//
// UNLOAD DRIVER function
//
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING symlinkName;

  DbgPrint("DriverUnload start\n");

  // TODO: Unload kernel model
  //  DriverCleanup();

  // Clean symbolic link
  RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
  IoDeleteSymbolicLink(&symlinkName);

  // Clean device object
  if (g_DeviceObject) {
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
  }

  DbgPrint("Driver unloaded.\n");
}
