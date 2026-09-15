#include "Dispatch.h"
#include "FishyFunctions.h"
#include "Shared.h"
#include <ntddk.h>

//
// Process income connect from client
//
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  DbgPrint("Client connected.\n");

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

//
// Process close connect from client
//
NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  DbgPrint("Client disconnected.\n");

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

//
// Process IOCTL
//
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS status = STATUS_SUCCESS;
  ULONG bytesReturned = 0;

  ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
  PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
  PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
  ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
  ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

  DbgPrint("IOCTL received: 0x%X\n", ioctlCode);

  switch (ioctlCode) {

  // ------------------------------------------------------
  // PING
  // ------------------------------------------------------
  case IOCTL_PING:
    DbgPrint("PING called\n");
    if (outputLength >= sizeof(DRIVER_RESPONSE)) {
      PDRIVER_RESPONSE response = (PDRIVER_RESPONSE)outputBuffer;
      response->Status = STATUS_SUCCESS;
      response->Data = 0xDEADBEEF;
      bytesReturned = sizeof(DRIVER_RESPONSE);
    } else {
      status = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  // ------------------------------------------------------
  // GET_VERSION
  // ------------------------------------------------------
  case IOCTL_GET_VERSION:
    DbgPrint("GET_VERSION called\n");
    if (outputLength >= sizeof(DRIVER_RESPONSE)) {
      PDRIVER_RESPONSE response = (PDRIVER_RESPONSE)outputBuffer;
      response->Status = STATUS_SUCCESS;
      response->Data = 0x00010000;
      bytesReturned = sizeof(DRIVER_RESPONSE);
    } else {
      status = STATUS_BUFFER_TOO_SMALL;
    }
    break;

    // ------------------------------------------------------
    // TODO: Fishy call here
    // ------------------------------------------------------

  default:
    DbgPrint("Unknown IOCTL: 0x%X\n", ioctlCode);
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = bytesReturned;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}