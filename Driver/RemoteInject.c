//
// ntifs.h must precede other headers for the process attach and Zw virtual
// memory declarations this module relies on.
//
#include <ntifs.h>
#include "RemoteInject.h"
#include "Shared.h"

//
// ZwProtectVirtualMemory is exported by ntoskrnl and present in ntoskrnl.lib,
// but no WDK header declares it, so the prototype is repeated here. The import
// resolves at link time like the other Zw calls; nothing here needs to be
// resolved by name at runtime.
//
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle,
                                               PVOID *BaseAddress,
                                               PSIZE_T RegionSize,
                                               ULONG NewProtect,
                                               PULONG OldProtect);

//
// Looks up TargetPid and returns a referenced EPROCESS that is still alive.
//
// Also the single IRQL gate for the module: allocation, protection and
// attachment are all PASSIVE_LEVEL-only, and every public entry point starts
// here, so the check cannot be forgotten by a future caller.
//
// PIDs 0 and 4 are refused - the Idle and System processes have no address
// space that can carry this - and a process that has begun terminating is
// refused too, because its address space is about to be torn down.
//
static NTSTATUS ReferenceTargetProcess(ULONG TargetPid, PEPROCESS *ProcessOut) {
  NTSTATUS status;

  if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
    DbgPrint("[LongsDriver] RemoteInject: refused at IRQL %u.\n",
             KeGetCurrentIrql());
    return STATUS_INVALID_DEVICE_STATE;
  }

  if (ProcessOut == NULL)
    return STATUS_INVALID_PARAMETER;

  *ProcessOut = NULL;

  if (TargetPid <= SYSTEM_PROCESS_PID)
    return STATUS_INVALID_PARAMETER;

  status = PsLookupProcessByProcessId(ULongToHandle(TargetPid), ProcessOut);
  if (!NT_SUCCESS(status))
    return status;

  if (PsGetProcessExitStatus(*ProcessOut) != STATUS_PENDING) {
    ObDereferenceObject(*ProcessOut);
    *ProcessOut = NULL;
    return STATUS_PROCESS_IS_TERMINATING;
  }

  return STATUS_SUCCESS;
}

//
// The three helpers below run with the caller already attached to the target,
// so "current process" is the target and NtCurrentProcess() is the right
// handle. None of them logs: the attach window is kept to allocation and copy
// work, both because the documented guidance is to keep the window simple and
// because DbgPrint inside it can stall the target's address space.
//

static NTSTATUS AllocateInCurrentProcess(PSIZE_T Size, ULONG Protect,
                                         PVOID *BaseOut) {
  PVOID base = NULL;
  SIZE_T size = *Size;
  NTSTATUS status;

  status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                   MEM_COMMIT | MEM_RESERVE, Protect);
  if (!NT_SUCCESS(status))
    return status;

  *BaseOut = base;
  *Size = size;
  return STATUS_SUCCESS;
}

//
// ProbeForWrite plus SEH rather than a bare RtlCopyMemory. The destination is
// user memory in a process this module does not control, so the target can
// unmap it or remove write access concurrently; the guard turns that race into
// an access-violation status instead of a kernel fault, and it is what makes it
// safe to report the failure rather than bugcheck.
//
static NTSTATUS WriteToCurrentProcess(PVOID RemoteAddress, const VOID *Source,
                                      SIZE_T Size) {
  NTSTATUS status = STATUS_SUCCESS;

  __try {
    ProbeForWrite(RemoteAddress, Size, sizeof(UCHAR));
    RtlCopyMemory(RemoteAddress, Source, Size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
  }

  return status;
}

static NTSTATUS ReadFromCurrentProcess(PVOID RemoteAddress, PVOID Buffer,
                                       SIZE_T Size) {
  NTSTATUS status = STATUS_SUCCESS;

  __try {
    ProbeForRead(RemoteAddress, Size, sizeof(UCHAR));
    RtlCopyMemory(Buffer, RemoteAddress, Size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
  }

  return status;
}

static NTSTATUS ProtectInCurrentProcess(PVOID RemoteAddress, SIZE_T Size,
                                        ULONG NewProtect, PULONG OldProtect) {
  PVOID base = RemoteAddress;
  SIZE_T regionSize = Size;
  ULONG oldProtect = 0;
  NTSTATUS status;

  //
  // BaseAddress is in/out: the kernel is allowed to round it down or otherwise
  // adjust it, so it is passed in a local copy and the caller's address is
  // never rewritten by a call that only meant to change protection.
  //
  status = ZwProtectVirtualMemory(NtCurrentProcess(), &base, &regionSize,
                                  NewProtect, &oldProtect);
  if (!NT_SUCCESS(status))
    return status;

  if (OldProtect != NULL)
    *OldProtect = oldProtect;

  return STATUS_SUCCESS;
}

static NTSTATUS FreeInCurrentProcess(PVOID RemoteAddress) {
  PVOID base = RemoteAddress;
  //
  // MEM_RELEASE demands a zero RegionSize and releases exactly the allocation
  // starting at BaseAddress, so the caller only has to remember the base.
  //
  SIZE_T size = 0;

  return ZwFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
}

NTSTATUS RemoteInjectAllocate(ULONG TargetPid, PSIZE_T Size, ULONG Protect,
                              PVOID *RemoteBase) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;
  PVOID base = NULL;

  if (Size == NULL || RemoteBase == NULL)
    return STATUS_INVALID_PARAMETER;

  *RemoteBase = NULL;
  if (*Size == 0)
    return STATUS_INVALID_PARAMETER;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  KeStackAttachProcess(target, &apcState);
  status = AllocateInCurrentProcess(Size, Protect, &base);
  KeUnstackDetachProcess(&apcState);

  ObDereferenceObject(target);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] RemoteInject: allocate in pid %lu failed "
             "0x%X.\n",
             TargetPid, status);
    return status;
  }

  DbgPrint("[LongsDriver] RemoteInject: pid %lu allocated %llu bytes at %p "
           "(protect 0x%X).\n",
           TargetPid, (ULONGLONG)*Size, base, Protect);

  *RemoteBase = base;
  return STATUS_SUCCESS;
}

NTSTATUS RemoteInjectWrite(ULONG TargetPid, PVOID RemoteAddress,
                           const VOID *Source, SIZE_T Size) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;

  if (RemoteAddress == NULL || Source == NULL || Size == 0)
    return STATUS_INVALID_PARAMETER;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  KeStackAttachProcess(target, &apcState);
  status = WriteToCurrentProcess(RemoteAddress, Source, Size);
  KeUnstackDetachProcess(&apcState);

  ObDereferenceObject(target);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] RemoteInject: write %llu bytes to pid %lu at %p "
             "failed 0x%X.\n",
             (ULONGLONG)Size, TargetPid, RemoteAddress, status);
  }

  return status;
}

NTSTATUS RemoteInjectRead(ULONG TargetPid, PVOID RemoteAddress, PVOID Buffer,
                          SIZE_T Size) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;

  if (RemoteAddress == NULL || Buffer == NULL || Size == 0)
    return STATUS_INVALID_PARAMETER;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  KeStackAttachProcess(target, &apcState);
  status = ReadFromCurrentProcess(RemoteAddress, Buffer, Size);
  KeUnstackDetachProcess(&apcState);

  ObDereferenceObject(target);

  return status;
}

NTSTATUS RemoteInjectProtect(ULONG TargetPid, PVOID RemoteAddress, SIZE_T Size,
                             ULONG NewProtect, PULONG OldProtect) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;

  if (RemoteAddress == NULL || Size == 0 || NewProtect == 0)
    return STATUS_INVALID_PARAMETER;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  KeStackAttachProcess(target, &apcState);
  status = ProtectInCurrentProcess(RemoteAddress, Size, NewProtect, OldProtect);
  KeUnstackDetachProcess(&apcState);

  ObDereferenceObject(target);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] RemoteInject: protect pid %lu at %p failed "
             "0x%X.\n",
             TargetPid, RemoteAddress, status);
  }

  return status;
}

NTSTATUS RemoteInjectFree(ULONG TargetPid, PVOID RemoteAddress) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;

  if (RemoteAddress == NULL)
    return STATUS_INVALID_PARAMETER;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  KeStackAttachProcess(target, &apcState);
  status = FreeInCurrentProcess(RemoteAddress);
  KeUnstackDetachProcess(&apcState);

  ObDereferenceObject(target);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] RemoteInject: free in pid %lu at %p failed "
             "0x%X.\n",
             TargetPid, RemoteAddress, status);
  }

  return status;
}

NTSTATUS RemoteInjectImage(ULONG TargetPid, const VOID *ImageBuffer,
                           SIZE_T ImageSize, ULONG FinalProtect,
                           PVOID *RemoteBase, PSIZE_T RemoteSize) {
  NTSTATUS status;
  PEPROCESS target = NULL;
  KAPC_STATE apcState;
  PVOID base = NULL;
  SIZE_T size = ImageSize;

  if (ImageBuffer == NULL || ImageSize == 0 || RemoteBase == NULL ||
      FinalProtect == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  *RemoteBase = NULL;
  if (RemoteSize != NULL)
    *RemoteSize = 0;

  status = ReferenceTargetProcess(TargetPid, &target);
  if (!NT_SUCCESS(status))
    return status;

  //
  // One attach covers the whole sequence. Detaching between steps would need a
  // second attach for the protection flip and would leave the fresh region
  // writable for that window.
  //
  KeStackAttachProcess(target, &apcState);

  status = AllocateInCurrentProcess(&size, PAGE_READWRITE, &base);
  if (NT_SUCCESS(status))
    status = WriteToCurrentProcess(base, ImageBuffer, ImageSize);
  if (NT_SUCCESS(status))
    status = ProtectInCurrentProcess(base, size, FinalProtect, NULL);

  //
  // All-or-nothing. A partially prepared region is not handed back: the caller
  // could not even free it correctly, because it would not know the rounded
  // size or whether the write landed.
  //
  if (!NT_SUCCESS(status) && base != NULL) {
    FreeInCurrentProcess(base);
    base = NULL;
    size = 0;
  }

  KeUnstackDetachProcess(&apcState);
  ObDereferenceObject(target);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] RemoteInject: image into pid %lu failed 0x%X, "
             "allocation rolled back.\n",
             TargetPid, status);
    return status;
  }

  DbgPrint("[LongsDriver] RemoteInject: pid %lu, %llu bytes at %p, final "
           "protect 0x%X.\n",
           TargetPid, (ULONGLONG)ImageSize, base, FinalProtect);

  *RemoteBase = base;
  if (RemoteSize != NULL)
    *RemoteSize = size;

  return STATUS_SUCCESS;
}