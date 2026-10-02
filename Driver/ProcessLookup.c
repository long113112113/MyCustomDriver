#include "ProcessLookup.h"
#include <ntddk.h>

//
// Name lookup.
//
// Two earlier shapes of this module are worth ruling out, because both are
// tempting and both are wrong here:
//
//   * PsGetNextProcess is documented but is not an export on every kernel.
//     Resolving it by name returns NULL on the build this targets, so the
//     lookup answered STATUS_DEVICE_CONFIGURATION_ERROR and never found the
//     shell.
//
//   * Walking EPROCESS.ActiveProcessLinks by hand and calling
//     ObReferenceObject on each node pins a process that may be mid-teardown.
//     ObfReferenceObject raises REFERENCE_BY_POINTER (bugcheck 0x18) when the
//     object is being deleted, and a once-per-second walk over every process
//     eventually meets one that is exiting.
//
// So the process set comes from a system snapshot (ZwQuerySystemInformation,
// SystemProcessInformation) and each PID is resolved through the documented
// PsLookupProcessByProcessId, which takes its own reference safely and reports
// a vanished process instead of touching freed memory. The name then comes from
// PsGetProcessImageFileName. No process-list pointer is ever dereferenced.
//
// The snapshot also carries each process's threads, which is what
// ProcessLookupGetThreadIds hands to the APC injector so it can pin threads
// through PsLookupThreadByThreadId rather than by walking ETHREAD lists.
//

NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);

//
// ZwQuerySystemInformation is exported but the WDK no longer declares it, and
// neither SYSTEM_PROCESS_INFORMATION nor SystemProcessInformation is in the
// headers. Both are repeated here; the class number has been stable since
// Windows 2000 and the struct is the documented x64 layout.
//
#define PL_SYSTEM_PROCESS_INFORMATION 5

typedef struct _PL_THREAD_INFORMATION {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  ULONG Reserved1;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  LONG BasePriority;
  ULONG ContextSwitches;
  ULONG ThreadState;
  ULONG WaitReason;
} PL_THREAD_INFORMATION, *PPL_THREAD_INFORMATION;

typedef struct _PL_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize;
  ULONG HardFaultCount;
  ULONG NumberOfThreadsHighWatermark;
  ULONGLONG CycleTime;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR UniqueProcessKey;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
} PL_PROCESS_INFORMATION, *PPL_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass,
                                                 PVOID SystemInformation,
                                                 ULONG SystemInformationLength,
                                                 PULONG ReturnLength);

#define PL_POOL_TAG 'LkpP'
#define PL_SNAPSHOT_START (256 * 1024)
#define PL_SNAPSHOT_MAX (16 * 1024 * 1024)

typedef struct _PL_SNAPSHOT {
  PVOID Buffer;
  ULONG Length;
} PL_SNAPSHOT;

//
// Takes a whole-system process snapshot.
//
// The first call is expected to fail with STATUS_INFO_LENGTH_MISMATCH and name
// the size it wanted; the retry grows from there. A process can appear between
// the size probe and the data call, so the grown size is padded and the whole
// loop repeats until the buffer is accepted.
//
static NTSTATUS TakeSnapshot(PL_SNAPSHOT *Snapshot) {
  ULONG size = PL_SNAPSHOT_START;

  Snapshot->Buffer = NULL;
  Snapshot->Length = 0;

  for (;;) {
    PVOID buffer;
    ULONG needed = 0;
    NTSTATUS status;

    buffer = ExAllocatePool2(POOL_FLAG_PAGED, size, PL_POOL_TAG);
    if (buffer == NULL)
      return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(PL_SYSTEM_PROCESS_INFORMATION, buffer,
                                      size, &needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
      ExFreePoolWithTag(buffer, PL_POOL_TAG);

      if (size >= PL_SNAPSHOT_MAX)
        return STATUS_INSUFFICIENT_RESOURCES;

      //
      // Trust the size the kernel asked for, with slack for processes created
      // between the two calls, but never shrink and never exceed the cap.
      //
      if (needed != 0 && needed > size) {
        ULONG grown = needed + needed / 4;
        size = (grown > size) ? grown : size * 2;
      } else {
        size = size * 2;
      }
      if (size > PL_SNAPSHOT_MAX)
        size = PL_SNAPSHOT_MAX;
      continue;
    }

    if (!NT_SUCCESS(status)) {
      ExFreePoolWithTag(buffer, PL_POOL_TAG);
      return status;
    }

    Snapshot->Buffer = buffer;
    Snapshot->Length = size;
    return STATUS_SUCCESS;
  }
}

static VOID ReleaseSnapshot(PL_SNAPSHOT *Snapshot) {
  if (Snapshot->Buffer != NULL) {
    ExFreePoolWithTag(Snapshot->Buffer, PL_POOL_TAG);
    Snapshot->Buffer = NULL;
  }
  Snapshot->Length = 0;
}

//
// Advances to the entry after Entry, or returns NULL at the end. Bounds are
// checked against the buffer because the chain is walked on offsets the kernel
// supplied, and a truncated tail must end the walk rather than be followed.
//
static PPL_PROCESS_INFORMATION NextEntry(PPL_PROCESS_INFORMATION Entry,
                                         const PL_SNAPSHOT *Snapshot) {
  PUCHAR next = (PUCHAR)Entry + Entry->NextEntryOffset;

  if (Entry->NextEntryOffset == 0)
    return NULL;
  if ((PUCHAR)Entry < (PUCHAR)Snapshot->Buffer)
    return NULL;
  if (next < (PUCHAR)Snapshot->Buffer ||
      next + sizeof(PL_PROCESS_INFORMATION) > (PUCHAR)Snapshot->Buffer +
                                                    Snapshot->Length) {
    return NULL;
  }
  return (PPL_PROCESS_INFORMATION)next;
}

static BOOLEAN NameMatchesImageFile(PCHAR ImagePath, PCUNICODE_STRING Target) {
  LONG start = 0;
  ULONG length;
  ULONG index;

  if (ImagePath == NULL || Target == NULL || Target->Buffer == NULL ||
      Target->Length == 0) {
    return FALSE;
  }

  //
  // Only the trailing component is compared: in kernel mode
  // PsGetProcessImageFileName normally answers the full NT device path, but the
  // bare file name is a documented possibility, and reducing the candidate to
  // "the part after the last separator" makes both cases answer the same way.
  //
  for (index = 0; ImagePath[index] != '\0'; index++) {
    if (ImagePath[index] == '\\' || ImagePath[index] == '/')
      start = (LONG)index + 1;
  }
  length = index - (ULONG)start;

  if (length == 0 || length >= 64)
    return FALSE;
  if (length * sizeof(WCHAR) != Target->Length)
    return FALSE;

  for (index = 0; index < length; index++) {
    if (RtlUpcaseUnicodeChar((WCHAR)(UCHAR)ImagePath[start + index]) !=
        RtlUpcaseUnicodeChar(Target->Buffer[index])) {
      return FALSE;
    }
  }

  return TRUE;
}

//
// Shared body of every public lookup.
//
// ProcessOut and ProcessIdOut are both optional and independent. The PID comes
// straight from the snapshot; only when the EPROCESS itself is requested is
// PsLookupProcessByProcessId called, and it either returns a referenced object
// or an error.
//
static NTSTATUS FindByNameInternal(PCWSTR ImageName, PEPROCESS *ProcessOut,
                                   PULONG ProcessIdOut,
                                   PULONG InstanceCount) {
  UNICODE_STRING target;
  PL_SNAPSHOT snapshot;
  PPL_PROCESS_INFORMATION entry;
  ULONG firstPid = 0;
  ULONG matches = 0;
  NTSTATUS status;

  if (ProcessOut != NULL)
    *ProcessOut = NULL;
  if (ProcessIdOut != NULL)
    *ProcessIdOut = 0;
  if (InstanceCount != NULL)
    *InstanceCount = 0;

  if (ProcessOut == NULL && ProcessIdOut == NULL)
    return STATUS_INVALID_PARAMETER;

  if (ImageName == NULL || ImageName[0] == L'\0')
    return STATUS_INVALID_PARAMETER;

  status = TakeSnapshot(&snapshot);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ProcessLookup: snapshot failed 0x%X.\n", status);
    return status;
  }

  RtlInitUnicodeString(&target, ImageName);

  for (entry = (PPL_PROCESS_INFORMATION)snapshot.Buffer; entry != NULL;
       entry = NextEntry(entry, &snapshot)) {
    ULONG pid;
    PEPROCESS process = NULL;

    if (entry->UniqueProcessId == NULL)
      continue;

    pid = HandleToULong(entry->UniqueProcessId);
    if (pid == 0)
      continue;

    //
    // PsLookupProcessByProcessId is the safe resolver: it takes its own
    // reference and fails cleanly if the process has gone, so no process-list
    // pointer is ever touched directly.
    //
    status = PsLookupProcessByProcessId(entry->UniqueProcessId, &process);
    if (!NT_SUCCESS(status))
      continue;

    if (NameMatchesImageFile(PsGetProcessImageFileName(process), &target)) {
      matches++;

      if (matches == 1)
        firstPid = pid;
      else
        DbgPrint("[LongsDriver] ProcessLookup: extra %wZ instance, pid %lu, "
                 "not used.\n",
                 &target, pid);
    }

    ObDereferenceObject(process);

    if (matches > 1)
      continue;
  }

  ReleaseSnapshot(&snapshot);

  if (InstanceCount != NULL)
    *InstanceCount = matches;

  if (matches == 0) {
    DbgPrint("[LongsDriver] ProcessLookup: no live process named %wZ.\n",
             &target);
    return STATUS_NOT_FOUND;
  }

  if (ProcessIdOut != NULL)
    *ProcessIdOut = firstPid;

  if (ProcessOut != NULL) {
    status = PsLookupProcessByProcessId(ULongToHandle(firstPid), ProcessOut);
    if (!NT_SUCCESS(status)) {
      if (ProcessIdOut != NULL)
        *ProcessIdOut = 0;
      DbgPrint("[LongsDriver] ProcessLookup: %wZ pid %lu vanished before "
               "reference, 0x%X.\n",
               &target, firstPid, status);
      return status;
    }
  }

  DbgPrint("[LongsDriver] ProcessLookup: %wZ -> pid %lu (%lu live "
           "instance(s)).\n",
           &target, firstPid, matches);

  return STATUS_SUCCESS;
}

NTSTATUS FindProcessIdByName(PCWSTR ImageName, PULONG ProcessId) {
  return FindByNameInternal(ImageName, NULL, ProcessId, NULL);
}

NTSTATUS FindExplorerProcessId(PULONG ProcessId) {
  return FindByNameInternal(PROCESS_LOOKUP_EXPLORER, NULL, ProcessId, NULL);
}

NTSTATUS FindProcessByName(PCWSTR ImageName, PEPROCESS *ProcessOut) {
  return FindByNameInternal(ImageName, ProcessOut, NULL, NULL);
}

NTSTATUS FindExplorerProcess(PEPROCESS *ProcessOut) {
  return FindByNameInternal(PROCESS_LOOKUP_EXPLORER, ProcessOut, NULL, NULL);
}

NTSTATUS FindExplorerProcessInfo(PPROCESS_LOOKUP_INFO Info) {
  PEPROCESS process = NULL;
  PCHAR imagePath;
  NTSTATUS status;
  ULONG index;

  if (Info == NULL)
    return STATUS_INVALID_PARAMETER;

  RtlZeroMemory(Info, sizeof(*Info));

  status = FindByNameInternal(PROCESS_LOOKUP_EXPLORER, &process,
                              &Info->ProcessId, &Info->InstanceCount);
  Info->Status = status;
  if (!NT_SUCCESS(status))
    return status;

  Info->ProcessObject = (ULONGLONG)(ULONG_PTR)process;

  imagePath = PsGetProcessImageFileName(process);
  if (imagePath != NULL) {
    for (index = 0; index + 1 < PROCESS_LOOKUP_PATH_MAX &&
                    imagePath[index] != '\0';
         index++) {
      Info->ImagePath[index] = imagePath[index];
    }
    Info->ImagePath[index] = '\0';
  }

  ReleaseLookupProcess(process);
  return STATUS_SUCCESS;
}

NTSTATUS ProcessLookupGetThreadIds(ULONG ProcessId, PULONG ThreadIds,
                                   ULONG Capacity, PULONG Count) {
  PL_SNAPSHOT snapshot;
  PPL_PROCESS_INFORMATION entry;
  NTSTATUS status;
  ULONG found = 0;

  if (ThreadIds == NULL || Count == NULL || Capacity == 0)
    return STATUS_INVALID_PARAMETER;

  *Count = 0;

  status = TakeSnapshot(&snapshot);
  if (!NT_SUCCESS(status))
    return status;

  for (entry = (PPL_PROCESS_INFORMATION)snapshot.Buffer; entry != NULL;
       entry = NextEntry(entry, &snapshot)) {
    PPL_THREAD_INFORMATION threads;
    ULONG index;

    if (entry->UniqueProcessId == NULL ||
        HandleToULong(entry->UniqueProcessId) != ProcessId) {
      continue;
    }

    //
    // The thread records follow the process record directly and there are
    // NumberOfThreads of them before NextEntryOffset takes over. ClientId
    // carries the TID that PsLookupThreadByThreadId can pin safely.
    //
    threads = (PPL_THREAD_INFORMATION)(entry + 1);
    for (index = 0; index < entry->NumberOfThreads; index++) {
      if (threads[index].ClientId.UniqueThread == NULL)
        continue;
      if (found < Capacity)
        ThreadIds[found] = HandleToULong(threads[index].ClientId.UniqueThread);
      found++;
    }
    break;
  }

  ReleaseSnapshot(&snapshot);

  *Count = (found < Capacity) ? found : Capacity;
  return (found == 0) ? STATUS_NOT_FOUND : STATUS_SUCCESS;
}

VOID ReleaseLookupProcess(PEPROCESS Process) {
  if (Process != NULL)
    ObDereferenceObject(Process);
}