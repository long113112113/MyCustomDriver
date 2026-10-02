#include <ntifs.h>
#include "ApcInject.h"
#include "ProcessLookup.h"

//
// The WDK shipped with this toolset no longer declares the APC DDI: wdm.h still
// defines the KAPC structure, but KAPC_ENVIRONMENT, the routine typedefs and
// KeInitializeApc/KeInsertQueueApc/KeRemoveQueueApc are absent from every
// header, even though ntoskrnl exports all three and the import library carries
// them. The shapes below are the documented ones; the enum order matters because
// KeInitializeApc takes the value by number and KAPC_ENVIRONMENT has been
// stable since before Windows 2000.
//
typedef enum _KAPC_ENVIRONMENT {
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID (*PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1,
                                 PVOID SystemArgument2);

typedef VOID (*PKKERNEL_ROUTINE)(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine,
                                 PVOID *NormalContext, PVOID *SystemArgument1,
                                 PVOID *SystemArgument2);

typedef VOID (*PKRUNDOWN_ROUTINE)(PKAPC Apc);

NTSYSAPI VOID NTAPI KeInitializeApc(
    PKAPC Apc, PKTHREAD Thread, KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ApcMode,
    PVOID NormalContext);

NTSYSAPI BOOLEAN NTAPI KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1,
                                        PVOID SystemArgument2,
                                        KPRIORITY Increment);

NTSYSAPI BOOLEAN NTAPI KeRemoveQueueApc(PKAPC Apc);

#define APC_POOL_TAG 'cnpA'
#define APC_MAX_THREADS 512

//
// APC ownership.
//
// Queued   - linked into g_ApcList, owned by the kernel until it is delivered.
// Kernel   - the kernel routine removed it and owns the free.
// Cancel   - ApcInjectCleanup removed it and owns the free.
//
// The spin lock serializes the three transitions. That serialization is the
// whole point: an entry can only be freed by whoever wins the race to move it
// out of the Queued state, so a delivery and a cancel cannot both free it.
//
#define APC_STATE_QUEUED 0
#define APC_STATE_KERNEL 1
#define APC_STATE_CANCEL 2

typedef struct _APC_ENTRY {
  KAPC Apc;
  LIST_ENTRY Link;
  volatile LONG State;
  // Set by the kernel routine when a canceller already claimed the entry, so
  // the canceller knows the kernel is done touching it before it frees.
  volatile LONG Acknowledged;
} APC_ENTRY, *PAPC_ENTRY;

static LIST_ENTRY g_ApcList;
static KSPIN_LOCK g_ApcLock;
static volatile LONG g_ApcPending;
static KEVENT g_ApcDrained;
static volatile LONG g_ApcShutdown;
static BOOLEAN g_ApcInitialized;

static VOID ApcComplete(PAPC_ENTRY Entry) {
  LONG remaining = InterlockedDecrement(&g_ApcPending);
  if (remaining <= 0)
    KeSetEvent(&g_ApcDrained, IO_NO_INCREMENT, FALSE);
  ExFreePoolWithTag(Entry, APC_POOL_TAG);
}

//
// Delivery path. Also used (through a thin wrapper) as the rundown routine, so
// a thread that exits with the APC still queued is handled by the same logic.
//
static VOID ApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine,
                             PVOID *NormalContext, PVOID *SystemArgument1,
                             PVOID *SystemArgument2) {
  PAPC_ENTRY entry = CONTAINING_RECORD(Apc, APC_ENTRY, Apc);
  KIRQL oldIrql;
  BOOLEAN owned = FALSE;

  UNREFERENCED_PARAMETER(NormalRoutine);
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  ExAcquireSpinLock(&g_ApcLock, &oldIrql);
  if (entry->State == APC_STATE_QUEUED) {
    entry->State = APC_STATE_KERNEL;
    RemoveEntryList(&entry->Link);
    owned = TRUE;
  } else {
    //
    // A canceller already claimed this entry. It will free it; tell it that
    // this routine is past the point of touching the entry.
    //
    InterlockedExchange(&entry->Acknowledged, 1);
  }
  ExReleaseSpinLock(&g_ApcLock, oldIrql);

  if (owned)
    ApcComplete(entry);
}

static VOID ApcRundownRoutine(PKAPC Apc) {
  ApcKernelRoutine(Apc, NULL, NULL, NULL, NULL);
}

NTSTATUS ApcInjectInitialize(VOID) {
  if (g_ApcInitialized)
    return STATUS_SUCCESS;

  InitializeListHead(&g_ApcList);
  KeInitializeSpinLock(&g_ApcLock);
  KeInitializeEvent(&g_ApcDrained, NotificationEvent, FALSE);
  g_ApcPending = 0;
  g_ApcShutdown = 0;
  g_ApcInitialized = TRUE;

  DbgPrint("[LongsDriver] ApcInject initialized.\n");
  return STATUS_SUCCESS;
}

//
// Removes an APC that is still queued. Returns TRUE only when the kernel
// confirms it was taken out of the thread's queue, because that is the one case
// where the kernel routine cannot run and the caller owns the free.
//
static BOOLEAN CancelQueuedApc(PAPC_ENTRY Entry) {
  return KeRemoveQueueApc(&Entry->Apc) ? TRUE : FALSE;
}

//
// Claims and frees every APC that has not been delivered.
//
// The entry is detached from the list under the lock first, so the kernel
// routine can no longer claim it: it has to see APC_STATE_QUEUED to own the
// free, and by then the entry reads APC_STATE_CANCEL. Everything after that is
// safe without the lock.
//
static VOID ApcCancelAll(VOID) {
  KIRQL oldIrql;

  for (;;) {
    PAPC_ENTRY entry;
    BOOLEAN removed;

    ExAcquireSpinLock(&g_ApcLock, &oldIrql);
    if (IsListEmpty(&g_ApcList)) {
      ExReleaseSpinLock(&g_ApcLock, oldIrql);
      break;
    }

    entry = CONTAINING_RECORD(g_ApcList.Flink, APC_ENTRY, Link);
    entry->State = APC_STATE_CANCEL;
    RemoveEntryList(&entry->Link);
    ExReleaseSpinLock(&g_ApcLock, oldIrql);

    removed = CancelQueuedApc(entry);
    if (!removed) {
      //
      // The kernel is delivering it. Its kernel routine will see the CANCEL
      // state, acknowledge and return without freeing. Wait for that
      // acknowledgement before freeing, so the routine is not still reading
      // the entry when it disappears. Bounded because a delivery that never
      // arrives must not hang unload.
      //
      ULONG spins = 0;
      while (entry->Acknowledged == 0 && spins < 20000) {
        KeStallExecutionProcessor(50);
        spins++;
      }
    }

    ApcComplete(entry);
  }
}

VOID ApcInjectCleanup(VOID) {
  if (!g_ApcInitialized)
    return;

  InterlockedExchange(&g_ApcShutdown, 1);
  ApcCancelAll();

  //
  // ApcCancelAll already accounted for every entry, so this wait is a backstop
  // for an APC that was mid-delivery and acknowledged late. Bounded so a
  // pathological thread cannot wedge unload.
  //
  if (g_ApcPending > 0) {
    LARGE_INTEGER timeout;

    timeout.QuadPart = -5 * 1000 * 1000 * 10; // 5 seconds
    KeWaitForSingleObject(&g_ApcDrained, Executive, KernelMode, FALSE,
                          &timeout);
  }

  DbgPrint("[LongsDriver] ApcInject cleaned up, %ld pending.\n",
           g_ApcPending);
}

NTSTATUS ApcInjectQueueToProcess(ULONG TargetPid, PVOID UserRoutine,
                                 PVOID UserContext, PULONG ThreadsQueued) {
  ULONG threadIds[APC_MAX_THREADS];
  ULONG threadCount = 0;
  ULONG index;
  ULONG queued = 0;
  NTSTATUS status;

  if (ThreadsQueued != NULL)
    *ThreadsQueued = 0;

  if (UserRoutine == NULL)
    return STATUS_INVALID_PARAMETER;

  if (KeGetCurrentIrql() > APC_LEVEL)
    return STATUS_INVALID_DEVICE_STATE;

  if (g_ApcShutdown)
    return STATUS_DELETE_PENDING;

  //
  // Thread IDs come from the system snapshot, and each is then pinned through
  // PsLookupThreadByThreadId. That is deliberate: an earlier version walked
  // ETHREAD.ThreadListEntry with a build offset and called ObReferenceObject on
  // each node, which raises REFERENCE_BY_POINTER (bugcheck 0x18) if a thread is
  // exiting at that moment. The documented lookup cannot do that.
  //
  status = ProcessLookupGetThreadIds(TargetPid, threadIds, APC_MAX_THREADS,
                                     &threadCount);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ApcInject: no thread list for pid %lu (0x%X).\n",
             TargetPid, status);
    return status;
  }

  for (index = 0; index < threadCount; index++) {
    PETHREAD thread = NULL;
    PAPC_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN inserted;

    status = PsLookupThreadByThreadId(ULongToHandle(threadIds[index]), &thread);
    if (!NT_SUCCESS(status))
      continue;

    entry = (PAPC_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(APC_ENTRY),
                                        APC_POOL_TAG);
    if (entry == NULL) {
      ObDereferenceObject(thread);
      continue;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    entry->State = APC_STATE_QUEUED;

    //
    // A user APC: ApcMode UserMode with the user address as NormalRoutine, so
    // the kernel queues it for delivery in the target's own context. The
    // routine is invoked as NormalRoutine(NormalContext, Arg1, Arg2).
    //
    KeInitializeApc(&entry->Apc, (PKTHREAD)thread, OriginalApcEnvironment,
                    ApcKernelRoutine, ApcRundownRoutine,
                    (PKNORMAL_ROUTINE)UserRoutine, UserMode, UserContext);

    //
    // Tracked before the insert. The kernel routine can run the moment the
    // insert succeeds, so the entry has to be on the list and counted first;
    // doing it after would race a delivery that removes and frees it.
    //
    InterlockedIncrement(&g_ApcPending);
    ExAcquireSpinLock(&g_ApcLock, &oldIrql);
    InsertTailList(&g_ApcList, &entry->Link);
    ExReleaseSpinLock(&g_ApcLock, oldIrql);

    inserted = KeInsertQueueApc(&entry->Apc, NULL, NULL, 0);
    if (!inserted) {
      //
      // Never queued, so no kernel routine will run: undo the tracking and
      // free it here.
      //
      ExAcquireSpinLock(&g_ApcLock, &oldIrql);
      RemoveEntryList(&entry->Link);
      ExReleaseSpinLock(&g_ApcLock, oldIrql);
      ApcComplete(entry);
    } else {
      queued++;
    }

    ObDereferenceObject(thread);
  }

  DbgPrint("[LongsDriver] ApcInject: pid %lu routine %p queued to %lu/%lu "
           "threads.\n",
           TargetPid, UserRoutine, queued, threadCount);

  if (ThreadsQueued != NULL)
    *ThreadsQueued = queued;

  return STATUS_SUCCESS;
}