#include "EtwTi.h"
#include "Bypass.h"
#include "Offsets.h"

//
// Verified against VM_Logs\ntoskrnl.exe 10.0.26100.4351 (SHA-256
// EB3AFF3F0C7D210E31DC8DA896493B2F74DBAFE8EBF2C10B0600E33CB3139AA2).
// 26200 is deliberately not accepted: the offsets below were read out of the
// 26100 binary only, and a build number match on paper is not evidence that
// they still hold.
//
#define ETW_TI_SUPPORTED_BUILD WIN_11_24H2

//
// Scan window over KeInsertQueueApc. The anchor sits at +0x1C on this build.
//
#define ETW_TI_APC_SCAN_LEN 0x29D

//
// "4C 8B 15" is "mov r10, qword ptr [rip+disp32]" on x64. The displacement is
// relative to the end of the whole 7-byte instruction, which is where the +7 in
// the resolution comes from.
//
static const UCHAR kAnchorPrefix[3] = {0x4C, 0x8B, 0x15};
#define ETW_TI_ANCHOR_INSN_LEN 7

//
// RVA of the Threat-Intelligence GUID that EtwRegister passes when it fills the
// slot the anchor points at.
//
#define ETW_TI_GUID_RVA 0x20300

//
// ETW_REGISTRY_ENTRY.EnableInfo, and IsEnabled inside the enable record that
// pointer refers to.
//
#define ETW_TI_ENTRY_ENABLE_INFO 0x20
#define ETW_TI_IS_ENABLED 0x60

//
// x64 canonical kernel virtual address range. A deref that lands outside it is a
// wild pointer, which is the signal that the chain was walked wrongly.
//
#define ETW_TI_MIN_KERNEL_ADDR 0xFFFF800000000000ull
#define ETW_TI_MAX_KERNEL_ADDR 0xFFFFFFFFFFFFFFFFull

//
// f4e1897c-bb5d-5668-f1d8-040f4d8dd344, stored the way it sits in the image.
//
static const UCHAR kTiGuid[sizeof(GUID)] = {
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
    0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44};

typedef struct _ETW_TI_TARGET {
  ULONGLONG Slot;
  ULONGLONG Entry;
  ULONGLONG Info;
  ULONG Value;
} ETW_TI_TARGET, *PETW_TI_TARGET;

static BOOLEAN g_Disabled;
static BOOLEAN g_HaveSavedValue;
static ULONG g_SavedValue;
static ULONGLONG g_InfoAtDisable;
static volatile LONG g_ArmAttempts;
static BOOLEAN g_Armed;
static BOOLEAN g_AutoSuspended;
static BOOLEAN g_AutoStarted;
static BOOLEAN IsKernelPointer(ULONGLONG Value) {
  return Value >= ETW_TI_MIN_KERNEL_ADDR && Value <= ETW_TI_MAX_KERNEL_ADDR;
}

static PVOID ResolveKeInsertQueueApc(VOID) {
  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"KeInsertQueueApc");
  return MmGetSystemRoutineAddress(&routineName);
}

//
// The GUID is the build signature here. The ETW offsets are semantic rather
// than byte-checkable, so without the GUID a shifted layout would be walked
// blindly and only fail once something was already written.
//
static BOOLEAN TiGuidMatches(PVOID KernelBase, ULONG KernelSize) {
  UCHAR actual[sizeof(kTiGuid)];

  if ((ETW_TI_GUID_RVA + sizeof(kTiGuid)) > KernelSize) {
    return FALSE;
  }

  __try {
    RtlCopyMemory(actual, (PUCHAR)KernelBase + ETW_TI_GUID_RVA, sizeof(actual));
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return FALSE;
  }

  return RtlCompareMemory(actual, kTiGuid, sizeof(kTiGuid)) ==
         sizeof(kTiGuid);
}

//
// Scans KeInsertQueueApc for the RIP-relative load whose target is the provider's
// REGHANDLE slot, and returns the slot address. The computed target has to fall
// inside the running kernel image: a pattern hit in unrelated code would produce
// an address that resolves to something, so the image bound is the only cheap
// way to tell the two apart.
//
static NTSTATUS FindProviderSlot(PVOID KernelBase, ULONG KernelSize,
                                 PULONGLONG OutSlot) {
  ULONGLONG imageStart = (ULONGLONG)(ULONG_PTR)KernelBase;
  ULONGLONG imageEnd = imageStart + KernelSize;
  PUCHAR apc = (PUCHAR)ResolveKeInsertQueueApc();
  ULONG i;

  if (apc == NULL) {
    DbgPrint("[LongsDriver] EtwTi: KeInsertQueueApc not exported.\n");
    return STATUS_NOT_FOUND;
  }

  for (i = 0; i + ETW_TI_ANCHOR_INSN_LEN <= ETW_TI_APC_SCAN_LEN; i++) {
    if (RtlCompareMemory(apc + i, kAnchorPrefix, sizeof(kAnchorPrefix)) !=
        sizeof(kAnchorPrefix)) {
      continue;
    }

    {
      LONG displacement = 0;
      ULONGLONG slot;

      RtlCopyMemory(&displacement, apc + i + sizeof(kAnchorPrefix),
                    sizeof(displacement));
      slot = (ULONGLONG)(ULONG_PTR)apc + i + ETW_TI_ANCHOR_INSN_LEN +
             (ULONGLONG)displacement;

      if (slot < imageStart || slot >= imageEnd) {
        DbgPrint("[LongsDriver] EtwTi: anchor at KeInsertQueueApc+0x%X "
                 "resolved to 0x%X, outside ntoskrnl.\n",
                 i, slot);
        return STATUS_REVISION_MISMATCH;
      }

      *OutSlot = slot;
      return STATUS_SUCCESS;
    }
  }

  DbgPrint("[LongsDriver] EtwTi: anchor not found in the first 0x%X bytes of "
           "KeInsertQueueApc.\n",
           ETW_TI_APC_SCAN_LEN);
  return STATUS_NOT_FOUND;
}

//
// Walks slot -> entry -> info and reads the live flag. Every hop is bounds
// checked before it is dereferenced and the flag itself has to be 0 or 1, which
// is the only range EtwProviderEnabled treats as meaningful.
//
static NTSTATUS ResolveTarget(PETW_TI_TARGET Out) {
  PVOID kernelBase = NULL;
  ULONG kernelSize = 0;
  ETW_TI_TARGET target;
  NTSTATUS status;

  RtlZeroMemory(&target, sizeof(target));

  if (g_WindowsBuildNumber != ETW_TI_SUPPORTED_BUILD) {
    DbgPrint("[LongsDriver] EtwTi: build %lu is not the verified %lu, "
             "refusing.\n",
             g_WindowsBuildNumber, ETW_TI_SUPPORTED_BUILD);
    return STATUS_REVISION_MISMATCH;
  }

  if (!BypassGetKernelBaseNSize(&kernelBase, &kernelSize)) {
    DbgPrint("[LongsDriver] EtwTi: could not locate ntoskrnl.\n");
    return STATUS_NOT_FOUND;
  }

  if (!TiGuidMatches(kernelBase, kernelSize)) {
    DbgPrint("[LongsDriver] EtwTi: Threat-Intelligence GUID absent at RVA "
             "0x%X, refusing.\n",
             ETW_TI_GUID_RVA);
    return STATUS_REVISION_MISMATCH;
  }

  status = FindProviderSlot(kernelBase, kernelSize, &target.Slot);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  {
    BOOLEAN chainOk = FALSE;
    BOOLEAN valueOk = FALSE;
    ULONG value = 0;
    ULONG faultCode = 0;

    __try {
      target.Entry = *(PULONGLONG)target.Slot;

      if (IsKernelPointer(target.Entry)) {
        target.Info = *(PULONGLONG)(target.Entry + ETW_TI_ENTRY_ENABLE_INFO);

        if (IsKernelPointer(target.Info)) {
          chainOk = TRUE;
          value = *(PULONG)(target.Info + ETW_TI_IS_ENABLED);
          valueOk = (value <= 1);
        }
      }
    } __except (faultCode = GetExceptionCode(),
                EXCEPTION_EXECUTE_HANDLER) {
      // The code is latched in the filter expression; the body stays empty so
      // the value survives past the handler.
    }

    if (faultCode != 0) {
      DbgPrint("[LongsDriver] EtwTi: walking the provider chain faulted, "
               "code 0x%X.\n",
               faultCode);
      return STATUS_ACCESS_VIOLATION;
    }

    //
    // EtwRegister fills the slot, so a NULL handle here means the provider has
    // not been registered yet - not that the layout moved. Kept distinct from
    // the non-kernel-pointer case below because on a freshly booted VM this is
    // the expected answer until the Threat-Intelligence client registers, and
    // reporting it as a layout break would send a tester hunting a bug that
    // does not exist.
    //
    if (target.Entry == 0) {
      DbgPrint("[LongsDriver] EtwTi: provider handle at ntoskrnl+0x%X is still "
               "NULL - EtwRegister has not run for the Threat-Intelligence "
               "provider on this boot.\n",
               target.Slot - (ULONGLONG)(ULONG_PTR)kernelBase);
      return STATUS_NOT_FOUND;
    }

    if (!chainOk) {
      DbgPrint("[LongsDriver] EtwTi: provider chain resolved to a "
               "non-kernel pointer (entry 0x%X, info 0x%X).\n",
               target.Entry, target.Info);
      return STATUS_DATA_ERROR;
    }

    if (!valueOk) {
      DbgPrint("[LongsDriver] EtwTi: IsEnabled at 0x%X holds 0x%X, not 0 or "
               "1; layout does not match 26100.4351.\n",
               target.Info + ETW_TI_IS_ENABLED, value);
      return STATUS_DATA_ERROR;
    }

    target.Value = value;
  }

  DbgPrint("[LongsDriver] EtwTi: slot ntoskrnl+0x%X -> entry 0x%X -> info "
           "0x%X, IsEnabled=%lu.\n",
           target.Slot - (ULONGLONG)(ULONG_PTR)kernelBase, target.Entry,
           target.Info, target.Value);

  *Out = target;
  return STATUS_SUCCESS;
}

//
// Target is NULL when the chain could not be walked. The addresses are zeroed and
// CurrentValue is set to a sentinel rather than left at 0, so a caller can tell
// "resolved and the flag is genuinely 0" from "never resolved" - which is exactly
// the distinction that matters when the whole point of the query is to find out
// whether the disable worked.
//
#define ETW_TI_VALUE_UNRESOLVED 0xFFFFFFFFul

static VOID FillResponse(PETWTI_STATUS_RESPONSE Response,
                         PETW_TI_TARGET Target) {
  RtlZeroMemory(Response, sizeof(*Response));

  if (Target != NULL) {
    Response->SlotAddress = Target->Slot;
    Response->EntryAddress = Target->Entry;
    Response->EnableInfoAddress = Target->Info;
    Response->CurrentValue = Target->Value;
  } else {
    Response->CurrentValue = ETW_TI_VALUE_UNRESOLVED;
  }

  Response->Disabled = g_Disabled ? 1 : 0;
  Response->SavedValue = g_HaveSavedValue ? g_SavedValue : 0;
  Response->ArmAttempts = (ULONG)g_ArmAttempts;
}

//
// Reported after the operation rather than derived from it, so a client can
// confirm the result instead of inferring it from the absence of an error.
//
static VOID ReportOutcome(PETWTI_STATUS_RESPONSE Response, NTSTATUS Status) {
  Response->Status = Status;
}

NTSTATUS EtwTiDisable(PETWTI_STATUS_RESPONSE Response) {
  ETW_TI_TARGET target;
  BOOLEAN chainResolved = FALSE;
  NTSTATUS status = STATUS_SUCCESS;

  RtlZeroMemory(&target, sizeof(target));

  if (g_Disabled) {
    status = STATUS_SUCCESS;
  } else if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    DbgPrint("[LongsDriver] EtwTi: must run at PASSIVE_LEVEL.\n");
    status = STATUS_INVALID_DEVICE_STATE;
  } else {
    status = ResolveTarget(&target);
  }

  if (NT_SUCCESS(status) && !g_Disabled) {
    chainResolved = TRUE;
    g_SavedValue = target.Value;
    g_HaveSavedValue = TRUE;

    //
    // The flag is a naturally aligned ULONG inside a pool allocation, so it is
    // already writable; clearing CR0.WP the way KernelWrite does for code pages
    // is unnecessary here and would only widen the window where the whole
    // processor accepts writes to read-only pages. InterlockedExchange is also
    // atomic, so a concurrent reader in EtwProviderEnabled sees either the old or
    // the new value and never a torn one.
    //
    // ETW's own writes to this field run under a push lock reached through the
    // enable record. That lock is deliberately not taken: from an arbitrary IOCTL
    // thread there is no way to know it is not already held, and taking it would
    // risk a stall without preventing ETW from re-enabling the provider the
    // moment we release. The flag is latched once the TI provider is armed and is
    // not toggled afterwards, so the window in which that race could bite is
    // empty in practice. The read-back below is what actually establishes the
    // outcome.
    //
    InterlockedExchange((volatile LONG *)(target.Info + ETW_TI_IS_ENABLED), 0);

    if (*(volatile ULONG *)(target.Info + ETW_TI_IS_ENABLED) != 0) {
      DbgPrint("[LongsDriver] EtwTi: IsEnabled did not take; restoring %lu.\n",
               g_SavedValue);
      InterlockedExchange((volatile LONG *)(target.Info + ETW_TI_IS_ENABLED),
                          (LONG)g_SavedValue);
      g_HaveSavedValue = FALSE;
      target.Value = g_SavedValue;
      status = STATUS_DEVICE_CONFIGURATION_ERROR;
    } else {
      g_InfoAtDisable = target.Info;
      g_Disabled = TRUE;
      g_AutoSuspended = FALSE; // an explicit Disable re-arms the hold phase
      target.Value = 0;
      DbgPrint("[LongsDriver] EtwTi: ETW-TI disabled at 0x%X (was %lu).\n",
               target.Info + ETW_TI_IS_ENABLED, g_SavedValue);
    }
  } else if (NT_SUCCESS(status)) {
    //
    // Already disabled. Re-report the chain so a caller that asks twice still
    // gets the live picture rather than an empty response.
    //
    status = ResolveTarget(&target);
    chainResolved = NT_SUCCESS(status);
  }

  if (Response != NULL) {
    FillResponse(Response, chainResolved ? &target : NULL);
    ReportOutcome(Response, status);
  }

  return status;
}

NTSTATUS EtwTiEnable(PETWTI_STATUS_RESPONSE Response) {
  ETW_TI_TARGET target;
  BOOLEAN chainResolved = FALSE;
  NTSTATUS status = STATUS_SUCCESS;

  RtlZeroMemory(&target, sizeof(target));

  if (!g_Disabled) {
    status = ResolveTarget(&target);
    chainResolved = NT_SUCCESS(status);
  } else if (!g_HaveSavedValue) {
    DbgPrint("[LongsDriver] EtwTi: disabled without a saved value, cannot "
             "restore.\n");
    status = STATUS_INVALID_DEVICE_STATE;
  } else {
    status = ResolveTarget(&target);

    if (NT_SUCCESS(status)) {
      chainResolved = TRUE;

      //
      // The enable record is allocated per enable, not once per registration, so
      // it can legitimately be a different allocation now than the one this module
      // first disarmed. That is not a reason to refuse: the field at +0x60 means
      // the same thing in both records (it is set by EnableTraceEx2 and is the
      // first condition EtwProviderEnabled tests), and ResolveTarget has already
      // confirmed this address is the live record for our GUID. Restoring the
      // value we observed at disarm puts the provider back the way the user found
      // it, which is what ENABLE is for.
      //
      if (target.Info != g_InfoAtDisable) {
        DbgPrint("[LongsDriver] EtwTi: enable record moved while disabled "
                 "(0x%X -> 0x%X); restoring the live record.\n",
                 g_InfoAtDisable, target.Info);
      }

      InterlockedExchange((volatile LONG *)(target.Info + ETW_TI_IS_ENABLED),
                          (LONG)g_SavedValue);
      target.Value = g_SavedValue;

      if (*(volatile ULONG *)(target.Info + ETW_TI_IS_ENABLED) !=
          g_SavedValue) {
        DbgPrint("[LongsDriver] EtwTi: restore to %lu did not take.\n",
                 g_SavedValue);
        status = STATUS_DEVICE_CONFIGURATION_ERROR;
      } else {
        g_Disabled = FALSE;
        g_HaveSavedValue = FALSE;
        g_InfoAtDisable = 0;
        g_AutoSuspended = TRUE; // do not let the worker undo an explicit Enable
        DbgPrint("[LongsDriver] EtwTi: ETW-TI restored to %lu.\n",
                 g_SavedValue);
      }
    }
  }

  if (Response != NULL) {
    FillResponse(Response, chainResolved ? &target : NULL);
    ReportOutcome(Response, status);
  }

  return status;
}

NTSTATUS EtwTiQueryStatus(PETWTI_STATUS_RESPONSE Response) {
  ETW_TI_TARGET target;
  NTSTATUS status;

  if (Response == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  status = ResolveTarget(&target);
  FillResponse(Response, NT_SUCCESS(status) ? &target : NULL);
  ReportOutcome(Response, status);
  return status;
}

BOOLEAN EtwTiIsDisabled(VOID) { return g_Disabled; }

//
// Auto-apply worker
//
// ETW-TI is applied by the driver itself, so a client only ever has to read the
// state back. The obvious way to do that - one attempt from DriverEntry - does
// not work: EtwRegister fills the provider slot when the Threat-Intelligence
// client comes up, which on a VM is routinely after this image has finished
// loading. A single early attempt resolves a NULL slot and gives up, leaving the
// module looking armed in the UI while ETW-TI is untouched. So the work is done
// from a thread that retries, and then keeps confirming the result.
//
#define ETW_TI_ARM_INTERVAL_MS 2000
#define ETW_TI_ARM_MAX_TRIES 300 // ~10 minutes at the interval above

//
// How often the hold phase re-checks. This is a floor on how long the provider
// can stay up after a session enables it, so it is chosen against that window
// rather than against CPU cost: EnableTraceEx2 sets IsEnabled before the caller
// starts receiving events, so anything longer than a moment here shows up as
// ETW-TI events landing in a viewer that was started after us. Five seconds is a
// deliberate tradeoff - it bounds the leak rather than eliminating it, in
// exchange for one pointer chase plus a 4KB GUID compare twelve times a minute.
//
#define ETW_TI_HOLD_INTERVAL_MS 5000

//
// Plain uninterruptible sleep. There is no stop path to service: DriverUnload is
// cleared on this mapped-load path, so the worker runs for the life of the
// machine and nothing can ask it to exit. A cancellable wait would be state that
// could never actually be used.
//
static VOID SleepInterval(ULONG Ms) {
  LARGE_INTEGER timeout;

  timeout.QuadPart = -((LONGLONG)Ms * 10000);
  KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}

//
// Puts the flag back down if something turned it back on.
//
// The enable record is NOT stable, and this is the reason the earlier version of
// this routine stopped holding the provider. ETW allocates a fresh
// TRACE_ENABLE_INFO whenever a session enables the provider, and repoints
// entry+0x20 at it, so a consumer started after us (a new ETW-TI session, or an
// ETW-TI viewer restarted) leaves us patching an allocation that nobody reads
// again. Guarding on "did the address move" and bailing out turned that
// recoverable re-arm into a permanent loss of the hold.
//
// ResolveTarget revalidates the whole chain against the CURRENT entry on every
// call - build, GUID at its RVA, canonical kernel pointers at each hop, and the
// 0/1 range of the flag - so whatever it hands back is the live record for this
// provider, and it is the correct place to write. No separate liveness check is
// wanted: a record that failed validation is rejected there.
//
// Deliberately does not touch g_SavedValue: the value ENABLE restores is the one
// captured when the provider was first disarmed, not whatever it happened to be
// on this pass. Rewriting it here would let a later ENABLE resurrect a state this
// module never actually observed.
//
static VOID EtwTiReassert(VOID) {
  ETW_TI_TARGET target;

  if (!NT_SUCCESS(ResolveTarget(&target)))
    return;

  if (target.Value == 0)
    return;

  if (target.Info != g_InfoAtDisable) {
    DbgPrint("[LongsDriver] EtwTi: enable record moved 0x%X -> 0x%X - a session "
             "re-enabled the provider; suppressing the new record.\n",
             g_InfoAtDisable, target.Info);
  }

  InterlockedExchange((volatile LONG *)(target.Info + ETW_TI_IS_ENABLED), 0);

  if (*(volatile ULONG *)(target.Info + ETW_TI_IS_ENABLED) == 0) {
    //
    // Track the live record so a later ENABLE restores into the allocation that
    // is actually current rather than reporting a spurious move.
    //
    g_InfoAtDisable = target.Info;
    DbgPrint("[LongsDriver] EtwTi: provider had come back up; re-disabled at "
             "0x%X.\n",
             target.Info + ETW_TI_IS_ENABLED);
  } else {
    DbgPrint("[LongsDriver] EtwTi: re-assert at 0x%X did not take; retrying.\n",
             target.Info + ETW_TI_IS_ENABLED);
  }
}

static VOID EtwTiAutoThread(PVOID Context) {
  ULONG tries = 0;

  UNREFERENCED_PARAMETER(Context);

  while (tries < ETW_TI_ARM_MAX_TRIES) {
    ETWTI_STATUS_RESPONSE probe = {0};
    NTSTATUS status;

    InterlockedIncrement(&g_ArmAttempts);
    status = EtwTiDisable(&probe);

    if (NT_SUCCESS(status) && probe.Disabled) {
      g_Armed = TRUE;
      DbgPrint("[LongsDriver] EtwTi: auto-applied on attempt %lu.\n", tries + 1);
      break;
    }

    //
    // A build or GUID mismatch is permanent: on a binary this module refuses,
    // EtwRegister for the expected provider is never going to show up either, so
    // there is nothing to gain from spending the rest of the window on it.
    //
    if (status == STATUS_REVISION_MISMATCH) {
      DbgPrint("[LongsDriver] EtwTi: auto-apply gave up, this ntoskrnl is not "
               "the verified build.\n");
      return;
    }

    tries++;
    SleepInterval(ETW_TI_ARM_INTERVAL_MS);
  }

  if (!g_Armed) {
    DbgPrint("[LongsDriver] EtwTi: auto-apply gave up after %lu attempts; "
             "ETW-TI left as it was found.\n",
             tries);
    return;
  }

  //
  // Hold phase. Nothing is expected to re-enable a latched provider, but the
  // write above deliberately takes no lock, so confirm rather than assume - and
  // report the moment it turns out to be needed, because that is exactly the
  // race the missing lock was accepted to risk.
  //
  //
  // The loop outlives an explicit Enable rather than exiting on it: the worker
  // goes idle while the module holds nothing, so a later Disable is picked up
  // again. Exiting here would make the hold permanently unavailable for the rest
  // of the boot, since EtwTiInitialize is called once and has no caller to
  // restart it.
  //
  for (;;) {
    SleepInterval(ETW_TI_HOLD_INTERVAL_MS);

    if (g_Disabled && !g_AutoSuspended)
      EtwTiReassert();
  }
}

//
// Starts the worker. Call at PASSIVE_LEVEL once OffsetsInitialize() has run, so
// g_WindowsBuildNumber is available for the build check. Best-effort: a failure
// here leaves the IOCTLs working and the client can still drive it by hand.
//
NTSTATUS EtwTiInitialize(VOID) {
  OBJECT_ATTRIBUTES attributes;
  UNICODE_STRING threadName;
  HANDLE thread = NULL;
  NTSTATUS status;

  if (g_AutoStarted)
    return STATUS_SUCCESS;

  g_AutoStarted = TRUE;

  RtlInitUnicodeString(&threadName, L"\\LongsEtwTi");
  InitializeObjectAttributes(&attributes, &threadName,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL,
                             NULL);

  status = PsCreateSystemThread(&thread, 0, &attributes, NULL, NULL,
                               EtwTiAutoThread, NULL);
  if (!NT_SUCCESS(status) || thread == NULL) {
    DbgPrint("[LongsDriver] EtwTi: auto-apply thread could not be started "
             "(0x%X).\n",
             status);
    if (thread != NULL)
      ZwClose(thread);
    return STATUS_UNSUCCESSFUL;
  }

  ZwClose(thread);

  DbgPrint("[LongsDriver] EtwTi: auto-apply worker started.\n");
  return STATUS_SUCCESS;
}
