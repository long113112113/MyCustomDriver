//
// ntifs.h must precede other headers for ObRegisterCallbacks definitions
//
#include <ntifs.h>
#include "ProcessProtect.h"
#include "Bypass.h"
#include "ObGatePatch.h"

//
// Process access rights (winnt.h equivalents for kernel mode)
//
#define PROCESS_TERMINATE 0x0001
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_SET_LIMITED_INFORMATION 0x2000

//
// Access rights stripped from handles opened to protected processes
//
#define PROTECT_DENIED_ACCESS                                                  \
  (PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ |              \
   PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |            \
   PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME |                         \
   PROCESS_SET_LIMITED_INFORMATION)

//
// Protected process list state
//
static ULONG g_ProtectedProcesses[MAX_PROTECTED_PROCESSES];
static ULONG g_ProtectedProcessCount = 0;
static FAST_MUTEX g_ProtectedListLock;
static PVOID g_ObCallbackHandle = NULL;
//
// Sentinel for "ObGatePatchApply was never reached", so a status query issued
// before initialization is distinguishable from a real failure. Not a
// documented NTSTATUS: it is reported as-is and the client prints it verbatim.
//
#define GATE_PATCH_NOT_ATTEMPTED ((NTSTATUS)0xFFFFFFFF)
static NTSTATUS g_GatePatchStatus = GATE_PATCH_NOT_ATTEMPTED;
//
// NTSTATUS the module returned from ProcessProtectInitialize. Kept so the
// client can be told why the feature is dead without attaching a debugger.
//
static NTSTATUS g_InitStatus = STATUS_UNSUCCESSFUL;

static BOOLEAN IsValidProcessId(ULONG ProcessId) {
  return ProcessId > SYSTEM_PROCESS_PID;
}

static BOOLEAN IsProcessProtectedLocked(ULONG ProcessId) {
  ULONG i;
  for (i = 0; i < g_ProtectedProcessCount; i++) {
    if (g_ProtectedProcesses[i] == ProcessId) {
      return TRUE;
    }
  }
  return FALSE;
}

static BOOLEAN IsProcessProtected(ULONG ProcessId) {
  BOOLEAN found;

  ExAcquireFastMutex(&g_ProtectedListLock);
  found = IsProcessProtectedLocked(ProcessId);
  ExReleaseFastMutex(&g_ProtectedListLock);

  return found;
}

static BOOLEAN AddProtectedProcess(ULONG ProcessId) {
  BOOLEAN success = FALSE;

  ExAcquireFastMutex(&g_ProtectedListLock);

  if (IsProcessProtectedLocked(ProcessId))
    goto exit;

  if (g_ProtectedProcessCount >= MAX_PROTECTED_PROCESSES)
    goto exit;

  g_ProtectedProcesses[g_ProtectedProcessCount++] = ProcessId;
  success = TRUE;

exit:
  ExReleaseFastMutex(&g_ProtectedListLock);
  return success;
}

static BOOLEAN RemoveProtectedProcess(ULONG ProcessId) {
  ULONG i;
  BOOLEAN found = FALSE;

  ExAcquireFastMutex(&g_ProtectedListLock);

  for (i = 0; i < g_ProtectedProcessCount; i++) {
    if (g_ProtectedProcesses[i] == ProcessId) {
      g_ProtectedProcesses[i] =
          g_ProtectedProcesses[g_ProtectedProcessCount - 1];
      g_ProtectedProcessCount--;
      found = TRUE;
      break;
    }
  }

  ExReleaseFastMutex(&g_ProtectedListLock);
  return found;
}

//
// Pre-operation callback: strips destructive access rights on handle create/duplicate
//
static OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(
    _Inout_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info) {
  UNREFERENCED_PARAMETER(RegistrationContext);

  PACCESS_MASK desiredAccess;
  ULONG processId;

  // Ignore kernel-mode requests and invalid objects
  if (Info->KernelHandle || !Info->Object)
    return OB_PREOP_SUCCESS;

  processId = HandleToULong(PsGetProcessId((PEPROCESS)Info->Object));
  if (!IsProcessProtected(processId))
    return OB_PREOP_SUCCESS;

  desiredAccess = &Info->Parameters->CreateHandleInformation.DesiredAccess;

  // Strip denied access rights while preserving query permissions
  *desiredAccess &= ~PROTECT_DENIED_ACCESS;

  return OB_PREOP_SUCCESS;
}

//
// Registers the Ob callback if PatchGuard bypass is active
//
NTSTATUS ProcessProtectInitialize(VOID) {
  NTSTATUS status;
  NTSTATUS gateStatus;
  OB_OPERATION_REGISTRATION operations[1];
  OB_CALLBACK_REGISTRATION registration;
  UNICODE_STRING altitude;

  ExInitializeFastMutex(&g_ProtectedListLock);
  g_ProtectedProcessCount = 0;
  g_ObCallbackHandle = NULL;
  g_InitStatus = STATUS_UNSUCCESSFUL;

  if (!g_PatchGuardBypassed) {
    g_InitStatus = STATUS_DEVICE_CONFIGURATION_ERROR;
    DbgPrint("[LongsDriver] ProcessProtect: skipped, PatchGuard bypass "
             "inactive (safe mode).\n");
    return g_InitStatus;
  }

  RtlInitUnicodeString(&altitude, PROCESS_PROTECT_ALTITUDE);

  //
  // ObRegisterCallbacks refuses callbacks that are not backed by a loader
  // entry, which is exactly our manually mapped code. Relax that gate first.
  // A failure here is not fatal on its own: registration will simply be
  // denied, which the existing status handling already reports.
  //
  gateStatus = ObGatePatchApply();
  g_GatePatchStatus = gateStatus;
  if (!NT_SUCCESS(gateStatus)) {
    //
    // Registration is about to fail with STATUS_ACCESS_DENIED, and that status
    // says nothing about why. Spell out the real reason here, and keep it
    // queryable, so a dead feature is not mistaken for a policy refusal.
    //
    DbgPrint("[LongsDriver] ProcessProtect: callback gate patch unavailable "
             "(0x%X); ObRegisterCallbacks will be refused next.\n",
             gateStatus);
  }

  RtlZeroMemory(operations, sizeof(operations));
  operations[0].ObjectType = PsProcessType;
  operations[0].Operations = OB_OPERATION_HANDLE_CREATE |
                             OB_OPERATION_HANDLE_DUPLICATE;
  operations[0].PreOperation = OnPreOpenProcess;
  operations[0].PostOperation = NULL;

  RtlZeroMemory(&registration, sizeof(registration));
  registration.Version = OB_FLT_REGISTRATION_VERSION;
  registration.RegistrationContext = NULL;
  registration.Altitude = altitude;
  registration.OperationRegistrationCount = 1;
  registration.OperationRegistration = operations;

  status = ObRegisterCallbacks(&registration, &g_ObCallbackHandle);
  g_InitStatus = status;
  if (!NT_SUCCESS(status)) {
    g_ObCallbackHandle = NULL;
    //
    // Nothing is registered, so there is no reason to keep the gate relaxed.
    //
    ObGatePatchRevert();
    DbgPrint("[LongsDriver] ProcessProtect: ObRegisterCallbacks failed 0x%X "
             "(feature disabled).\n",
             status);
    return status;
  }

  DbgPrint("[LongsDriver] ProcessProtect: Ob callback registered, altitude "
           "%s.\n",
           PROCESS_PROTECT_ALTITUDE);
  return STATUS_SUCCESS;
}

VOID ProcessProtectCleanup(VOID) {
  ULONG i;

  if (g_ObCallbackHandle) {
    ObUnRegisterCallbacks(g_ObCallbackHandle);
    g_ObCallbackHandle = NULL;
    DbgPrint("[LongsDriver] ProcessProtect: Ob callback unregistered.\n");
  }

  //
  // Restore ntoskrnl only after the callback is gone, so nothing can call
  // through the relaxed gate while the original validation is being restored.
  //
  ObGatePatchRevert();

  ExAcquireFastMutex(&g_ProtectedListLock);
  for (i = 0; i < g_ProtectedProcessCount; i++)
    g_ProtectedProcesses[i] = 0;
  g_ProtectedProcessCount = 0;
  ExReleaseFastMutex(&g_ProtectedListLock);

  DbgPrint("[LongsDriver] ProcessProtect cleaned up.\n");
}

BOOLEAN ProcessProtectAvailable(VOID) {
  return (BOOLEAN)(g_ObCallbackHandle != NULL);
}

//
// Reports the registration outcome so the client can explain a dead feature
// without a debugger attached.
//
NTSTATUS ProcessProtectQueryStatus(PPROTECT_STATUS_RESPONSE Response) {
  if (!Response)
    return STATUS_INVALID_PARAMETER;

  Response->InitStatus = g_InitStatus;
  Response->CallbackActive = (ULONG)(g_ObCallbackHandle != NULL);
  Response->GatePatchStatus = g_GatePatchStatus;
  Response->GatePatchApplied = (ULONG)ObGatePatchIsApplied();

  ExAcquireFastMutex(&g_ProtectedListLock);
  Response->Count = g_ProtectedProcessCount;
  ExReleaseFastMutex(&g_ProtectedListLock);

  return STATUS_SUCCESS;
}

NTSTATUS ProcessProtect(ULONG ProcessId) {
  if (!ProcessProtectAvailable()) {
    DbgPrint("[LongsDriver] ProcessProtect(%lu) refused: Ob callback not "
             "registered.\n",
             ProcessId);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  if (!IsValidProcessId(ProcessId)) {
    DbgPrint("[LongsDriver] ProcessProtect(%lu) refused: PID must be > %d.\n",
             ProcessId, SYSTEM_PROCESS_PID);
    return STATUS_INVALID_PARAMETER;
  }

  if (!AddProtectedProcess(ProcessId)) {
    DbgPrint("[LongsDriver] ProcessProtect(%lu) refused: list rejected it.\n",
             ProcessId);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  DbgPrint("[LongsDriver] Protected process %lu against kill.\n", ProcessId);
  return STATUS_SUCCESS;
}

NTSTATUS ProcessUnprotect(ULONG ProcessId) {
  if (!ProcessProtectAvailable()) {
    DbgPrint("[LongsDriver] ProcessUnprotect(%lu) refused: Ob callback not "
             "registered.\n",
             ProcessId);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  if (!IsValidProcessId(ProcessId)) {
    DbgPrint("[LongsDriver] ProcessUnprotect(%lu) refused: PID must be > %d.\n",
             ProcessId, SYSTEM_PROCESS_PID);
    return STATUS_INVALID_PARAMETER;
  }

  if (!RemoveProtectedProcess(ProcessId)) {
    DbgPrint("[LongsDriver] ProcessUnprotect(%lu) refused: not in list.\n",
             ProcessId);
    return STATUS_NOT_FOUND;
  }

  DbgPrint("[LongsDriver] Unprotected process %lu.\n", ProcessId);
  return STATUS_SUCCESS;
}

NTSTATUS ProcessListProtected(PPROTECTED_PROCESS_LIST_RESPONSE Response) {
  ULONG i;

  if (!Response)
    return STATUS_INVALID_PARAMETER;

  ExAcquireFastMutex(&g_ProtectedListLock);
  Response->Count = g_ProtectedProcessCount;
  for (i = 0; i < g_ProtectedProcessCount; i++)
    Response->ProcessIds[i] = g_ProtectedProcesses[i];
  ExReleaseFastMutex(&g_ProtectedListLock);

  return STATUS_SUCCESS;
}
