//
// ntifs.h must precede other headers for ObRegisterCallbacks definitions
//
#include <ntifs.h>
#include "ProcessProtect.h"
#include "Bypass.h"
#include "ProcessModule.h"

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

#define PROCESS_PROTECT_ALTITUDE L"31105.6171"

//
// Protected process list state
//
static ULONG g_ProtectedProcesses[MAX_PROTECTED_PROCESSES];
static ULONG g_ProtectedProcessCount = 0;
static FAST_MUTEX g_ProtectedListLock;
static PVOID g_ObCallbackHandle = NULL;

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
  OB_OPERATION_REGISTRATION operations[1];
  OB_CALLBACK_REGISTRATION registration;
  UNICODE_STRING altitude;

  ExInitializeFastMutex(&g_ProtectedListLock);
  g_ProtectedProcessCount = 0;
  g_ObCallbackHandle = NULL;

  if (!g_PatchGuardBypassed) {
    DbgPrint("[LongsDriver] ProcessProtect: skipped, PatchGuard bypass "
             "inactive (safe mode).\n");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  RtlInitUnicodeString(&altitude, PROCESS_PROTECT_ALTITUDE);

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
  if (!NT_SUCCESS(status)) {
    g_ObCallbackHandle = NULL;
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

NTSTATUS ProcessProtect(ULONG ProcessId) {
  if (!ProcessProtectAvailable())
    return STATUS_DEVICE_CONFIGURATION_ERROR;

  if (!IsValidProcessId(ProcessId))
    return STATUS_INVALID_PARAMETER;

  if (!AddProtectedProcess(ProcessId))
    return STATUS_INSUFFICIENT_RESOURCES;

  DbgPrint("[LongsDriver] Protected process %lu against kill.\n", ProcessId);
  return STATUS_SUCCESS;
}

NTSTATUS ProcessUnprotect(ULONG ProcessId) {
  if (!ProcessProtectAvailable())
    return STATUS_DEVICE_CONFIGURATION_ERROR;

  if (!IsValidProcessId(ProcessId))
    return STATUS_INVALID_PARAMETER;

  if (!RemoveProtectedProcess(ProcessId))
    return STATUS_NOT_FOUND;

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
