#include "TaskInternal.h"

//
// SYSTEM impersonation ------------------------------------------------------
//
// Writing into \SystemRoot\System32\Tasks is DACL-guarded (SYSTEM/admin
// only). A driver can bypass that check by impersonating the System process
// token before touching the file system, so the task can be created even when
// the mapping client is not elevated. PsOpenProcessToken is declared by the
// DDK headers but is NOT actually exported by ntoskrnl (resolving it returns
// STATUS_PROCEDURE_NOT_FOUND), so instead open the System process object from
// kernel mode (ObOpenObjectByPointer bypasses the caller DACL) and use
// ZwOpenProcessTokenEx to reach its token.
//

NTSTATUS TaskImpersonateSystem(PHANDLE tokenOut) {
  NTSTATUS status;
  PEPROCESS systemProcess = NULL;
  POBJECT_TYPE processType = NULL;
  HANDLE hProcess = NULL;
  HANDLE systemToken = NULL;
  HANDLE dupToken = NULL;
  OBJECT_ATTRIBUTES oa;
  SECURITY_QUALITY_OF_SERVICE sqos;

  *tokenOut = NULL;

  status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)4, &systemProcess);
  DbgPrint("[LongsDriver] Impersonate: lookup System (PID 4): 0x%X\n", status);
  if (!NT_SUCCESS(status))
    return status;

  processType = ObGetObjectType((PVOID)systemProcess);
  status = ObOpenObjectByPointer(systemProcess, OBJ_KERNEL_HANDLE, NULL,
                                 PROCESS_QUERY_INFORMATION, processType,
                                 KernelMode, &hProcess);
  ObDereferenceObject(systemProcess);
  DbgPrint("[LongsDriver] Impersonate: open System process handle: 0x%X\n",
           status);
  if (!NT_SUCCESS(status))
    return status;

  status = ZwOpenProcessTokenEx(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY,
                                OBJ_KERNEL_HANDLE, &systemToken);
  ZwClose(hProcess);
  DbgPrint("[LongsDriver] Impersonate: open System token: 0x%X\n", status);
  if (!NT_SUCCESS(status))
    return status;

  sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
  sqos.ImpersonationLevel = SecurityImpersonation;
  sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
  sqos.EffectiveOnly = FALSE;

  // dupToken must be a NORMAL (user) handle, not OBJ_KERNEL_HANDLE: it is
  // referenced by ZwSetInformationThread/ObReferenceObjectByHandle using the
  // thread's previous mode (UserMode for the IOCTL caller thread), which
  // rejects kernel-mode handles with STATUS_INVALID_HANDLE.
  InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
  oa.SecurityQualityOfService = &sqos;

  status = ZwDuplicateToken(systemToken, TOKEN_ALL_ACCESS, &oa, FALSE,
                            TokenImpersonation, &dupToken);
  ZwClose(systemToken);
  DbgPrint("[LongsDriver] Impersonate: duplicate token (rev2): 0x%X\n", status);
  if (!NT_SUCCESS(status))
    return status;

  status = ZwSetInformationThread((HANDLE)(LONG_PTR)-2,
                                  ThreadImpersonationToken, &dupToken,
                                  sizeof(HANDLE));
  DbgPrint("[LongsDriver] Impersonate: set thread token (rev3, dupToken %p): "
           "0x%X\n",
           dupToken, status);
  if (NT_SUCCESS(status)) {
    *tokenOut = dupToken;
  } else {
    ZwClose(dupToken);
  }
  return status;
}

VOID TaskRevertImpersonation(HANDLE token) {
  HANDLE nullHandle = NULL;
  if (token == NULL)
    return;
  ZwSetInformationThread((HANDLE)(LONG_PTR)-2, ThreadImpersonationToken,
                         &nullHandle, sizeof(nullHandle));
  ZwClose(token);
}