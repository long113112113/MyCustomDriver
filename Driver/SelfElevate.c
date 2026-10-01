#include "SelfElevate.h"
#include "TaskInternal.h"

//
// Self elevation: hand the System process token to the calling client thread
// and leave it there.
//
// Scope - read this before wiring the feature up.
//
// This elevates a *thread*, not a process, and that is a constraint rather than
// a shortcut. The documented way to give a process the System token is
// ZwSetInformationProcess(ProcessAccessToken), and the DDK closes that path to
// any process that is already running: the PROCESS_ACCESS_TOKEN comment in
// ntddk.h states the precondition as "a process's access token can only be
// changed if the process has no threads or a single thread that has not yet
// begun execution". By the time the client calls us it is running with several
// threads, so ProcessAccessToken would fail and there is no privilege to
// reorder that from here.
//
// What remains is the thread impersonation token, which the DDK does allow to
// be set on a running thread. That is the mechanism below.
//
// Consequences the caller has to live with:
//
//   - Only the thread that issued the IOCTL is elevated. The client's other
//     threads keep their own tokens, and any thread it starts later inherits
//     the process token rather than this one. Reaching SYSTEM on another thread
//     means calling the elevate command from that thread.
//
//   - The token outlives the call. It is dropped when the thread exits or when
//     SelfUnelevate clears it, not when the IOCTL returns.
//
//   - The client's primary token is unchanged. Anything that reads the token
//     directly - OpenProcessToken on itself, GetTokenInformation - keeps
//     reporting the unelevated token even while this thread runs as SYSTEM.
//
//

NTSTATUS SelfElevate(VOID) {
  HANDLE token = NULL;
  NTSTATUS status;

  //
  // Reuse the TaskPersistence path rather than reimplementing it. That helper
  // duplicates the System token as a normal (user-mode) handle and attaches it
  // to this thread via ZwSetInformationThread; TaskFile.c then reverts it
  // immediately. This function stops right where TaskFile.c would start.
  //
  status = TaskImpersonateSystem(&token);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  //
  // ZwSetInformationThread gave the thread its own reference to the token
  // object, so the driver's handle is no longer needed and can be dropped
  // without ending the impersonation. TaskRevertImpersonation cannot be used
  // here: it both clears the thread token and closes the handle, and clearing
  // the token is the opposite of what this command is for.
  //
  ZwClose(token);
  return STATUS_SUCCESS;
}

NTSTATUS SelfUnelevate(VOID) {
  HANDLE nullToken = NULL;

  //
  // A NULL token in ThreadImpersonationToken means "impersonate nobody", which
  // restores this thread to using its process token.
  //
  return ZwSetInformationThread(PsGetCurrentThread(), ThreadImpersonationToken,
                                &nullToken, sizeof(nullToken));
}

NTSTATUS SelfQueryElevation(PULONG Elevated) {
  HANDLE token = NULL;
  NTSTATUS status;

  if (Elevated == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  *Elevated = 0;

  status = ZwQueryInformationThread(PsGetCurrentThread(),
                                    ThreadImpersonationToken, &token,
                                    sizeof(token), NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  *Elevated = (token != NULL) ? 1 : 0;

  //
  // The query returns a handle this call now owns. Close it, otherwise a plain
  // status check leaks a token handle every time it is issued.
  //
  if (token != NULL) {
    ZwClose(token);
  }

  return STATUS_SUCCESS;
}
