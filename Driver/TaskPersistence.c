#include "TaskPersistence.h"
#include "TaskInternal.h"
#include <ntstrsafe.h>

NTSTATUS TaskPersistenceSetImagePath(PWCHAR path, ULONG charCount) {
  return TaskSetImagePathCache(path, charCount);
}

NTSTATUS TaskPersistenceInitialize(VOID) {
  NTSTATUS status;
  PWCHAR buffer = NULL;
  ULONG byteLen = 0;

  status = TaskReadTaskFile(&buffer, &byteLen);
  if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
    DbgPrint(
        "[LongsDriver] Auto-load task missing (creation deferred to client "
        "context).\n");
  } else if (NT_SUCCESS(status)) {
    ExFreePoolWithTag(buffer, TASK_POOL_TAG);
    DbgPrint("[LongsDriver] Auto-load task already present.\n");
  } else {
    DbgPrint("[LongsDriver] Auto-load task check failed: 0x%X\n", status);
  }

  return STATUS_SUCCESS;
}

VOID TaskPersistenceCleanup(VOID) {}

NTSTATUS TaskPersistenceControl(ULONG op, PULONG state) {
  NTSTATUS status;
  BOOLEAN enabled = FALSE;
  BOOLEAN want = (op == TASK_OP_ENABLE) ? TRUE : FALSE;
  PWCHAR buffer = NULL;
  ULONG byteLen = 0;
  ULONG charCount = 0;

  if (state)
    *state = 0;
  if (op > TASK_OP_DISABLE)
    return STATUS_INVALID_PARAMETER;

  status = TaskReadTaskFile(&buffer, &byteLen);
  if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

    if (op != TASK_OP_QUERY && op != TASK_OP_ENABLE)
      return STATUS_SUCCESS;
    status = TaskCreateTaskFile(TRUE);
    if (state)
      *state = NT_SUCCESS(status) ? 1 : 0;
    return status;
  }
  if (!NT_SUCCESS(status))
    return status;

  charCount = byteLen / sizeof(WCHAR);
  enabled = TaskBufferIsEnabled(buffer, charCount);

  if (op == TASK_OP_QUERY) {
    if (state)
      *state = enabled ? 1 : 0;
  } else if (enabled != want) {
    PWCHAR newBuffer = NULL;
    ULONG newByteLen = 0;
    status =
        TaskFlipEnabledTags(buffer, charCount, want, &newBuffer, &newByteLen);
    if (NT_SUCCESS(status) && newBuffer != NULL) {
      status = TaskWriteTaskFile(newBuffer, newByteLen);
      ExFreePoolWithTag(newBuffer, TASK_POOL_TAG);
    }
    if (state)
      *state = want ? 1 : 0;
  } else if (state) {
    *state = enabled ? 1 : 0;
  }

  ExFreePoolWithTag(buffer, TASK_POOL_TAG);
  return status;
}