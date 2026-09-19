#include "TaskInternal.h"

static NTSTATUS ReadTaskFileInternal(PWCHAR *outBuffer, ULONG *outByteLen) {
  NTSTATUS status;
  UNICODE_STRING path = RTL_CONSTANT_STRING(TASK_FILE_PATH);
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  HANDLE handle = NULL;
  FILE_STANDARD_INFORMATION stdInfo;
  PVOID buffer = NULL;
  LARGE_INTEGER readOffset = {0};

  *outBuffer = NULL;
  *outByteLen = 0;

  InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenFile(&handle, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] TaskPersistence: open task file (read): 0x%X\n",
             status);
    return status;
  }

  status = ZwQueryInformationFile(handle, &iosb, &stdInfo, sizeof(stdInfo),
                                  FileStandardInformation);
  if (!NT_SUCCESS(status)) {
    ZwClose(handle);
    return status;
  }
  if (stdInfo.EndOfFile.QuadPart <= 0 ||
      stdInfo.EndOfFile.QuadPart > TASK_FILE_MAX_BYTES) {
    ZwClose(handle);
    return STATUS_FILE_TOO_LARGE;
  }

  buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                           (ULONG)stdInfo.EndOfFile.QuadPart, TASK_POOL_TAG);
  if (buffer == NULL) {
    ZwClose(handle);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = ZwReadFile(handle, NULL, NULL, NULL, &iosb, buffer,
                      (ULONG)stdInfo.EndOfFile.QuadPart, &readOffset, NULL);
  ZwClose(handle);

  if (!NT_SUCCESS(status) ||
      (ULONGLONG)iosb.Information != (ULONGLONG)stdInfo.EndOfFile.QuadPart) {
    if (NT_SUCCESS(status))
      status = STATUS_IO_DEVICE_ERROR;
    ExFreePoolWithTag(buffer, TASK_POOL_TAG);
    return status;
  }

  *outBuffer = (PWCHAR)buffer;
  *outByteLen = (ULONG)stdInfo.EndOfFile.QuadPart;
  return STATUS_SUCCESS;
}

static NTSTATUS WriteTaskFileInternal(PWCHAR buffer, ULONG byteLen) {
  NTSTATUS status;
  UNICODE_STRING path = RTL_CONSTANT_STRING(TASK_FILE_PATH);
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  HANDLE handle = NULL;
  LARGE_INTEGER writeOffset = {0};
  LARGE_INTEGER endOfFile;

  InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwCreateFile(&handle, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                        NULL, 0);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] TaskPersistence: create task file (write): 0x%X\n",
             status);
    return status;
  }

  status = ZwWriteFile(handle, NULL, NULL, NULL, &iosb, buffer, byteLen,
                       &writeOffset, NULL);
  if (NT_SUCCESS(status)) {
    endOfFile.QuadPart = iosb.Information;
    status = ZwSetInformationFile(handle, &iosb, &endOfFile, sizeof(endOfFile),
                                  FileEndOfFileInformation);
  }
  ZwClose(handle);
  return status;
}

// Impersonated wrappers: every file touch runs as the System process token.
NTSTATUS TaskReadTaskFile(PWCHAR *outBuffer, ULONG *outByteLen) {
  HANDLE token = NULL;
  NTSTATUS status = TaskImpersonateSystem(&token);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] TaskPersistence: SYSTEM impersonation failed: "
             "0x%X (falling back to caller token)\n",
             status);
  }
  status = ReadTaskFileInternal(outBuffer, outByteLen);
  TaskRevertImpersonation(token);
  return status;
}

NTSTATUS TaskWriteTaskFile(PWCHAR buffer, ULONG byteLen) {
  HANDLE token = NULL;
  NTSTATUS status = TaskImpersonateSystem(&token);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] TaskPersistence: SYSTEM impersonation failed: "
             "0x%X (falling back to caller token)\n",
             status);
  }
  status = WriteTaskFileInternal(buffer, byteLen);
  TaskRevertImpersonation(token);
  return status;
}