#include "TaskInternal.h"
#include <ntstrsafe.h>

static WCHAR g_clientImagePath[TASK_IMAGE_PATH_MAX] = {0};

NTSTATUS TaskSetImagePathCache(PWCHAR path, ULONG charCount) {
  if (path == NULL || charCount == 0 || charCount >= TASK_IMAGE_PATH_MAX)
    return STATUS_INVALID_PARAMETER;
  RtlCopyMemory(g_clientImagePath, path, charCount * sizeof(WCHAR));
  g_clientImagePath[charCount] = L'\0';
  DbgPrint("[LongsDriver] Task image path set: %ls\n", g_clientImagePath);
  return STATUS_SUCCESS;
}

NTSTATUS TaskBuildTaskXml(PWCHAR xml, ULONG xmlCapacityChars, PULONG charCount,
                          BOOLEAN enabled) {
  NTSTATUS status;
  SIZE_T xmlLength = 0;
  PUNICODE_STRING command = NULL;
  PWCHAR toFree = NULL;

  if (g_clientImagePath[0] != L'\0') {
    // Authoritative: the client supplied its own Win32 path.
    static UNICODE_STRING cachedPath;
    RtlInitUnicodeString(&cachedPath, g_clientImagePath);
    command = &cachedPath;
    DbgPrint("[LongsDriver] Auto-load task command (client): %wZ\n", command);
  } else {

    PSE_LOCATE_PROCESS_IMAGE_NAME locateImage =
        (PSE_LOCATE_PROCESS_IMAGE_NAME)ResolveExportByWChar(
            L"SeLocateProcessImageName");
    PUNICODE_STRING imagePath;
    if (locateImage == NULL)
      return STATUS_PROCEDURE_NOT_FOUND;
    status = locateImage(PsGetCurrentProcess(), &imagePath);
    if (!NT_SUCCESS(status) || imagePath == NULL || imagePath->Buffer == NULL)
      return STATUS_UNSUCCESSFUL;

    command = imagePath;
    UNICODE_STRING dosPath;
    NTSTATUS dosStatus = TaskImagePathToDos(imagePath, &dosPath);
    if (NT_SUCCESS(dosStatus)) {
      command = &dosPath;
      toFree = dosPath.Buffer;
      DbgPrint("[LongsDriver] Auto-load task command (win32): %wZ\n", command);
    } else {
      DbgPrint("[LongsDriver] Auto-load task command (nt, dos-status 0x%X): "
               "%wZ\n",
               dosStatus, imagePath);
    }
  }

  status = RtlStringCchPrintfW(
      xml, xmlCapacityChars,
      L"\xFEFF<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
      L"<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/"
      L"2004/02/mit/task\">\r\n"
      L"  <RegistrationInfo>\r\n"
      L"    <Date>2026-09-19T00:00:00</Date>\r\n"
      L"    <Author>LongsDriver</Author>\r\n"
      L"    <URI>\\LongsDriver</URI>\r\n"
      L"  </RegistrationInfo>\r\n"
      L"  <Triggers>\r\n"
      L"    <BootTrigger>\r\n"
      L"      <Enabled>%ws</Enabled>\r\n"
      L"    </BootTrigger>\r\n"
      L"  </Triggers>\r\n"
      L"  <Principals>\r\n"
      L"    <Principal id=\"Author\">\r\n"
      L"      <UserId>S-1-5-18</UserId>\r\n"
      L"    </Principal>\r\n"
      L"  </Principals>\r\n"
      L"  <Settings>\r\n"
      L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
      L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
      L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
      L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
      L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
      L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
      L"    <IdleSettings>\r\n"
      L"      <StopOnIdleEnd>true</StopOnIdleEnd>\r\n"
      L"      <RestartOnIdle>false</RestartOnIdle>\r\n"
      L"    </IdleSettings>\r\n"
      L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
      L"    <Enabled>%ws</Enabled>\r\n"
      L"    <Hidden>true</Hidden>\r\n"
      L"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n"
      L"    <WakeToRun>false</WakeToRun>\r\n"
      L"    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\r\n"
      L"    <Priority>7</Priority>\r\n"
      L"  </Settings>\r\n"
      L"  <Actions Context=\"Author\">\r\n"
      L"    <Exec>\r\n"
      L"      <Command>\"%wZ\"</Command>\r\n"
      L"    </Exec>\r\n"
      L"  </Actions>\r\n"
      L"</Task>\r\n",
      enabled ? L"true" : L"false", enabled ? L"true" : L"false", command);
  if (!NT_SUCCESS(status))
    return status;

  status = RtlStringCchLengthW(xml, xmlCapacityChars, &xmlLength);
  if (!NT_SUCCESS(status))
    return status;

  if (toFree != NULL) {
    ExFreePoolWithTag(toFree, TASK_POOL_TAG);
    toFree = NULL;
  }
  if (charCount)
    *charCount = (ULONG)xmlLength;
  return STATUS_SUCCESS;
}

NTSTATUS TaskCreateTaskFile(BOOLEAN enabled) {
  NTSTATUS status;
  PWCHAR xml = ExAllocatePool2(
      POOL_FLAG_NON_PAGED, TASK_XML_MAX_WCHAR * sizeof(WCHAR), TASK_POOL_TAG);
  ULONG charCount = 0;
  if (xml == NULL)
    return STATUS_INSUFFICIENT_RESOURCES;

  status = TaskBuildTaskXml(xml, TASK_XML_MAX_WCHAR, &charCount, enabled);
  if (NT_SUCCESS(status))
    status = TaskWriteTaskFile(xml, charCount * sizeof(WCHAR));

  ExFreePoolWithTag(xml, TASK_POOL_TAG);
  return status;
}

BOOLEAN TaskBufferIsEnabled(PWCHAR text, ULONG charCount) {
  return FindWStr(text, charCount, L"<Enabled>false</Enabled>") < 0;
}

NTSTATUS TaskFlipEnabledTags(PWCHAR text, ULONG charCount, BOOLEAN toEnabled,
                             PWCHAR *outBuffer, ULONG *outByteLen) {
  PCWSTR from =
      toEnabled ? L"<Enabled>false</Enabled>" : L"<Enabled>true</Enabled>";
  PCWSTR to =
      toEnabled ? L"<Enabled>true</Enabled>" : L"<Enabled>false</Enabled>";
  ULONG fromLen = WStrLen(from);
  ULONG toLen = WStrLen(to);
  ULONG count = 0;

  for (LONG pos = 0; pos + fromLen <= charCount;) {
    LONG hit = FindWStr(text + pos, charCount - pos, from);
    if (hit < 0)
      break;
    count++;
    pos += hit + fromLen;
  }
  if (count == 0)
    return STATUS_SUCCESS;

  ULONG newCharCount = charCount + count * (toLen - fromLen);
  ULONG newByteLen = newCharCount * sizeof(WCHAR);
  PWCHAR out = ExAllocatePool2(POOL_FLAG_NON_PAGED, newByteLen, TASK_POOL_TAG);
  if (out == NULL)
    return STATUS_INSUFFICIENT_RESOURCES;

  ULONG src = 0;
  ULONG dst = 0;
  while (src < charCount) {
    LONG hit = FindWStr(text + src, charCount - src, from);
    if (hit < 0) {
      RtlCopyMemory(out + dst, text + src, (charCount - src) * sizeof(WCHAR));
      dst += charCount - src;
      break;
    }
    RtlCopyMemory(out + dst, text + src, hit * sizeof(WCHAR));
    dst += hit;
    RtlCopyMemory(out + dst, to, toLen * sizeof(WCHAR));
    dst += toLen;
    src += hit + fromLen;
  }
  *outBuffer = out;
  *outByteLen = newByteLen;
  return STATUS_SUCCESS;
}