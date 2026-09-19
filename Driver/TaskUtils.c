#include <ntddk.h>
#include "TaskInternal.h"

ULONG WStrLen(PCWSTR s) {
  ULONG n = 0;
  while (s[n] != L'\0')
    n++;
  return n;
}

LONG FindWStr(PCWSTR hay, ULONG hayLen, PCWSTR needle) {
  ULONG needleLen = WStrLen(needle);
  if (needleLen == 0 || needleLen > hayLen)
    return -1;
  ULONG last = hayLen - needleLen;
  for (ULONG i = 0; i <= last; i++) {
    if (RtlEqualMemory(hay + i, needle, needleLen * sizeof(WCHAR)))
      return (LONG)i;
  }
  return -1;
}

PVOID ResolveExportByWChar(PCWSTR name) {
  UNICODE_STRING routineName;
  RtlInitUnicodeString(&routineName, name);
  return MmGetSystemRoutineAddress(&routineName);
}