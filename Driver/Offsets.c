#include "Offsets.h"

ULONG g_WindowsBuildNumber = 0;

NTSTATUS OffsetsInitialize(VOID) {
  NTSTATUS status;
  RTL_OSVERSIONINFOW osVersion;

  RtlZeroMemory(&osVersion, sizeof(osVersion));
  osVersion.dwOSVersionInfoSize = sizeof(osVersion);

  status = RtlGetVersion(&osVersion);
  if (NT_SUCCESS(status)) {
    g_WindowsBuildNumber = osVersion.dwBuildNumber;
    DbgPrint("Windows build: %lu\n", g_WindowsBuildNumber);
  }

  return status;
}

ULONG GetActiveProcessLinksOffset(VOID) {
#ifndef _AMD64_
  return 0;
#else
  ULONG offset = 0;

  if (g_WindowsBuildNumber < WIN_1507 || g_WindowsBuildNumber > WIN_LATEST)
    return offset;

  switch (g_WindowsBuildNumber) {
  case WIN_1507:
  case WIN_1511:
  case WIN_1607:
  case WIN_1903:
  case WIN_1909:
    offset = 0x2f0;
    break;
  case WIN_1703:
  case WIN_1709:
  case WIN_1803:
  case WIN_1809:
    offset = 0x2e8;
    break;
  case WIN_11_24H2:
  case WIN_11_25H2:
    offset = 0x1d8;
    break;
  default:
    offset = 0x448;
    break;
  }

  return offset;
#endif
}

ULONG GetProcessLockOffset(VOID) {
#ifndef _AMD64_
  return 0;
#else
  ULONG offset = 0;

  if (g_WindowsBuildNumber < WIN_1507 || g_WindowsBuildNumber > WIN_LATEST)
    return offset;

  switch (g_WindowsBuildNumber) {
  case WIN_1507:
  case WIN_1511:
  case WIN_1607:
  case WIN_1703:
  case WIN_1709:
  case WIN_1803:
  case WIN_1809:
    offset = 0x2d8;
    break;
  case WIN_1903:
  case WIN_1909:
    offset = 0x2e0;
    break;
  case WIN_11_24H2:
  case WIN_11_25H2:
    offset = 0x1c8;
    break;
  default:
    offset = 0x438;
    break;
  }

  return offset;
#endif
}