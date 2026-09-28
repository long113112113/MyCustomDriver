
#include "Bypass.h"
#include "Kurasagi\Global.hpp"
#include "Kurasagi\Log.hpp"
#include "Kurasagi\Module.hpp"
#include "Kurasagi\Util\Memory.hpp"

extern "C" BOOLEAN g_PatchGuardBypassed = FALSE;

extern "C" BOOLEAN BypassPatchGuard(void) {
  if (!gl::RtVar::InitializeRuntimeVariables()) {
    LogError("[Kurasagi]: Bypass Failed to initialize runtime variables.");
    return FALSE;
  }

  if (gl::RtVar::MmAccessFaultPtr == nullptr) {
    LogError("[Kurasagi]: MmAccessFaultPtr is NULL after runtime variable initialization.");
    return FALSE;
  }

  if (*(UCHAR *)gl::RtVar::MmAccessFaultPtr == 0xFF) {
    LogInfo("[Kurasagi]: PatchGuard already bypassed this boot, skipping.");
    return TRUE;
  }

  if (!wsbp::BypassPatchGuard()) {
    LogError("[Kurasagi]: Failed to bypass PatchGuard.");
    return FALSE;
  }

  LogInfo("[Kurasagi]: PatchGuard bypassed.");
  return TRUE;
}

extern "C" BOOLEAN BypassGetKernelBaseNSize(PVOID *OutBase, ULONG *OutSize) {
  uintptr_t base = 0;
  size_t size = 0;

  if (OutBase == nullptr || OutSize == nullptr) {
    return FALSE;
  }

  if (!GetKernelBaseNSize(&base, &size)) {
    return FALSE;
  }

  *OutBase = reinterpret_cast<PVOID>(base);
  *OutSize = static_cast<ULONG>(size);
  return TRUE;
}