
#include "Bypass.h"
#include "Kurasagi\Global.hpp"
#include "Kurasagi\Log.hpp"
#include "Kurasagi\Module.hpp"

extern "C" BOOLEAN BypassPatchGuard(void) {
  if (!gl::RtVar::InitializeRuntimeVariables()) {
    LogError("[Kurasagi]: Bypass Failed to initialize runtime variables.");
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