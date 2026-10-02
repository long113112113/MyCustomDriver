#include "Probe.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

//
// Kept deliberately thin.
//
// The reflective loader added later calls into this same file, so the boundary
// between "loader brings the image up" and "image starts working" stays in one
// place: DllMain is the only thing that starts the probe, and NetProbeStart is
// the only thing it calls.
//
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
  UNREFERENCED_PARAMETER(reserved);

  switch (reason) {
  case DLL_PROCESS_ATTACH:
    //
    // The probe never calls back into this module, so the notifications are
    // pure overhead. Suppressing them also avoids the loader lock being held on
    // a thread attach path.
    //
    DisableThreadLibraryCalls(module);
    NetProbeStart();
    break;

  case DLL_PROCESS_DETACH:
    NetProbeStop();
    break;

  default:
    break;
  }

  return TRUE;
}
