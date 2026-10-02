#include "LoaderPe.h"
#include "LoaderLog.h"
#include "LoaderSelf.h"

//
// Kept thin on purpose. The loader must not start doing work on load: the whole
// point of ReflectiveLoad being an explicit export is that the payload is
// mapped when the caller asks for it, not because a DLL got loaded.
//
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  UNREFERENCED_PARAMETER(reserved);

  if (reason == DLL_PROCESS_ATTACH) {
    LoaderTraceOpen();
    g_ownModule = instance;
    DisableThreadLibraryCalls(instance);
    LoaderLogLine("[loader] DllMain attach", 0);
  }
  return TRUE;
}
