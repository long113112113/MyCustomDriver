#ifndef NETPROBELOADER_LOADERSELF_H
#define NETPROBELOADER_LOADERSELF_H

//
// The loader's own module handle.
//
// DllMain records it on attach, because it is the handle FindResourceA needs to
// find the embedded payload. ReflectiveLoad falls back to
// GetModuleHandleA(NULL) so the export still works if it is ever called before
// attach is observed.
//

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

extern HMODULE g_ownModule;

#endif
