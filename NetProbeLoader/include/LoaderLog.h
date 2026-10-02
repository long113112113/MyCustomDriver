#ifndef NETPROBELOADER_LOADERLOG_H
#define NETPROBELOADER_LOADERLOG_H

//
// Loader diagnostics.
//
// Every stage that can reject an image reports here. The loader runs once,
// before the payload exists, so it has no logging of its own to fall back on
// and deliberately holds no file handle it could leak when mapping fails halfway.
//
// Release only emits OutputDebugString. Debug additionally appends to a file,
// because OutputDebugString is invisible unless a debugger is attached and a
// loader that stops at "fail import" with no record of which symbol is close to
// undebuggable.
//

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opens the debug trace file. Idempotent; called from DllMain.
void LoaderTraceOpen(void);

#ifdef NETPROBE_LOADER_TRACE

// Debug-only. Logs an arbitrary string in brackets, for the names that failed to
// bind. The only reader is whoever is diagnosing the failure.
void LoaderTraceName(const char *text);

#define LOADER_TRACE_NAME(text) LoaderTraceName(text)

#else

#define LOADER_TRACE_NAME(text) ((void)0)

#endif

// "message <value in decimal>"
void LoaderLogLine(const char *message, UINT64 value);

// "message 0x<value in hex>"
void LoaderLogHex(const char *message, UINT64 value);

#ifdef __cplusplus
}
#endif

#endif
