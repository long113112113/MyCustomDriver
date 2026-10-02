#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Reflective load of the embedded NetProbe image into a target process.
//
// The sequence is deliberately thin, because each half already exists:
//
//   1. RemoteInject writes the raw file image into the target and protects it
//      execute-read.
//   2. PeFindExportByName resolves the ReflectiveLoader export to a file offset
//      in that raw image.
//   3. ApcInject queues a user-mode APC to every thread at that address.
//
// The loader then maps the image into the target on its own. Nothing about the
// driver is reachable from the target after the APC is queued.
//
// The export name is the contract between this side and the DLL. It is the
// classic reflective-loader signature: self-locating, maps its own image, no
// imports and no resource lookups before it has mapped itself.
//
#define NETPROBE_REFLECTIVE_EXPORT "ReflectiveLoader"

//
// Initializes APC tracking. Called once from device init. Best effort: the
// injector also initializes lazily, so a missing call only means the unload
// drain has nothing to wait on.
//
NTSTATUS NetProbeInjectInitialize(VOID);

//
// Drains outstanding APCs. Called from DriverUnload so a pending APC cannot
// outlive the driver code its kernel routine lives in.
//
VOID NetProbeInjectCleanup(VOID);

//
// Starts the background worker that waits for explorer.exe, then injects the
// embedded NetProbe image into it. Called once at the end of device init so the
// load happens after every other module is up. Logs each stage through
// DbgPrint.
//
// Idempotent: a second call is a no-op.
//
NTSTATUS NetProbeInjectAutoStart(VOID);

//
// Writes the embedded NetProbe image into TargetPid and queues ReflectiveLoader
// in every one of its threads.
//
// Returns STATUS_SUCCESS once the APC is queued (the load itself happens later,
// in the target). On failure past the write, the remote image is released so no
// half-prepared region is left behind.
//
NTSTATUS NetProbeInjectIntoProcess(ULONG TargetPid);

#ifdef __cplusplus
}
#endif