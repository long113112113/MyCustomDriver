#pragma once
#include "Shared.h"
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Registers as a Winsock Kernel (WSK) client so this driver can open outbound
// TCP connections from kernel mode, then starts a worker that probes the
// hardcoded host in WskClient.c on a fixed interval until the module is torn
// down. Nothing outside the driver triggers it: no IOCTL, no client.
//
// Why the WSK entry points are resolved at runtime
// -------------------------------------------------
// WskRegister and friends live in netio.sys, not ntoskrnl.exe, so they would
// have to be imported from netio.sys. That is not acceptable here: this image
// is mapped by kdmapper rather than loaded by the I/O manager, and the project
// rule is that /imports must contain ntoskrnl.exe only. Adding netio.sys to the
// import table would also make the load depend on netio.sys already being
// mapped, which is not something kdmapper guarantees. Every entry point is
// therefore fetched with MmGetSystemRoutineAddress, in the same style as the
// IoCreateDriver resolution in DriverEntry.c, which leaves the import table
// untouched and lets the lookup be retried once netio.sys is present.
//
// Why the provider NPI is captured on a worker thread
// ----------------------------------------------------
// WskRegister only records the client; it does not touch the network stack and
// completes inline, so it is safe to call from driver init. WskCaptureProviderNPI
// on the other hand blocks until the WSK subsystem has a provider to hand out,
// which on a booting machine can be many seconds. Calling it from the entry
// would stall kdmapper, so the worker thread captures it and only then enters
// the probe loop. Capturing and probing share one thread because the probe
// cannot run before the capture completes.
//
// The worker logs every outcome through DbgPrint rather than reporting to a
// caller, so there is deliberately no query or probe entry point in this
// header.
//
NTSTATUS WskClientInitialize(VOID);

//
// Stops the probe loop, releases the captured provider NPI and deregisters.
// Safe to call when initialization failed or never ran. Must be called at
// PASSIVE_LEVEL. On the mapped-load path DriverUnload is cleared, so this
// normally does not run: WSK stays registered and the probe keeps running until
// reboot.
//
VOID WskClientCleanup(VOID);

#ifdef __cplusplus
}
#endif
