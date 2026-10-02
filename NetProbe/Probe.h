#pragma once
#ifndef NETPROBE_PROBE_H
#define NETPROBE_PROBE_H

//
// Probe parameters. These mirror the kernel WSK probe that was removed: the same
// host, port, payload and cadence, so behaviour can be compared directly once the
// network layer moves out of the driver.
//
#define NETPROBE_HOST "192.168.153.1"
#define NETPROBE_PORT 8080
#define NETPROBE_REQUEST "PING\n"
#define NETPROBE_EXPECTED "PONG\n"

#define NETPROBE_INTERVAL_MS 5000
#define NETPROBE_CONNECT_TIMEOUT_MS 5000
#define NETPROBE_IO_TIMEOUT_MS 5000

#ifdef __cplusplus
extern "C" {
#endif

//
// Starts the worker thread that probes the host on a timer until stopped.
// Nothing outside this DLL triggers a probe: no IOCTL, no client, no arguments.
//
// Returns 1 if the worker was started, 0 otherwise. Safe to call more than once;
// subsequent calls while running are no-ops and return 1.
//
__declspec(dllexport) int NetProbeStart(void);

//
// Signals the worker to stop and waits briefly for it to unwind. Safe to call
// when the worker never started.
//
__declspec(dllexport) void NetProbeStop(void);

#ifdef __cplusplus
}
#endif

#endif
