#ifndef NETPROBE_PROBENET_H
#define NETPROBE_PROBENET_H

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

#ifdef __cplusplus
}
#endif

#endif
