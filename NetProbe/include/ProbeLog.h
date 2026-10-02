#ifndef NETPROBE_PROBELOG_H
#define NETPROBE_PROBELOG_H

//
// Line logging for the probe.
//
// One shared buffer per line, flushed to two sinks: OutputDebugStringA so the
// lines appear in a debugger attached to the target, and a file under %TEMP% so
// the probe can be checked without one. Both receive the same bytes.
//
// Every entry point here composes and flushes a whole line. Callers never see
// the buffer, which is what keeps a probe guaranteed to occupy exactly one log
// line no matter how many pieces make it up.
//

// Set NETPROBE_LOG_TO_FILE to 0 in the build to drop the file sink. That is what
// a build meant to live inside someone else's process should use.
#ifndef NETPROBE_LOG_TO_FILE
#define NETPROBE_LOG_TO_FILE 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opens the file sink. Idempotent, and called once from NetProbeStart.
void LogOpenFile(void);

// Closes the file sink. Called from NetProbeStop.
void LogCloseFile(void);

// "message"
void LogMsg(const char *message);

// "message detail", for the few places where a value is worth inlining as text.
void LogMsgText(const char *message, const char *detail);

// "message 0xCODE", for Winsock error codes.
void LogMsgCode(const char *message, unsigned long code);

// "every Nms", emitted once by the worker at startup.
void LogProbeEvery(unsigned long milliseconds);

// "ok <stage> in Nms reply \"...\"" - a successful probe.
// The reply is escaped, so a reply containing newlines stays on one line.
void LogProbeOk(const char *stage, unsigned long milliseconds,
                const char *reply, int replyLength);

// "fail unexpected reply \"...\""
void LogProbeBad(const char *reply, int replyLength);

// "fail <stage> error 0xCODE"
void LogProbeFail(const char *stage, unsigned long code);

#ifdef __cplusplus
}
#endif

#endif
