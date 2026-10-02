//
// Line logging implementation.
//
// A line is built into one shared buffer and flushed as a unit. Building the
// line and flushing it both happen under a single lock, so the probe running on
// the worker thread and a NetProbeStop on another thread cannot interleave
// halves of two lines into the output.
//

#include "ProbeLog.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

#define LOG_BUFFER_SIZE 512

static char g_log[LOG_BUFFER_SIZE];
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static SRWLOCK g_logLock = SRWLOCK_INIT;

//
// Line sinks
//
void LogOpenFile(void) {
  char path[MAX_PATH];
  DWORD used;

  if (g_logFile != INVALID_HANDLE_VALUE || NETPROBE_LOG_TO_FILE == 0) {
    return;
  }

  used = GetTempPathA(MAX_PATH, path);
  if (used == 0 || used >= MAX_PATH) {
    return;
  }
  lstrcatA(path, "NetProbe.log");

  g_logFile = CreateFileA(path, FILE_APPEND_DATA,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (g_logFile != INVALID_HANDLE_VALUE) {
    SetFilePointer(g_logFile, 0, NULL, FILE_END);
  }
}

void LogCloseFile(void) {
  if (g_logFile != INVALID_HANDLE_VALUE) {
    CloseHandle(g_logFile);
    g_logFile = INVALID_HANDLE_VALUE;
  }
}

//
// Buffer appends
//
// Every helper starts writing at the current end of the line rather than at a
// fixed offset. The numeric helpers originally started at zero, which silently
// truncated whatever the tag had already written - that is how "every 5000ms"
// came out as "5000ms".
//
static size_t LogEnd(void) {
  size_t pos = 0;
  while (g_log[pos] != '\0' && pos + 1 < LOG_BUFFER_SIZE) {
    pos++;
  }
  return pos;
}

static size_t LogText(const char *text) {
  size_t pos = LogEnd();

  while (*text != '\0' && pos + 1 < LOG_BUFFER_SIZE) {
    g_log[pos++] = *text++;
  }
  g_log[pos] = '\0';
  return pos;
}

static size_t LogHex(unsigned long value) {
  static const char kHex[] = "0123456789ABCDEF";
  char digits[8];
  size_t pos;
  int count = 0;

  if (value == 0) {
    digits[count++] = '0';
  }
  while (value != 0 && count < 8) {
    digits[count++] = kHex[value & 0xF];
    value >>= 4;
  }

  pos = LogEnd();
  while (count > 0 && pos + 1 < LOG_BUFFER_SIZE) {
    g_log[pos++] = kHex[digits[--count]];
  }
  g_log[pos] = '\0';
  return pos;
}

static size_t LogDec(unsigned long value) {
  char digits[10];
  size_t pos;
  int count = 0;

  if (value == 0) {
    digits[count++] = '0';
  }
  while (value != 0 && count < 10) {
    digits[count++] = (char)('0' + (value % 10));
    value /= 10;
  }

  pos = LogEnd();
  while (count > 0 && pos + 1 < LOG_BUFFER_SIZE) {
    g_log[pos++] = digits[--count];
  }
  g_log[pos] = '\0';
  return pos;
}

//
// Line assembly
//
static void LogBegin(void) {
  AcquireSRWLockExclusive(&g_logLock);
  g_log[0] = '\0';
  LogText("[NetProbe] ");
}

static void LogFlush(void) {
  if (g_logFile != INVALID_HANDLE_VALUE) {
    //
    // Two writes rather than appending a CRLF into the buffer: the buffer may
    // already be full, and there is no room left at the tail to put it in.
    //
    WriteFile(g_logFile, g_log, (DWORD)strlen(g_log), NULL, NULL);
    WriteFile(g_logFile, "\r\n", 2, NULL, NULL);
  }
  OutputDebugStringA(g_log);
  ReleaseSRWLockExclusive(&g_logLock);
}

//
// Appends bytes with control characters escaped.
//
// The reply is data that arrived over the network and it ends in a newline, so
// logging it raw would split one probe across several lines. Everything below
// 0x20, plus DEL, becomes an escape sequence instead, which keeps one probe on
// one line regardless of what the peer sent.
//
static void LogEscaped(const char *data, int length) {
  static const char kHex[] = "0123456789ABCDEF";
  int i;

  for (i = 0; i < length; i++) {
    unsigned char c = (unsigned char)data[i];

    if (c == '\n') {
      LogText("\\n");
    } else if (c == '\r') {
      LogText("\\r");
    } else if (c == '\t') {
      LogText("\\t");
    } else if (c < 0x20 || c == 0x7F) {
      char escaped[5];
      escaped[0] = '\\';
      escaped[1] = 'x';
      escaped[2] = kHex[(c >> 4) & 0xF];
      escaped[3] = kHex[c & 0xF];
      escaped[4] = '\0';
      LogText(escaped);
    } else {
      char one[2];
      one[0] = (char)c;
      one[1] = '\0';
      LogText(one);
    }
  }
}

//
// Public entry points. Each one composes and flushes a whole line, so no caller
// can emit a partial one.
//
void LogMsg(const char *message) {
  LogBegin();
  LogText(message);
  LogFlush();
}

void LogMsgText(const char *message, const char *detail) {
  LogBegin();
  LogText(message);
  LogText(detail);
  LogFlush();
}

void LogMsgCode(const char *message, unsigned long code) {
  LogBegin();
  LogText(message);
  LogText("0x");
  LogHex(code);
  LogFlush();
}

void LogProbeEvery(unsigned long milliseconds) {
  LogBegin();
  LogText("every ");
  LogDec(milliseconds);
  LogText("ms");
  LogFlush();
}

void LogProbeOk(const char *stage, unsigned long milliseconds,
               const char *reply, int replyLength) {
  LogBegin();
  LogText("ok ");
  LogText(stage);
  LogText(" in ");
  LogDec(milliseconds);
  LogText("ms");
  if (reply != NULL) {
    LogText(" reply \"");
    LogEscaped(reply, replyLength);
    LogText("\"");
  }
  LogFlush();
}

void LogProbeBad(const char *reply, int replyLength) {
  LogBegin();
  LogText("fail unexpected reply \"");
  LogEscaped(reply, replyLength);
  LogText("\"");
  LogFlush();
}

void LogProbeFail(const char *stage, unsigned long code) {
  LogBegin();
  LogText("fail ");
  LogText(stage);
  LogText(" error 0x");
  LogHex(code);
  LogFlush();
}
