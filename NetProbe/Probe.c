#include "Probe.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <string.h>

//
// Winsock entry points are resolved at runtime instead of imported.
//
// This is deliberate. A DLL that is going to be manually mapped has its import
// table rewritten by the loader code, and every entry in it is work to get right.
// Resolving ws2_32 by hand keeps the static import table down to kernel32, which
// the target process has already mapped, and it means the probe still works in a
// process where ws2_32 has never been loaded before.
//
// For the same reason nothing below calls into the CRT. There is no printf, no
// malloc and no STL: buffers live on the stack, formatting is done by hand, and
// logging goes to OutputDebugStringA. That is what lets the reflective loader
// bring this code up without running CRT startup.
//
typedef int(WSAAPI *PFN_WSAStartup)(WORD, LPWSADATA);
typedef int(WSAAPI *PFN_WSACleanup)(void);
typedef SOCKET(WSAAPI *PFN_socket)(int, int, int);
typedef int(WSAAPI *PFN_connect)(SOCKET, const SOCKADDR *, int);
typedef int(WSAAPI *PFN_send)(SOCKET, const char *, int, int);
typedef int(WSAAPI *PFN_recv)(SOCKET, char *, int, int);
typedef int(WSAAPI *PFN_closesocket)(SOCKET);
typedef int(WSAAPI *PFN_ioctlsocket)(SOCKET, long, ...);
typedef int(WSAAPI *PFN_select)(int, fd_set *, fd_set *, fd_set *,
                                const struct timeval *);
typedef int(WSAAPI *PFN_getsockopt)(SOCKET, int, int, char *, int *);
typedef int(WSAAPI *PFN_WSAGetLastError)(void);

typedef struct PROBE_WINSOCK {
  HMODULE Module;
  PFN_WSAStartup Startup;
  PFN_WSACleanup Cleanup;
  PFN_socket Socket;
  PFN_connect Connect;
  PFN_send Send;
  PFN_recv Recv;
  PFN_closesocket CloseSocket;
  PFN_ioctlsocket IoctlSocket;
  PFN_select Select;
  PFN_getsockopt GetSockOpt;
  PFN_WSAGetLastError GetLastError;
} PROBE_WINSOCK;

//
// Logging
//
// One shared buffer, one flush. The flush goes to two places: OutputDebugStringA
// so the lines show up in DebugView or a debugger attached to the target, and a
// file under %TEMP% so the probe can be checked without one. Both are the same
// bytes; only the sinks differ.
//
// Set NETPROBE_LOG_TO_FILE to 0 in the build to drop the file, which is what a
// build meant to live inside another process should probably use.
//
#if !defined(NETPROBE_LOG_TO_FILE)
#define NETPROBE_LOG_TO_FILE 1
#endif

static char g_log[512];
static HANDLE g_logFile = INVALID_HANDLE_VALUE;

static void LogOpenFile(void) {
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

static void LogCloseFile(void) {
  if (g_logFile != INVALID_HANDLE_VALUE) {
    CloseHandle(g_logFile);
    g_logFile = INVALID_HANDLE_VALUE;
  }
}

//
// Every helper appends at the current end of the line. LogEnd() is what finds
// it, and it has to be used by all of them: the numeric helpers used to start
// writing at offset 0, which silently truncated whatever the tag had already
// written and is how "every 5000ms" came out as "5000ms".
//
// The line is shared between the worker thread and whatever thread starts and
// stops it, so each log line is taken under one lock.
//
static size_t LogEnd(void) {
  size_t pos = 0;
  while (g_log[pos] != '\0' && pos + 1 < sizeof(g_log)) {
    pos++;
  }
  return pos;
}

static size_t LogText(const char *text) {
  size_t pos = LogEnd();
  while (*text != '\0' && pos + 1 < sizeof(g_log)) {
    g_log[pos++] = *text++;
  }
  g_log[pos] = '\0';
  return pos;
}

static size_t LogHex(unsigned long value) {
  char digits[8];
  size_t pos;
  int count = 0;

  if (value == 0) {
    digits[count++] = '0';
  }
  while (value != 0 && count < 8) {
    digits[count++] = "0123456789ABCDEF"[value & 0xF];
    value >>= 4;
  }

  pos = LogEnd();
  while (count > 0 && pos + 1 < sizeof(g_log)) {
    g_log[pos++] = "0123456789ABCDEF"[digits[--count]];
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
  while (count > 0 && pos + 1 < sizeof(g_log)) {
    g_log[pos++] = digits[--count];
  }
  g_log[pos] = '\0';
  return pos;
}

//
// A whole line is built under the lock and flushed under it, so two threads
// logging at once cannot interleave into the same buffer.
//
static SRWLOCK g_logLock = SRWLOCK_INIT;

static void LogBegin(void) {
  AcquireSRWLockExclusive(&g_logLock);
  g_log[0] = '\0';
  LogText("[NetProbe] ");
}

static void LogFlush(void) {
  if (g_logFile != INVALID_HANDLE_VALUE) {
    //
    // Two writes rather than appending a CRLF into g_log: the buffer can already
    // be full, and there is no room left at the tail to put it in.
    //
    WriteFile(g_logFile, g_log, (DWORD)strlen(g_log), NULL, NULL);
    WriteFile(g_logFile, "\r\n", 2, NULL, NULL);
  }
  OutputDebugStringA(g_log);
  ReleaseSRWLockExclusive(&g_logLock);
}

static void LogMsg(const char *message) {
  LogBegin();
  LogText(message);
  LogFlush();
}

static void LogMsgText(const char *message, const char *detail) {
  LogBegin();
  LogText(message);
  LogText(detail);
  LogFlush();
}

static void LogMsgCode(const char *message, unsigned long code) {
  LogBegin();
  LogText(message);
  LogText("0x");
  LogHex(code);
  LogFlush();
}

//
// Appends bytes with control characters escaped.
//
// The reply is data that came off the network: it ends in a newline, so logging
// it raw would split one log line across several. Everything below 0x20, plus
// DEL, becomes an escape sequence so one probe stays one line.
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

static void LogProbeOk(const char *stage, unsigned long milliseconds,
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

static void LogProbeBad(const char *reply, int replyLength) {
  LogBegin();
  LogText("fail unexpected reply \"");
  LogEscaped(reply, replyLength);
  LogText("\"");
  LogFlush();
}

static void LogProbeFail(const char *stage, unsigned long code) {
  LogBegin();
  LogText("fail ");
  LogText(stage);
  LogText(" error 0x");
  LogHex(code);
  LogFlush();
}

//
// Socket address helpers
//
// The host is a dotted quad, so no name resolution is needed. Building the
// SOCKADDR_IN by hand keeps getaddrinfo (and its DNS dependency) out of the DLL.
//
static unsigned short ProbeHtons(unsigned short value) {
  return (unsigned short)(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
}

static BOOL ProbeParseIpv4(const char *text, unsigned long *address) {
  unsigned long octet[4];
  int part = 0;
  unsigned long value = 0;
  int digits = 0;
  const char *p = text;

  if (text == NULL) {
    return FALSE;
  }

  while (part < 4) {
    value = 0;
    digits = 0;
    while (*p >= '0' && *p <= '9') {
      value = value * 10 + (unsigned long)(*p - '0');
      if (value > 255) {
        return FALSE;
      }
      digits++;
      p++;
    }
    if (digits == 0) {
      return FALSE;
    }
    octet[part++] = value;
    if (*p == '\0') {
      break;
    }
    if (*p != '.') {
      return FALSE;
    }
    p++;
  }

  if (part != 4 || *p != '\0') {
    return FALSE;
  }

  //
  // S_addr holds the four address bytes in network order, so the numeric value
  // depends on the host's own byte order: on little-endian x86 the first octet
  // has to end up in the LOW byte. Building it the other way round (first octet
  // shifted to the top) stores C0 A8 99 01 as the bytes 01 99 A8 C0, and the
  // stack then reads 1.153.168.192 - which just times out rather than failing
  // loudly, so it looks like a firewall problem instead of an addressing one.
  //
  *address = octet[0] | (octet[1] << 8) | (octet[2] << 16) | (octet[3] << 24);
  return TRUE;
}

static void ProbeFillDeadline(unsigned long timeoutMs, struct timeval *tv) {
  tv->tv_sec = (long)(timeoutMs / 1000);
  tv->tv_usec = (long)((timeoutMs % 1000) * 1000);
}

//
// Winsock loading
//
static BOOL ProbeLoadWinsock(PROBE_WINSOCK *ws) {
#define PROBE_RESOLVE(field, type, name)                \
  do {                                                  \
    ws->field = (type)GetProcAddress(ws->Module, name);  \
    if (ws->field == NULL) {                            \
      goto Fail;                                        \
    }                                                   \
  } while (0)

  memset(ws, 0, sizeof(*ws));

  ws->Module = LoadLibraryA("ws2_32.dll");
  if (ws->Module == NULL) {
    return FALSE;
  }

  PROBE_RESOLVE(Startup, PFN_WSAStartup, "WSAStartup");
  PROBE_RESOLVE(Cleanup, PFN_WSACleanup, "WSACleanup");
  PROBE_RESOLVE(Socket, PFN_socket, "socket");
  PROBE_RESOLVE(Connect, PFN_connect, "connect");
  PROBE_RESOLVE(Send, PFN_send, "send");
  PROBE_RESOLVE(Recv, PFN_recv, "recv");
  PROBE_RESOLVE(CloseSocket, PFN_closesocket, "closesocket");
  PROBE_RESOLVE(IoctlSocket, PFN_ioctlsocket, "ioctlsocket");
  PROBE_RESOLVE(Select, PFN_select, "select");
  PROBE_RESOLVE(GetSockOpt, PFN_getsockopt, "getsockopt");
  PROBE_RESOLVE(GetLastError, PFN_WSAGetLastError, "WSAGetLastError");

  return TRUE;

Fail:
  FreeLibrary(ws->Module);
  ws->Module = NULL;
  return FALSE;

#undef PROBE_RESOLVE
}

//
// Connect with a deadline.
//
// The socket is put into non-blocking mode so a filtered host cannot park this
// thread inside connect() forever; select() enforces the timeout instead, and
// SO_ERROR is queried afterwards to tell a real refusal from a timeout.
//
static BOOL ProbeConnect(const PROBE_WINSOCK *ws, SOCKET s,
                         unsigned long address, unsigned short port,
                         unsigned long timeoutMs) {
  SOCKADDR_IN addr;
  fd_set writeSet;
  struct timeval tv;
  unsigned long nonBlocking = 1;
  unsigned long optError = 0;
  int optLength = sizeof(optError);
  int rc;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = ProbeHtons(port);
  addr.sin_addr.S_un.S_addr = address;

  if (ws->IoctlSocket(s, FIONBIO, &nonBlocking) != 0) {
    LogProbeFail("ioctlsocket", (unsigned long)ws->GetLastError());
    return FALSE;
  }

  rc = ws->Connect(s, (const SOCKADDR *)&addr, sizeof(addr));
  if (rc == 0) {
    return TRUE;
  }
  if (ws->GetLastError() != WSAEWOULDBLOCK) {
    LogProbeFail("connect", (unsigned long)ws->GetLastError());
    return FALSE;
  }

  FD_ZERO(&writeSet);
  FD_SET(s, &writeSet);
  ProbeFillDeadline(timeoutMs, &tv);

  rc = ws->Select(0, NULL, &writeSet, NULL, &tv);
  if (rc == 0) {
    LogMsg("fail connect timeout");
    return FALSE;
  }
  if (rc < 0) {
    LogProbeFail("select", (unsigned long)ws->GetLastError());
    return FALSE;
  }

  if (ws->GetSockOpt(s, SOL_SOCKET, SO_ERROR, (char *)&optError,
                     &optLength) != 0) {
    LogProbeFail("getsockopt", (unsigned long)ws->GetLastError());
    return FALSE;
  }
  if (optError != 0) {
    LogProbeFail("connect", optError);
    return FALSE;
  }

  return TRUE;
}

//
// Blocking-style send and receive over the non-blocking socket: wait for the
// descriptor to be ready, attempt the call, and retry if it reports that it
// would block. The deadline is what actually bounds the wait, not the socket.
//
static BOOL ProbeSendAll(const PROBE_WINSOCK *ws, SOCKET s, const char *data,
                         int length, unsigned long timeoutMs) {
  unsigned long deadline = GetTickCount() + timeoutMs;
  int sent = 0;

  while (sent < length) {
    fd_set writeSet;
    struct timeval tv;
    unsigned long remaining = deadline - GetTickCount();
    int rc;

    if ((long)remaining <= 0) {
      LogMsg("fail send timeout");
      return FALSE;
    }

    FD_ZERO(&writeSet);
    FD_SET(s, &writeSet);
    ProbeFillDeadline(remaining, &tv);

    rc = ws->Select(0, NULL, &writeSet, NULL, &tv);
    if (rc == 0) {
      LogMsg("fail send timeout");
      return FALSE;
    }
    if (rc < 0) {
      LogProbeFail("select", (unsigned long)ws->GetLastError());
      return FALSE;
    }

    rc = ws->Send(s, data + sent, length - sent, 0);
    if (rc == SOCKET_ERROR) {
      unsigned long err = (unsigned long)ws->GetLastError();
      if (err == WSAEWOULDBLOCK) {
        continue;
      }
      LogProbeFail("send", err);
      return FALSE;
    }
    if (rc == 0) {
      LogMsg("fail send closed");
      return FALSE;
    }
    sent += rc;
  }

  return TRUE;
}

static BOOL ProbeRecvAll(const PROBE_WINSOCK *ws, SOCKET s, char *buffer,
                         int length, unsigned long timeoutMs,
                         int *received) {
  unsigned long deadline = GetTickCount() + timeoutMs;
  int total = 0;

  while (total < length) {
    fd_set readSet;
    struct timeval tv;
    unsigned long remaining = deadline - GetTickCount();
    int rc;

    if ((long)remaining <= 0) {
      LogMsg("fail receive timeout");
      return FALSE;
    }

    FD_ZERO(&readSet);
    FD_SET(s, &readSet);
    ProbeFillDeadline(remaining, &tv);

    rc = ws->Select(0, &readSet, NULL, NULL, &tv);
    if (rc == 0) {
      LogMsg("fail receive timeout");
      return FALSE;
    }
    if (rc < 0) {
      LogProbeFail("select", (unsigned long)ws->GetLastError());
      return FALSE;
    }

    rc = ws->Recv(s, buffer + total, length - total, 0);
    if (rc == SOCKET_ERROR) {
      unsigned long err = (unsigned long)ws->GetLastError();
      if (err == WSAEWOULDBLOCK) {
        continue;
      }
      LogProbeFail("recv", err);
      return FALSE;
    }
    if (rc == 0) {
      LogMsg("fail receive closed by peer");
      return FALSE;
    }
    total += rc;
  }

  *received = total;
  return TRUE;
}

//
// One full probe: connect, send PING, read the reply, compare, tear down.
//
static void ProbeOnce(void) {
  PROBE_WINSOCK ws;
  WSADATA wsaData;
  SOCKET s = INVALID_SOCKET;
  char reply[64];
  unsigned long address = 0;
  unsigned long started;
  int expectedLength = (int)sizeof(NETPROBE_EXPECTED) - 1;
  int requestLength = (int)sizeof(NETPROBE_REQUEST) - 1;
  int received = 0;

  memset(&wsaData, 0, sizeof(wsaData));

  if (!ProbeParseIpv4(NETPROBE_HOST, &address)) {
    LogMsgText("bad host literal ", NETPROBE_HOST);
    return;
  }

  if (!ProbeLoadWinsock(&ws)) {
    LogMsgCode("cannot load ws2_32", (unsigned long)GetLastError());
    return;
  }

  if (ws.Startup(MAKEWORD(2, 2), &wsaData) != 0) {
    LogProbeFail("WSAStartup", (unsigned long)ws.GetLastError());
    FreeLibrary(ws.Module);
    return;
  }

  started = GetTickCount();

  s = ws.Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    LogProbeFail("socket", (unsigned long)ws.GetLastError());
    goto Done;
  }

  if (!ProbeConnect(&ws, s, address, NETPROBE_PORT,
                    NETPROBE_CONNECT_TIMEOUT_MS)) {
    goto Done;
  }

  if (!ProbeSendAll(&ws, s, NETPROBE_REQUEST, requestLength,
                    NETPROBE_IO_TIMEOUT_MS)) {
    goto Done;
  }

  if (!ProbeRecvAll(&ws, s, reply, expectedLength, NETPROBE_IO_TIMEOUT_MS,
                    &received)) {
    goto Done;
  }

  if (memcmp(reply, NETPROBE_EXPECTED, (size_t)expectedLength) != 0) {
      LogProbeBad(reply, received);
      goto Done;
  }

  LogProbeOk("probe", GetTickCount() - started, reply, received);

Done:
  if (s != INVALID_SOCKET) {
    ws.CloseSocket(s);
  }
  ws.Cleanup();
  FreeLibrary(ws.Module);
}

//
// Worker thread
//
static HANDLE g_thread = NULL;
static HANDLE g_stopEvent = NULL;
static volatile LONG g_running = 0;

static DWORD WINAPI ProbeThread(LPVOID parameter) {
  UNREFERENCED_PARAMETER(parameter);

  LogMsgText("probing ", NETPROBE_HOST);
  LogBegin();
  LogText("every ");
  LogDec(NETPROBE_INTERVAL_MS);
  LogText("ms");
  LogFlush();

  //
  // Wait first, probe after: the interval is the gap between probes, not a delay
  // before the first one. A timeout return means the interval elapsed and the
  // stop event was not signalled, which is the signal to run.
  //
  while (WaitForSingleObject(g_stopEvent, NETPROBE_INTERVAL_MS) ==
         WAIT_TIMEOUT) {
    ProbeOnce();
  }

  LogMsg("worker exiting");
  return 0;
}

int NetProbeStart(void) {
  if (InterlockedCompareExchange(&g_running, 1, 0) != 0) {
    return 1;
  }

  LogOpenFile();

  g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_stopEvent == NULL) {
    LogMsgCode("CreateEvent failed", (unsigned long)GetLastError());
    InterlockedExchange(&g_running, 0);
    return 0;
  }

  g_thread = CreateThread(NULL, 0, ProbeThread, NULL, 0, NULL);
  if (g_thread == NULL) {
    LogMsgCode("CreateThread failed", (unsigned long)GetLastError());
    CloseHandle(g_stopEvent);
    g_stopEvent = NULL;
    InterlockedExchange(&g_running, 0);
    return 0;
  }

  //
  // The thread handle is deliberately kept. NetProbeStop needs it to know when
  // the worker has really finished, and closing it here would leave no way to
  // find out.
  //
  return 1;
}

void NetProbeStop(void) {
  HANDLE thread;
  HANDLE stopEvent;
  BOOL exited;

  if (InterlockedCompareExchange(&g_running, 0, 0) == 0) {
    return;
  }

  stopEvent = g_stopEvent;
  thread = g_thread;

  if (stopEvent != NULL) {
    SetEvent(stopEvent);
  }

  //
  // Bounded wait. DllMain may be running under the loader lock, so this cannot
  // block indefinitely. A probe already in flight unwinds on its own timeout.
  //
  exited = (thread == NULL) ||
           (WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0);

  //
  // Handles are closed only once the worker is confirmed gone. Closing the stop
  // event while the thread is still inside WaitForSingleObject on it would be a
  // use-after-close, so an unfinished worker keeps both handles until it exits.
  //
  if (exited) {
    if (thread != NULL) {
      CloseHandle(thread);
      g_thread = NULL;
    }
    if (stopEvent != NULL) {
      CloseHandle(stopEvent);
      g_stopEvent = NULL;
    }
  }

  InterlockedExchange(&g_running, 0);
  LogMsg("stopped");
  LogCloseFile();
}
