//
// One probe: connect, send PING, read the reply, compare, tear down.
//
// The socket is non-blocking and every wait goes through select(), so a filtered
// or silent host costs a bounded amount of time rather than parking the worker
// thread inside connect() or recv() forever.
//

#include "NetProbe.h"
#include "ProbeNet.h"
#include "ProbeLog.h"
#include "ProbeWinsock.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string.h>

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
// Connect with a deadline.
//
// FIONBIO turns the blocking call into a WSAEWOULDBLOCK report, select() enforces
// the timeout, and SO_ERROR afterwards tells a real refusal from a timeout.
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

void ProbeOnce(void) {
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
    ProbeUnloadWinsock(&ws);
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
  ProbeUnloadWinsock(&ws);
}
