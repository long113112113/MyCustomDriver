//
// Winsock entry points are resolved at runtime instead of imported.
//
// This is deliberate. A DLL that is going to be manually mapped has its import
// table rewritten by the loader code, and every entry in it is work to get right.
// Resolving ws2_32 by hand keeps the static import table down to kernel32, which
// the target process has already mapped, and it means the probe still works in a
// process where ws2_32 was never loaded before.
//
// For the same reason nothing here calls into the CRT: no malloc, no STL.
//

#include "ProbeWinsock.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

//
// Binds one entry point, or abandons the whole table.
//
// Going through a macro keeps the NULL check in one place. The alternative -
// a chain of eleven ifs - is exactly the kind of thing that ends up missing one.
//
#define PROBE_RESOLVE(field, type, name)                     \
  do {                                                       \
    ws->field = (type)GetProcAddress(ws->Module, name);      \
    if (ws->field == NULL) {                                 \
      goto Fail;                                             \
    }                                                        \
  } while (0)

BOOL ProbeLoadWinsock(PROBE_WINSOCK *ws) {
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
  //
  // Release the module and leave the table empty, so a partially bound table is
  // never observable by a caller that only checks the return value.
  //
  FreeLibrary(ws->Module);
  memset(ws, 0, sizeof(*ws));
  return FALSE;
}

void ProbeUnloadWinsock(PROBE_WINSOCK *ws) {
  if (ws->Module != NULL) {
    FreeLibrary(ws->Module);
    ws->Module = NULL;
  }
}

#undef PROBE_RESOLVE
