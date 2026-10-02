#ifndef NETPROBE_PROBEWINSOCK_H
#define NETPROBE_PROBEWINSOCK_H

//
// Winsock entry points are resolved at runtime instead of imported.
//
// This is deliberate. A DLL that gets manually mapped has its import table
// rewritten by the loader, and every entry in it is work to get right.
// Resolving ws2_32 by hand keeps the static import table down to kernel32, which
// the host process has already mapped, and it means the probe still works in a
// process where ws2_32 was never loaded before.
//
// For the same reason nothing here calls into the CRT: no malloc, no STL.
//

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

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
// Loads ws2_32 and binds the table above. On any failure the module is released
// and the table left empty, so a partial table is never observable.
//
BOOL ProbeLoadWinsock(PROBE_WINSOCK *ws);

//
// Releases a table from ProbeLoadWinsock. Safe on an already-released table.
//
void ProbeUnloadWinsock(PROBE_WINSOCK *ws);

#ifdef __cplusplus
}
#endif

#endif
