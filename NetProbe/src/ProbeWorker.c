//
// The worker thread: one probe per interval, until stopped.
//

#include "NetProbe.h"
#include "ProbeLog.h"
#include "ProbeNet.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static HANDLE g_thread = NULL;
static HANDLE g_stopEvent = NULL;
static volatile LONG g_running = 0;

static DWORD WINAPI ProbeThread(LPVOID parameter) {
  UNREFERENCED_PARAMETER(parameter);

  LogMsgText("probing ", NETPROBE_HOST);
  LogProbeEvery(NETPROBE_INTERVAL_MS);

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
