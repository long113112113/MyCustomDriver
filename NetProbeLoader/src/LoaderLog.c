//
// Loader diagnostics.
//
// Formatting is done by hand into stack buffers: the loader must not depend on
// the CRT, because the whole point is bringing an image up without CRT startup.
//

#include "LoaderLog.h"

#ifdef NETPROBE_LOADER_TRACE

#include <stdio.h>

static FILE *g_trace;

void LoaderTraceOpen(void) {
  char path[MAX_PATH];
  DWORD length;

  if (g_trace != NULL) {
    return;
  }
  length = GetTempPathA(MAX_PATH, path);
  if (length == 0 || length >= MAX_PATH) {
    return;
  }
  lstrcatA(path, "NetProbeLoader.log");
  g_trace = fopen(path, "a");
}

static void LoaderTraceWrite(const char *text) {
  if (g_trace != NULL) {
    fputs(text, g_trace);
    fflush(g_trace);
  }
}

void LoaderTraceName(const char *text) {
  char line[160];
  int i = 0;

  line[i++] = '[';
  while (text[i - 1] != '\0' && i < 140) {
    line[i] = text[i - 1];
    i++;
  }
  line[i++] = ']';
  line[i++] = '\r';
  line[i++] = '\n';
  line[i] = '\0';
  LoaderTraceWrite(line);
}

#else

void LoaderTraceOpen(void) {}

//
// Trace-only output has nowhere to go, so it disappears in Release.
//
#define LoaderTraceWrite(text) ((void)0)

#endif

//
// "message <decimal>" and "message 0x<hex>".
//
// Both build the whole line in one buffer and emit it once, so a debug reader
// attached to the host sees the same atomic line the trace file records.
//
void LoaderLogLine(const char *message, UINT64 value) {
  char buffer[192];
  char digits[24];
  int count = 0;
  int i = 0;

  if (value == 0) {
    digits[count++] = '0';
  }
  while (value != 0 && count < 24) {
    digits[count++] = (char)('0' + (value % 10));
    value /= 10;
  }

  //
  // Assigned in two statements rather than "buffer[i++] = message[i]". Written the
  // short way, the side effect of i++ is unsequenced against the value computation
  // of i in message[i], which leaves the program with undefined behaviour no matter
  // that every compiler in use happens to evaluate them the convenient way.
  //
  while (message[i] != '\0' && i < 120) {
    buffer[i] = message[i];
    i++;
  }
  buffer[i++] = ' ';
  while (count > 0 && i < 170) {
    buffer[i++] = digits[--count];
  }
  buffer[i++] = '\r';
  buffer[i++] = '\n';
  buffer[i] = '\0';

  OutputDebugStringA(buffer);
  LoaderTraceWrite(buffer);
}

void LoaderLogHex(const char *message, UINT64 value) {
  static const char kHex[] = "0123456789ABCDEF";
  char buffer[192];
  char digits[24];
  int count = 0;
  int i = 0;

  if (value == 0) {
    digits[count++] = '0';
  }
  while (value != 0 && count < 24) {
    digits[count++] = kHex[value & 0xF];
    value >>= 4;
  }

  while (message[i] != '\0' && i < 120) {
    buffer[i] = message[i];
    i++;
  }
  buffer[i++] = ' ';
  buffer[i++] = '0';
  buffer[i++] = 'x';
  //
  // digits holds characters, not indexes into kHex - the conversion already
  // happened when the digits were collected. Indexing kHex with them a second
  // time reads past the end of it and prints a stray byte instead of the number.
  //
  while (count > 0 && i < 175) {
    buffer[i++] = digits[--count];
  }
  buffer[i++] = '\r';
  buffer[i++] = '\n';
  buffer[i] = '\0';

  OutputDebugStringA(buffer);
  LoaderTraceWrite(buffer);
}
