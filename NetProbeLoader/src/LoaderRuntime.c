//
// Runtime services a mapped image needs: x64 unwind registration and TLS
// callbacks. Both are things the Windows loader does on a normal LoadLibrary and
// both are absent for an image nobody told the loader about.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"

static HMODULE g_ntdll;

void LdrRegisterUnwind(BYTE *base, const LdrNtHeaders *nt) {
  const LdrDataDirectory *dir;
  LdrRtlAddFunctionTable registerTable;
  ULONG entries;

  dir = LdrDirectory(nt, LDR_DIR_EXCEPTION);
  if (dir == NULL || dir->VirtualAddress == 0 || dir->Size == 0) {
    return;
  }
  if (dir->VirtualAddress + dir->Size > nt->OptionalHeader.SizeOfImage) {
    LoaderLogLine("[loader] fail unwind directory out of range", 0);
    return;
  }

  if (g_ntdll == NULL) {
    g_ntdll = (HMODULE)GetModuleHandleA("ntdll.dll");
    if (g_ntdll == NULL) {
      return;
    }
  }
  registerTable =
      (LdrRtlAddFunctionTable)(UINT_PTR)GetProcAddress(g_ntdll,
                                                      "RtlAddFunctionTable");
  if (registerTable == NULL) {
    LoaderLogLine("[loader] warn RtlAddFunctionTable unavailable", 0);
    return;
  }

  entries = dir->Size / (ULONG)sizeof(LdrRuntimeFunction);
  if (entries == 0) {
    return;
  }

  //
  // The third argument is the image base that the function table's RVAs are
  // relative to. There is no out parameter and no status: the result is TRUE when
  // the table was accepted.
  //
  if (registerTable((PRUNTIME_FUNCTION)LDR_AT(base, dir->VirtualAddress),
                    entries, (DWORD64)(UINT_PTR)base)) {
    LoaderLogLine("[loader] registered unwind entries", entries);
  } else {
    //
    // Not fatal: an image with no registered unwind data still runs, it just
    // cannot unwind an exception across its own frames.
    //
    LoaderLogLine("[loader] warn unwind registration refused", entries);
  }
}

void LdrInvokeTls(BYTE *base, const LdrNtHeaders *nt, DWORD reason) {
  const LdrDataDirectory *dir;
  const LdrTlsDirectory64 *tls;
  const UINT64 *callbacks;

  dir = LdrDirectory(nt, LDR_DIR_TLS);
  if (dir == NULL || dir->VirtualAddress == 0 || dir->Size == 0) {
    return;
  }
  if (dir->VirtualAddress + dir->Size > nt->OptionalHeader.SizeOfImage) {
    LoaderLogLine("[loader] fail TLS directory out of range", 0);
    return;
  }

  tls = (const LdrTlsDirectory64 *)LDR_AT(base, dir->VirtualAddress);

  //
  // AddressOfCallbacks is a VA, not an RVA, so by this point relocations have
  // already moved it onto the mapped base. Using it as an RVA would jump
  // somewhere unrelated whenever the image did not land at its preferred base.
  //
  if (tls->AddressOfCallbacks == 0) {
    return;
  }
  if (tls->AddressOfCallbacks < (UINT64)(UINT_PTR)base ||
      tls->AddressOfCallbacks >= (UINT64)(UINT_PTR)base +
                                      nt->OptionalHeader.SizeOfImage) {
    LoaderLogLine("[loader] fail TLS callbacks outside image", 0);
    return;
  }

  callbacks = (const UINT64 *)(UINT_PTR)tls->AddressOfCallbacks;
  while (*callbacks != 0) {
    LdrDllMain callback = (LdrDllMain)(UINT_PTR)*callbacks;
    if (callback != NULL) {
      callback((HINSTANCE)base, reason, NULL);
    }
    callbacks++;
  }
}
