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
  if (dir->VirtualAddress > nt->OptionalHeader.SizeOfImage ||
      dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress) {
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

  UNREFERENCED_PARAMETER(reason);

  dir = LdrDirectory(nt, LDR_DIR_TLS);
  if (dir == NULL || dir->VirtualAddress == 0 || dir->Size == 0) {
    return;
  }
  if (dir->VirtualAddress > nt->OptionalHeader.SizeOfImage ||
      dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress) {
    LoaderLogLine("[loader] fail TLS directory out of range", 0);
    return;
  }

  tls = (const LdrTlsDirectory64 *)LDR_AT(base, dir->VirtualAddress);

  //
  // This loader does not support TLS, and the reason is worth saying out loud
  // rather than failing quietly.
  //
  // Bringing TLS up means allocating an index from the process-wide TLS table,
  // publishing the template's raw data, and having every new thread copy and
  // zero-fill it. None of that happens here.
  //
  // The previous version of this function read the wrong field, AddressOfIndex
  // rather than AddressOfCallBacks, so it followed a small integer, failed a
  // range check against the image and returned in silence. A loader that quietly
  // skips TLS callbacks looks exactly like one that ran them, which is how a
  // payload using __declspec(thread) would have started misbehaving with nothing
  // in the log to explain it.
  //
  // Refusing here is deliberate. Running the callbacks without an index would
  // hand them a TLS variable that was never allocated, which is a crash in the
  // host rather than a gap in the payload. Announce it and let the caller decide.
  //
  // Two details to keep in mind when TLS support does land: AddressOfCallBacks is
  // a VA rather than an RVA, so relocations have already moved it onto the
  // mapped base by this point; and every entry in the array is likewise a
  // relocated VA, because the linker emits a DIR64 fixup for each slot.
  //
  if (tls->AddressOfCallBacks != 0) {
    LoaderLogLine("[loader] warn TLS directory present but unsupported", 0);
  }
}
