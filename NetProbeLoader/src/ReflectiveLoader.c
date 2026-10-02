//
// Reflective self-loader: orchestration.
//
// Maps an embedded PE image out of this DLL's own RCDATA into the current
// process without ever handing it to the Windows loader. The stages themselves
// live next door; this file decides the order, owns the checks that guard them,
// and is the only place the payload's entry point is called.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"
#include "LoaderSelf.h"

HMODULE g_ownModule;

__declspec(dllexport) BYTE *WINAPI ReflectiveLoad(void);

//
// Locates and validates the embedded payload.
//
// Everything here reads the payload out of our own resource, so a failure means
// the file on disk is not what this loader expects rather than the mapped image
// being wrong.
//
// The header is a pointer into the resource, so the file base has to come back
// too: the copy stage reads sections as file offsets from it.
//
static LdrNtHeaders *LdrOpenPayload(const BYTE **fileBase, UINT32 *fileSizeOut) {
  HRSRC resource;
  HGLOBAL loaded;
  const BYTE *file;
  DWORD fileSize;
  LdrNtHeaders *nt;

  if (g_ownModule == NULL) {
    //
    // GetModuleHandleExA with FROM_ADDRESS, naming an address inside this loader,
    // is the correct way to get the handle FindResourceA needs. The previous
    // GetModuleHandleA(NULL) does not do this: with a NULL name it returns the
    // handle of the host executable, not the DLL the resource lives in. That
    // happened to be harmless only because DllMain assigns g_ownModule before
    // ReflectiveLoad ever runs, so the fallback was never reached in practice -
    // it was simply the wrong answer waiting for the first caller that arrives
    // before DllMain, or a build where it is not.
    //
    // UNCHANGED_REFCOUNT keeps this from balancing the loader's own entry, which
    // would undo the refcount the caller is about to drop with FreeLibrary.
    //
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(UINT_PTR)&ReflectiveLoad, &g_ownModule)) {
      LoaderLogLine("[loader] fail no own module handle",
                    (UINT64)GetLastError());
      return NULL;
    }
  }

  resource = FindResourceA(g_ownModule, LDR_PAYLOAD_RESOURCE_ID, LDR_RT_RCDATA);
  if (resource == NULL) {
    LoaderLogLine("[loader] fail RCDATA resource not found",
                  (UINT64)GetLastError());
    return NULL;
  }
  loaded = LoadResource(g_ownModule, resource);
  if (loaded == NULL) {
    LoaderLogLine("[loader] fail LoadResource", (UINT64)GetLastError());
    return NULL;
  }

  file = (const BYTE *)LockResource(loaded);
  fileSize = (DWORD)SizeofResource(g_ownModule, resource);
  if (file == NULL || fileSize < sizeof(IMAGE_DOS_HEADER)) {
    LoaderLogLine("[loader] fail payload truncated", fileSize);
    return NULL;
  }
  if (file[0] != 'M' || file[1] != 'Z') {
    LoaderLogLine("[loader] fail payload has no MZ header", fileSize);
    return NULL;
  }

  //
  // e_lfanew is the one field read before the header layout is known, and it is
  // the field an attacker would point at a mapped file to make the checks below
  // read somewhere else entirely. Bounding it is what makes those checks mean
  // anything.
  //
  {
    UINT32 lfanew = *(const UINT32 *)(const void *)(file + 0x3C);

    if (lfanew + sizeof(LdrNtHeaders) > fileSize) {
      LoaderLogHex("[loader] fail e_lfanew past end of payload", lfanew);
      return NULL;
    }
    nt = (LdrNtHeaders *)(void *)(file + lfanew);
  }

  if (nt->Signature != 0x4550) { /* 'PE' */
    LoaderLogHex("[loader] fail bad PE signature", nt->Signature);
    return NULL;
  }
  if (nt->FileHeader.Machine != LDR_MACHINE_AMD64) {
    LoaderLogHex("[loader] fail machine is not AMD64", nt->FileHeader.Machine);
    return NULL;
  }
  if (nt->OptionalHeader.Magic != LDR_MAGIC_PE32_PLUS) {
    LoaderLogHex("[loader] fail optional header is not PE32+",
                 nt->OptionalHeader.Magic);
    return NULL;
  }
  if (nt->OptionalHeader.SizeOfImage == 0) {
    LoaderLogLine("[loader] fail image size is zero", 0);
    return NULL;
  }

  LoaderLogLine("[loader] payload accepted, size of image",
                nt->OptionalHeader.SizeOfImage);
  *fileBase = file;
  *fileSizeOut = fileSize;
  return nt;
}

__declspec(dllexport) BYTE *WINAPI ReflectiveLoad(void) {
  const BYTE *file;
  UINT32 fileSize;
  LdrNtHeaders *nt;
  BYTE *base;
  UINT64 delta;
  LdrDllMain entry;

  nt = LdrOpenPayload(&file, &fileSize);
  if (nt == NULL) {
    return NULL;
  }

  base = LdrMapImage(file, fileSize, nt);
  if (base == NULL) {
    LoaderLogLine("[loader] fail VirtualAlloc for image", 0);
    return NULL;
  }
  LoaderLogHex("[loader] mapped at", (UINT64)(UINT_PTR)base);

  //
  // Every failure past this point unwinds through Fail. Without it each early
  // return leaked the whole SizeOfImage reservation, which for a caller that
  // retries in a loop is a reliable way to exhaust the address space - and it
  // leaked an image whose imports were half bound and whose entry point had
  // never run, so nothing else would ever reclaim it either.
  //
  delta = (UINT64)(UINT_PTR)base - nt->OptionalHeader.ImageBase;
  if (!LdrApplyRelocations(base, nt, delta)) {
    LoaderLogHex("[loader] fail relocation stage, delta", (UINT64)(LONG)delta);
    goto Fail;
  }
  if (!LdrResolveImports(base, nt)) {
    goto Fail;
  }
  //
  // Protections go on last: relocations and imports both write into the image,
  // so anything made read-only first would fault the next stage.
  //
  if (!LdrProtectSections(base, nt)) {
    goto Fail;
  }
  LdrRegisterUnwind(base, nt);
  LdrInvokeTls(base, nt, DLL_PROCESS_ATTACH);

  entry = (LdrDllMain)LDR_AT(base, nt->OptionalHeader.AddressOfEntryPoint);
  if (entry == NULL) {
    LoaderLogLine("[loader] fail entry point is null", 0);
    goto Fail;
  }

  //
  // Relocations have just rewritten the immediate operands of the payload's
  // code, so the instruction stream changed after those bytes were written.
  // FlushInstructionCache is what tells the CPU to discard anything it had
  // already fetched for the old bytes.
  //
  // Worth being precise about the reason, because the usual justification
  // oversells it. x86-64 keeps caches coherent and has cross-modifying-code
  // detection, so the CPU does not silently execute a mixture of old and new
  // instructions the way it would on a looser architecture. What the API
  // actually buys is ordering and portability: it is the documented way to
  // publish code you have just written, and it costs one serializing instruction
  // over a range nobody is about to re-fetch in a hot loop.
  //
  FlushInstructionCache(GetCurrentProcess(), base,
                        nt->OptionalHeader.SizeOfImage);

  LoaderLogLine("[loader] calling payload entry point", 0);
  if (!entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL)) {
    LoaderLogLine("[loader] fail payload entry point returned FALSE", 0);
    goto Fail;
  }
  LoaderLogLine("[loader] payload is live", 0);
  return base;

Fail:
  //
  // MEM_RELEASE hands the whole reservation back at once and takes care of the
  // individual sections; the size argument is ignored for it and must be zero.
  //
  VirtualFree(base, 0, MEM_RELEASE);
  return NULL;
}

__declspec(dllexport) void WINAPI ReflectiveUnload(void) {
  LoaderLogLine("[loader] unload is not implemented", 0);
}
