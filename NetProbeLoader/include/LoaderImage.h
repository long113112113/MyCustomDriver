#ifndef NETPROBELOADER_LOADERIMAGE_H
#define NETPROBELOADER_LOADERIMAGE_H

//
// The stages that take a raw file image to a running one, in the order
// ReflectiveLoad runs them:
//
//   LdrMapImage        reserve memory and copy headers + sections
//   LdrApplyRelocations  fix up absolute addresses if it did not land at its
//                        preferred base
//   LdrResolveImports  bind the IAT
//   LdrProtectSections apply section protections
//   LdrRegisterUnwind  register .pdata so x64 exceptions inside the payload
//                      unwind inside the payload
//   LdrInvokeTls       run TLS callbacks, if any
//
// Splitting these out keeps each one answerable on its own: when a map fails,
// the question is always which stage returned FALSE.
//

#include "LoaderPe.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Copies headers and sections into freshly reserved memory.
//
// The preferred base is tried first so an image linked at its own ImageBase
// needs no relocation fixups at all; the attempt is abandoned if that address is
// already taken. Anywhere is fine otherwise, because the relocation pass exists
// exactly so the image does not care where it landed.
//
// Returns NULL only when both allocation attempts fail.
//
BYTE *LdrMapImage(const BYTE *file, const LdrNtHeaders *nt);

//
// Applies IMAGE_REL_BASED_DIR64 fixups for a base that differs from ImageBase.
// A zero delta is a success, not a no-op failure: it means the image landed
// exactly where it wanted to be.
//
BOOL LdrApplyRelocations(BYTE *base, const LdrNtHeaders *nt, UINT64 delta);

//
// Binds the import table by hand, writing resolved addresses into the IAT.
//
BOOL LdrResolveImports(BYTE *base, const LdrNtHeaders *nt);

//
// Applies a protection per section characteristic. Runs after imports, because
// .idata has to stay writable until the last thunk is bound.
//
BOOL LdrProtectSections(BYTE *base, const LdrNtHeaders *nt);

//
// Registers the payload's x64 unwind table with the OS.
//
// Without this, any exception or unwind inside the payload walks off into the
// host process. Best effort: a refusal is logged and the load continues,
// because an image without exceptions still runs.
//
void LdrRegisterUnwind(BYTE *base, const LdrNtHeaders *nt);

//
// Runs the payload's TLS callbacks for one reason code.
//
void LdrInvokeTls(BYTE *base, const LdrNtHeaders *nt, DWORD reason);

#ifdef __cplusplus
}
#endif

#endif
