//
// Import table binding.
//
// Two PE details drive the shape of this file:
//
//  1. A thunk entry is either an ordinal, or an RVA to an IMAGE_IMPORT_BY_NAME.
//     That struct is { WORD Hint; CHAR Name[]; } - the RVA points at the HINT,
//     not at the name. GetProcAddress needs the name, so the read has to start
//     two bytes in. Handing it the struct base passes a string starting with the
//     hint, and on a little-endian image that is a visible junk byte in front of
//     the real name: hint 0x0142 looks like "B\x01DisableThreadLibraryCalls".
//     Nothing about the symbol is wrong, only the pointer, so the failure
//     presents as "GetProcAddress cannot find a function that plainly exists".
//
//  2. Both the descriptor list and the thunk list are walked until a zero
//     field, not until a count, so they have to be bounded by the directory size.
//     An unbounded walk trusts whatever the mapped bytes happen to be, which on
//     a malformed or half-copied image means reading and writing far outside it.
//
// Symbol lookup goes through GetProcAddress rather than a hand-written walk of
// the export directory. GetProcAddress is the right tool here because this is a
// real DLL with kernel32 already mapped, and it already knows how to follow
// forwarder chains - which on Windows 10/11 is most of kernel32's exports. A
// loader that stopped at the raw export slot would bind a string literal as
// though it were a function pointer and die on the first call.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"

//
// Binds one module's thunks.
//
// lookup and address are the INT and the IAT. They are normally different
// arrays, and they are the same array in an unbound image that only has one
// thunk table - which is why the lookup table falls back to FirstThunk.
//
static BOOL LdrBindModule(BYTE *base, UINT32 sizeOfImage,
                          const LdrImportDescriptor *desc) {
  const UINT64 *lookup;
  UINT64 *address;
  const char *moduleName;
  HMODULE module;
  UINT32 thunkRva;
  UINT32 iatRva;
  UINT32 bytesLeft;
  UINT32 offset;
  int byOrdinal;

  moduleName = (const char *)LDR_AT(base, desc->Name);
  module = (HMODULE)LoadLibraryA(moduleName);
  if (module == NULL) {
    LOADER_TRACE_NAME(moduleName);
    LoaderLogHex("[loader] fail LoadLibrary rva", (UINT64)desc->Name);
    return FALSE;
  }

  thunkRva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk
                                           : desc->FirstThunk;
  iatRva = desc->FirstThunk;
  if (thunkRva == 0 || thunkRva + sizeof(UINT64) > sizeOfImage ||
      iatRva == 0 || iatRva + sizeof(UINT64) > sizeOfImage) {
    LoaderLogHex("[loader] fail thunk table out of range", thunkRva);
    return FALSE;
  }
  bytesLeft = sizeOfImage - thunkRva;

  //
  // lookup is the INT (read-only: it holds the import names the linker wrote),
  // address is the IAT. Only the IAT is written. Overwriting the INT instead
  // leaves the IAT holding the RVAs the linker put there, and the payload then
  // calls through them as though they were function pointers - an access
  // violation at an address that looks like a plausible RVA, in the middle of
  // the image's own .idata.
  //
  lookup = (const UINT64 *)LDR_AT(base, thunkRva);
  address = (UINT64 *)LDR_AT(base, iatRva);

  for (offset = 0; offset + sizeof(UINT64) <= bytesLeft;
       offset += (UINT32)sizeof(UINT64)) {
    FARPROC resolved;
    UINT64 target = lookup[offset / sizeof(UINT64)];

    //
    // Both runs stop at the same place: an empty name is indistinguishable from
    // running off the mapped image, and only one of them is a real terminator.
    //
    if (target == 0) {
      break;
    }

    byOrdinal = (target & LDR_ORDINAL_FLAG) != 0;
    if (byOrdinal) {
      resolved = GetProcAddress(module, (LPSTR)(target & 0xFFFF));
      if (resolved == NULL) {
        LoaderLogHex("[loader] fail import ordinal in",
                     (UINT64)(UINT_PTR)moduleName);
        LoaderLogHex("[loader] fail import ordinal", target & 0xFFFF);
        return FALSE;
      }
    } else {
      const LdrImportByName *byName =
          (const LdrImportByName *)LDR_AT(base, target & 0x7FFFFFFF);
      //
      // byName->Name, not (char *)byName: the hint is part of the record and is
      // not part of the string.
      //
      resolved = GetProcAddress(module, byName->Name);
      if (resolved == NULL) {
        LoaderLogHex("[loader] fail import name in",
                     (UINT64)(UINT_PTR)moduleName);
        LOADER_TRACE_NAME(byName->Name);
        LoaderLogHex("[loader] fail import name rva", target & 0x7FFFFFFF);
        return FALSE;
      }
    }

    address[offset / sizeof(UINT64)] = (UINT64)(UINT_PTR)resolved;
  }
  return TRUE;
}

BOOL LdrResolveImports(BYTE *base, const LdrNtHeaders *nt) {
  const LdrDataDirectory *dir;
  const LdrImportDescriptor *desc;
  const BYTE *end;
  UINT32 sizeOfImage = nt->OptionalHeader.SizeOfImage;

  dir = LdrDirectory(nt, LDR_DIR_IMPORT);
  if (dir == NULL || dir->VirtualAddress == 0 || dir->Size == 0) {
    LoaderLogLine("[loader] no imports to bind", 0);
    return TRUE;
  }

  desc = (const LdrImportDescriptor *)LDR_AT(base, dir->VirtualAddress);
  end = (const BYTE *)desc + dir->Size;

  //
  // The directory covers at least the descriptors plus a terminating all-zero
  // one, which is what makes Name == 0 a safe loop condition here.
  //
  while ((const BYTE *)desc + sizeof(LdrImportDescriptor) <= end) {
    if (desc->Name == 0) {
      break;
    }
    if (!LdrBindModule(base, sizeOfImage, desc)) {
      return FALSE;
    }
    desc++;
  }
  return TRUE;
}
