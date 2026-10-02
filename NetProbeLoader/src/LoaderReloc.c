//
// Base relocation.
//
// A .reloc block is a page RVA, a block size, then a run of 16-bit entries whose
// top 4 bits are the fixup type and whose low 12 bits are an offset into that
// page. Blocks are padded to 4 bytes and the last entry in a block is normally
// ABSOLUTE, so walking means following SizeOfBlock rather than searching for
// terminators.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"

BOOL LdrApplyRelocations(BYTE *base, const LdrNtHeaders *nt, UINT64 delta) {
  const LdrDataDirectory *dir;
  const BYTE *block;
  const BYTE *end;

  //
  // Landing on the preferred base means every absolute value in the image is
  // already correct. This is the common case, not an error.
  //
  if (delta == 0) {
    LoaderLogLine("[loader] relocation not needed, delta is zero", 0);
    return TRUE;
  }

  dir = LdrDirectory(nt, LDR_DIR_BASERELOC);
  if (dir == NULL || dir->VirtualAddress == 0 || dir->Size == 0) {
    LoaderLogLine("[loader] fail no relocation directory", 0);
    return FALSE;
  }

  block = (const BYTE *)LDR_AT(base, dir->VirtualAddress);
  end = block + dir->Size;

  while (block + sizeof(LdrBaseRelocation) <= end) {
    const LdrBaseRelocation *entry = (const LdrBaseRelocation *)block;
    const BYTE *item;
    const BYTE *blockEnd;

    //
    // A block that claims to be smaller than its own header, or that runs past
    // the directory, ends the walk. Continuing would read arbitrary bytes as
    // fixup entries and write through whatever addresses they decode to.
    //
    if (entry->SizeOfBlock < sizeof(LdrBaseRelocation)) {
      break;
    }
    blockEnd = block + entry->SizeOfBlock;
    if (blockEnd > end) {
      break;
    }

    item = block + sizeof(LdrBaseRelocation);
    while (item + sizeof(UINT16) <= blockEnd) {
      UINT16 packed = *(const UINT16 *)item;
      UINT16 type = (UINT16)(packed >> 12);
      UINT32 target;

      item += sizeof(UINT16);

      //
      // ABSOLUTE is padding and carries no fixup.
      //
      if (type == LDR_REL_ABSOLUTE) {
        continue;
      }
      if (type != LDR_REL_DIR64) {
        LoaderLogLine("[loader] fail unsupported relocation type", type);
        return FALSE;
      }

      target = entry->VirtualAddress + (UINT32)(packed & 0x0FFF);
      if ((UINT64)target + sizeof(UINT64) > nt->OptionalHeader.SizeOfImage) {
        LoaderLogLine("[loader] fail relocation target out of range", target);
        return FALSE;
      }
      *(UINT64 *)LDR_AT(base, target) += delta;
    }

    block = blockEnd;
  }
  return TRUE;
}
