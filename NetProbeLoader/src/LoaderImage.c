//
// Reservation, section copy, and section protection.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"

#include <string.h>

BYTE *LdrMapImage(const BYTE *file, const LdrNtHeaders *nt) {
  const LdrSectionHeader *sections;
  BYTE *base;
  UINT32 headers;
  UINT32 i;

  base = (BYTE *)VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase,
                              nt->OptionalHeader.SizeOfImage,
                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (base == NULL) {
    LoaderLogHex("[loader] preferred base taken", nt->OptionalHeader.ImageBase);
    base = (BYTE *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }
  if (base == NULL) {
    return NULL;
  }

  //
  // Headers first. Everything else - the section table the copy loop walks, the
  // data directories the later stages read - is inside them.
  //
  headers = nt->OptionalHeader.SizeOfHeaders;
  if (headers > nt->OptionalHeader.SizeOfImage) {
    headers = nt->OptionalHeader.SizeOfImage;
  }
  memcpy(base, file, headers);

  sections = LDR_SECTIONS(nt);
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (sections[i].SizeOfRawData == 0) {
      continue;
    }
    if (sections[i].VirtualAddress + sections[i].SizeOfRawData >
        nt->OptionalHeader.SizeOfImage) {
      continue;
    }
    memcpy(LDR_AT(base, sections[i].VirtualAddress),
           file + sections[i].PointerToRawData, sections[i].SizeOfRawData);
  }
  return base;
}

BOOL LdrProtectSections(BYTE *base, const LdrNtHeaders *nt) {
  const LdrSectionHeader *sections = LDR_SECTIONS(nt);
  UINT32 i;

  for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    DWORD characteristics = sections[i].Characteristics;
    DWORD oldProtect = 0;
    DWORD protect;
    UINT32 size;
    int readable = (characteristics & LDR_SCN_MEM_READ) != 0;
    int writable = (characteristics & LDR_SCN_MEM_WRITE) != 0;
    int executable = (characteristics & LDR_SCN_MEM_EXECUTE) != 0;

    if (sections[i].VirtualAddress >= nt->OptionalHeader.SizeOfImage) {
      continue;
    }

    //
    // Derive the protection from the flags the linker actually set, instead of
    // handing everything executable a read-write page.
    //
    // PAGE_EXECUTE_READWRITE is not a safe default for code: it is what an
    // exploit looks like, so a process under Exploit Protection or any EDR that
    // watches for writable-executable memory now flags the payload's .text, and
    // a writable code section is also the one an attacker wants to patch. .text
    // is EXECUTE|READ and needs nothing more than PAGE_EXECUTE_READ.
    //
    // WRITE|EXECUTE together genuinely do need RWX - some images merge writable
    // data into the code section - so that combination is honoured rather than
    // silently downgraded to something the image cannot live with.
    //
    if (executable && writable) {
      protect = PAGE_EXECUTE_READWRITE;
    } else if (executable) {
      protect = readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    } else if (writable) {
      protect = PAGE_READWRITE;
    } else if (readable) {
      protect = PAGE_READONLY;
    } else {
      continue;
    }

    size = sections[i].VirtualSize;
    if (size == 0) {
      size = sections[i].SizeOfRawData;
    }
    if (size == 0) {
      continue;
    }

    if (!VirtualProtect(LDR_AT(base, sections[i].VirtualAddress), size, protect,
                        &oldProtect)) {
      LoaderLogHex("[loader] fail VirtualProtect",
                   (UINT64)sections[i].VirtualAddress);
      return FALSE;
    }
  }

  //
  // The headers are copied but never written again once imports are bound, and
  // leaving them writable costs an easy overwrite target for anything that walks
  // the image. Read-only is enough: the loader keeps reading them from its own
  // copy of the file, not from here.
  //
  if (nt->OptionalHeader.SizeOfHeaders > 0) {
    if (!VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY,
                        &oldProtect)) {
      LoaderLogLine("[loader] fail VirtualProtect on headers", 0);
      return FALSE;
    }
  }
  return TRUE;
}
