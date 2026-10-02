//
// Reservation, section copy, and section protection.
//

#include "LoaderPe.h"
#include "LoaderImage.h"
#include "LoaderLog.h"

#include <string.h>

BYTE *LdrMapImage(const BYTE *file, UINT32 fileSize,
                  const LdrNtHeaders *nt) {
  const LdrSectionHeader *sections;
  BYTE *base;
  UINT32 sizeOfImage = nt->OptionalHeader.SizeOfImage;
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
  // Clamped against both the image and the buffer. The image bound stops a
  // SizeOfHeaders larger than the image from running off the allocation; the
  // buffer bound stops it from reading off the end of the resource.
  //
  headers = nt->OptionalHeader.SizeOfHeaders;
  if (headers > sizeOfImage) {
    headers = sizeOfImage;
  }
  if (headers > fileSize) {
    LoaderLogHex("[loader] fail SizeOfHeaders past end of payload", headers);
    VirtualFree(base, 0, MEM_RELEASE);
    return NULL;
  }
  memcpy(base, file, headers);

  sections = LDR_SECTIONS(nt);
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    UINT32 virtualAddress = sections[i].VirtualAddress;
    UINT32 rawSize = sections[i].SizeOfRawData;
    UINT32 rawPointer = sections[i].PointerToRawData;

    //
    // A section with no file data is a .bss-style section: MEM_COMMIT already
    // zeroed it, and there is nothing to copy.
    //
    if (rawSize == 0) {
      continue;
    }

    //
    // Both bounds are written as subtractions rather than sums on purpose.
    // "virtualAddress + rawSize > sizeOfImage" overflows when the two are chosen
    // to add up to more than 2^32, wraps to a small number, and passes a check it
    // was supposed to fail. Comparing the length against what is left cannot wrap.
    //
    if (virtualAddress > sizeOfImage || rawSize > sizeOfImage - virtualAddress) {
      LoaderLogHex("[loader] fail section does not fit the image",
                   (UINT64)virtualAddress);
      VirtualFree(base, 0, MEM_RELEASE);
      return NULL;
    }

    //
    // The other half of the copy. Without this the source read runs off the end
    // of the resource, because PointerToRawData is a value from the image and the
    // image is what is being trusted.
    //
    if (rawPointer > fileSize || rawSize > fileSize - rawPointer) {
      LoaderLogHex("[loader] fail section past end of payload", (UINT64)rawPointer);
      VirtualFree(base, 0, MEM_RELEASE);
      return NULL;
    }

    memcpy(LDR_AT(base, virtualAddress), file + rawPointer, rawSize);
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
    DWORD headersOldProtect = 0;

    if (!VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY,
                        &headersOldProtect)) {
      LoaderLogLine("[loader] fail VirtualProtect on headers", 0);
      return FALSE;
    }
  }
  return TRUE;
}
