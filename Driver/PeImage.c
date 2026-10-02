#include "PeImage.h"
#include <ntddk.h>
#include <ntimage.h>

//
// ntimage.h carries the PE structures, but ntddk.h does not pull it in and the
// kernel does not use the user-mode winnt.h copies. Including it here keeps the
// reader on the same field layout the OS loader uses.
//

static BOOLEAN AsciiEquals(PCSTR Left, PCSTR Right) {
  while (*Left != '\0' && *Left == *Right) {
    Left++;
    Right++;
  }
  return (BOOLEAN)(*Left == '\0' && *Right == '\0');
}

//
// Maps an RVA to an offset inside the raw file image.
//
// RVAs below SizeOfHeaders are the headers themselves and are contiguous from
// offset zero. Everything else lives in a section, where RVA and file offset
// diverge by the section's alignment, and the mapping only holds inside the
// section's raw data - a larger VirtualSize is zero-filled at run time and has
// no file bytes to point at.
//
static BOOLEAN RvaToFileOffset(SIZE_T ImageSize,
                               _In_ const IMAGE_NT_HEADERS64 *Nt, ULONG Rva,
                               _Out_ PULONG FileOffset) {
  const IMAGE_SECTION_HEADER *sections;
  USHORT index;

  if (Rva < Nt->OptionalHeader.SizeOfHeaders) {
    if (Rva >= ImageSize)
      return FALSE;
    *FileOffset = Rva;
    return TRUE;
  }

  sections = IMAGE_FIRST_SECTION(Nt);
  for (index = 0; index < Nt->FileHeader.NumberOfSections; index++) {
    ULONG virtualAddress = sections[index].VirtualAddress;
    ULONG rawSize = sections[index].SizeOfRawData;
    ULONG rawPointer = sections[index].PointerToRawData;

    if (rawSize == 0 || Rva < virtualAddress)
      continue;
    if (Rva - virtualAddress >= rawSize)
      continue;

    //
    // Bounds written as subtraction so a raw pointer chosen to wrap cannot
    // pass the check.
    //
    if (rawPointer > ImageSize || rawSize > ImageSize - rawPointer)
      return FALSE;

    *FileOffset = rawPointer + (Rva - virtualAddress);
    return TRUE;
  }

  return FALSE;
}

NTSTATUS PeFindExportByName(const VOID *Image, SIZE_T ImageSize, PCSTR Name,
                            PPE_EXPORT_LOCATION Location) {
  const IMAGE_DOS_HEADER *dos;
  const IMAGE_NT_HEADERS64 *nt;
  const IMAGE_DATA_DIRECTORY *exportDir;
  const IMAGE_EXPORT_DIRECTORY *exports;
  ULONG exportOffset;
  ULONG namesOffset;
  ULONG ordinalsOffset;
  ULONG functionsOffset;
  const ULONG *names;
  const USHORT *ordinals;
  const ULONG *functions;
  ULONG index;

  if (Image == NULL || Name == NULL || Location == NULL)
    return STATUS_INVALID_PARAMETER;

  Location->Rva = 0;
  Location->FileOffset = 0;

  if (ImageSize < sizeof(IMAGE_DOS_HEADER))
    return STATUS_INVALID_IMAGE_FORMAT;

  dos = (const IMAGE_DOS_HEADER *)Image;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return STATUS_INVALID_IMAGE_FORMAT;

  //
  // e_lfanew is the first image-supplied value that gets dereferenced, so it is
  // bounded before use rather than after something has already read through it.
  //
  if ((ULONG)dos->e_lfanew > ImageSize ||
      sizeof(IMAGE_NT_HEADERS64) > ImageSize - (ULONG)dos->e_lfanew) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }
  nt = (const IMAGE_NT_HEADERS64 *)((const UCHAR *)Image + dos->e_lfanew);

  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return STATUS_INVALID_IMAGE_FORMAT;
  if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    return STATUS_INVALID_IMAGE_FORMAT;
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return STATUS_INVALID_IMAGE_FORMAT;

  if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
    return STATUS_NOT_FOUND;

  //
  // The section table has to fit too: RvaToFileOffset walks it, and a header
  // claiming more sections than the buffer holds would read off the end before
  // any RVA check gets a chance to fail.
  //
  {
    SIZE_T sectionTable =
        (SIZE_T)((const UCHAR *)IMAGE_FIRST_SECTION(nt) - (const UCHAR *)Image) +
        (SIZE_T)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTable > ImageSize)
      return STATUS_INVALID_IMAGE_FORMAT;
  }

  exportDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (exportDir->VirtualAddress == 0 || exportDir->Size == 0)
    return STATUS_NOT_FOUND;

  if (!RvaToFileOffset(ImageSize, nt, exportDir->VirtualAddress,
                       &exportOffset)) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }
  if ((SIZE_T)exportOffset > ImageSize ||
      sizeof(IMAGE_EXPORT_DIRECTORY) > ImageSize - exportOffset) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }
  exports = (const IMAGE_EXPORT_DIRECTORY *)((const UCHAR *)Image +
                                             exportOffset);

  if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
    return STATUS_NOT_FOUND;

  if (!RvaToFileOffset(ImageSize, nt, exports->AddressOfNames,
                       &namesOffset) ||
      !RvaToFileOffset(ImageSize, nt, exports->AddressOfNameOrdinals,
                       &ordinalsOffset) ||
      !RvaToFileOffset(ImageSize, nt, exports->AddressOfFunctions,
                       &functionsOffset)) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }

  //
  // All three arrays are sized by the count fields, so the count is what has to
  // be bounded against the buffer, not the walk.
  //
  if ((SIZE_T)exports->NumberOfNames * sizeof(ULONG) > ImageSize - namesOffset ||
      (SIZE_T)exports->NumberOfNames * sizeof(USHORT) >
          ImageSize - ordinalsOffset ||
      (SIZE_T)exports->NumberOfFunctions * sizeof(ULONG) >
          ImageSize - functionsOffset) {
    return STATUS_INVALID_IMAGE_FORMAT;
  }

  names = (const ULONG *)((const UCHAR *)Image + namesOffset);
  ordinals = (const USHORT *)((const UCHAR *)Image + ordinalsOffset);
  functions = (const ULONG *)((const UCHAR *)Image + functionsOffset);

  for (index = 0; index < exports->NumberOfNames; index++) {
    ULONG nameOffset;
    USHORT ordinal;
    ULONG functionRva;
    ULONG functionOffset;

    if (!RvaToFileOffset(ImageSize, nt, names[index], &nameOffset))
      continue;

    if (!AsciiEquals((PCSTR)((const UCHAR *)Image + nameOffset), Name))
      continue;

    ordinal = ordinals[index];
    if (ordinal >= exports->NumberOfFunctions)
      return STATUS_NOT_FOUND;

    functionRva = functions[ordinal];
    if (functionRva == 0)
      return STATUS_NOT_FOUND;

    //
    // An export whose RVA points back into the export directory is a forwarder
    // string, not code. There is nothing to jump to at that address, so it is
    // refused rather than returned as if it were a function.
    //
    if (functionRva >= exportDir->VirtualAddress &&
        functionRva - exportDir->VirtualAddress < exportDir->Size) {
      return STATUS_NOT_FOUND;
    }

    if (!RvaToFileOffset(ImageSize, nt, functionRva, &functionOffset))
      return STATUS_INVALID_IMAGE_FORMAT;

    Location->Rva = functionRva;
    Location->FileOffset = functionOffset;
    return STATUS_SUCCESS;
  }

  return STATUS_NOT_FOUND;
}