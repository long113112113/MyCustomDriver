#ifndef NETPROBELOADER_LOADERPE_H
#define NETPROBELOADER_LOADERPE_H

//
// PE32+ structures and the loader's own constants.
//
// These are declared locally rather than taken from winternl.h. Those structs
// move between SDK versions, and the one thing this loader cannot afford is
// disagreeing with the real loader about an offset. Every field here is fixed
// by the PE/COFF specification, so the risk is drift against a header nobody
// controls, not drift against the format.
//

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define LDR_MACHINE_AMD64 0x8664
#define LDR_MAGIC_PE32_PLUS 0x020B

#define LDR_DIR_IMPORT 1
#define LDR_DIR_EXCEPTION 3
#define LDR_DIR_BASERELOC 5
#define LDR_DIR_TLS 9

#define LDR_REL_ABSOLUTE 0
#define LDR_REL_DIR64 10

//
// When set in the high bit of a thunk, the remaining bits are an ordinal.
//
#define LDR_ORDINAL_FLAG 0x8000000000000000ULL

//
// Section characteristics used when picking a protection.
//
#define LDR_SCN_MEM_EXECUTE 0x20000000
#define LDR_SCN_MEM_READ 0x40000000
#define LDR_SCN_MEM_WRITE 0x80000000

//
// RT_RCDATA is itself a MAKEINTRESOURCE, which widens to LPWSTR under some SDK
// configurations and then fails to match FindResourceA's LPCSTR parameter.
// Spelling the value out is what keeps the build warning-free.
//
#define LDR_RT_RCDATA ((LPCSTR)(UINT_PTR)10)
#define LDR_PAYLOAD_RESOURCE_ID ((LPCSTR)(UINT_PTR)1)

typedef struct {
  UINT16 Machine;
  UINT8 NumberOfSections;
  UINT32 TimeDateStamp;
  UINT32 PointerToSymbolTable;
  UINT32 NumberOfSymbols;
  UINT16 SizeOfOptionalHeader;
  UINT16 Characteristics;
} LdrFileHeader;

typedef struct {
  UINT32 VirtualAddress;
  UINT32 Size;
} LdrDataDirectory;

typedef struct {
  UINT16 Magic;
  UINT8 MajorLinkerVersion;
  UINT8 MinorLinkerVersion;
  UINT32 SizeOfCode;
  UINT32 SizeOfInitializedData;
  UINT32 SizeOfUninitializedData;
  UINT32 AddressOfEntryPoint;
  UINT32 BaseOfCode;
  UINT64 ImageBase;
  UINT32 SectionAlignment;
  UINT32 FileAlignment;
  UINT16 MajorOperatingSystemVersion;
  UINT16 MinorOperatingSystemVersion;
  UINT16 MajorImageVersion;
  UINT16 MinorImageVersion;
  UINT16 MajorSubsystemVersion;
  UINT16 MinorSubsystemVersion;
  UINT32 Win32VersionValue;
  UINT32 SizeOfImage;
  UINT32 SizeOfHeaders;
  UINT32 CheckSum;
  UINT16 Subsystem;
  UINT16 DllCharacteristics;
  UINT64 SizeOfStackReserve;
  UINT64 SizeOfStackCommit;
  UINT64 SizeOfHeapReserve;
  UINT64 SizeOfHeapCommit;
  UINT32 LoaderFlags;
  UINT32 NumberOfRvaAndSizes;
  //
  // The count is a field, not a constant, so the array has to be sized for the
  // full 16 entries the spec allows even though a given image may declare
  // fewer. Dropping this array is what silently shifts every RVA lookup below.
  //
  LdrDataDirectory DataDirectory[16];
} LdrOptionalHeader;

typedef struct {
  UINT32 Signature;
  LdrFileHeader FileHeader;
  LdrOptionalHeader OptionalHeader;
} LdrNtHeaders;

typedef struct {
  UINT8 Name[8];
  UINT32 VirtualSize;
  UINT32 VirtualAddress;
  UINT32 SizeOfRawData;
  UINT32 PointerToRawData;
  UINT32 PointerToRelocations;
  UINT32 PointerToLinenumbers;
  UINT16 NumberOfRelocations;
  UINT16 NumberOfLinenumbers;
  UINT32 Characteristics;
} LdrSectionHeader;

typedef struct {
  UINT32 OriginalFirstThunk;
  UINT32 TimeDateStamp;
  UINT32 ForwarderChain;
  UINT32 Name;
  UINT32 FirstThunk;
} LdrImportDescriptor;

//
// The table an IMAGE_IMPORT_BY_NAME points at. Hint is the index the linker
// guessed for the symbol; it is advisory and the loader ignores it, but it is
// still part of the record, which is why skipping it matters (see LoaderImport.c).
//
typedef struct {
  UINT16 Hint;
  CHAR Name[1];
} LdrImportByName;

typedef struct {
  UINT64 AddressOfData;
  UINT64 AddressOfIndex;
  UINT64 AddressOfCallbacks;
  UINT32 SizeOfZeroFill;
  UINT32 Characteristics;
} LdrTlsDirectory64;

typedef struct {
  UINT32 BeginAddress;
  UINT32 EndAddress;
  UINT32 UnwindInfoAddress;
} LdrRuntimeFunction;

typedef struct {
  UINT32 VirtualAddress;
  UINT32 SizeOfBlock;
} LdrBaseRelocation;

typedef BOOL(WINAPI *LdrDllMain)(HINSTANCE, DWORD, LPVOID);

//
// RtlAddFunctionTable as declared in winnt.h for _AMD64_ (identical for ARM and
// ARM64): three parameters, __cdecl, and a BOOLEAN where TRUE means the table was
// accepted. There is no handle out parameter and no NTSTATUS, so treating the
// result as a status inverts it - a successful registration returns 1 and reads
// as a failure.
//
// Note that a four-argument call still lands the right values in RCX/RDX/R8 on
// x64, because Windows x64 has a single calling convention and ignores the
// __cdecl/__stdcall distinction. That is why a wrong prototype can appear to work
// and then report success as failure.
//
typedef BOOLEAN(__cdecl *LdrRtlAddFunctionTable)(PRUNTIME_FUNCTION,
                                                  DWORD, DWORD64);

//
// A mapped image is addressed by base + RVA everywhere below, so one helper
// keeps that arithmetic in a single place.
//
#define LDR_AT(base, rva) ((void *)((BYTE *)(base) + (UINT32)(rva)))

//
// The first section header sits immediately after the optional header, whose
// length is variable.
//
#define LDR_SECTIONS(nt)                                                       \
  ((const LdrSectionHeader *)((const BYTE *)(nt) + sizeof(UINT32) +           \
                              sizeof(LdrFileHeader) +                          \
                              (nt)->FileHeader.SizeOfOptionalHeader))

//
// Returns the directory entry at an index, or NULL when the image declares
// fewer directories than that. Every directory read goes through here because a
// missing entry has to mean "absent", not "index into whatever follows".
//
static __inline const LdrDataDirectory *LdrDirectory(const LdrNtHeaders *nt,
                                                     UINT32 index) {
  if (nt->OptionalHeader.NumberOfRvaAndSizes <= index) {
    return NULL;
  }
  return &nt->OptionalHeader.DataDirectory[index];
}

#endif
