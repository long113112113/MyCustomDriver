//
// Classic reflective loader, exported for a caller that has placed this DLL's
// raw file image somewhere in memory and wants it mapped.
//
// Why this exists separately from NetProbeLoader
// ----------------------------------------------
// NetProbeLoader is a normally loaded DLL: it asks the OS for its own module
// handle and reads a payload out of its own resource. Neither works for an
// image that was written into a process by hand, because the image is not in
// the module list and its resource directory is never searched by the loader.
// This routine instead does the two things that make that case work:
//
//   1. It finds its own image base without being told, by scanning backwards
//      from its own code address for the MZ/PE header. That lets the caller
//      land on an export whose RVA it computed from the file, without the
//      loader needing to already know the base.
//   2. It maps that image the way the OS loader would - reserve, copy
//      sections, relocate, bind imports, protect, register unwind - and then
//      calls the image's own entry point.
//
// Everything before the mapped image is running has to work with no imports,
// no C runtime and no initialized globals, because none of those exist yet:
// the code is executing out of the raw file copy, whose IAT is still the RVAs
// the linker wrote. So the routines use only their parameters and the stack,
// and the few APIs they need are resolved by walking the PEB.
//
// This file is deliberately built with optimization and stack cookies off
// (see NetProbe.vcxproj) and avoids switch statements, which would emit jump
// tables holding absolute addresses that are still unrelocated here.
//

#include <windows.h>
#include <intrin.h>

#ifndef REFLECTIVE_LOADER_API
#define REFLECTIVE_LOADER_API __declspec(dllexport)
#endif

//
// The slice of the PEB and loader list this routine reads. Layout is taken
// from the documented x64 PEB offsets; the module list is what the loader
// builds before any DLL gets control, so it is already populated when the stub
// runs.
//
typedef struct _RL_PEB_LDR_DATA {
  ULONG Length;
  ULONG Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} RL_PEB_LDR_DATA, *PRL_PEB_LDR_DATA;

typedef struct _RL_PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN BitField;
  UCHAR Padding0[4];
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PRL_PEB_LDR_DATA Ldr;
} RL_PEB, *PRL_PEB;

typedef struct _RL_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} RL_UNICODE_STRING, *PRL_UNICODE_STRING;

typedef struct _RL_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  RL_UNICODE_STRING FullDllName;
  RL_UNICODE_STRING BaseDllName;
} RL_LDR_DATA_TABLE_ENTRY, *PRL_LDR_DATA_TABLE_ENTRY;

typedef HMODULE(WINAPI *RL_LOAD_LIBRARY_A)(LPCSTR);
typedef FARPROC(WINAPI *RL_GET_PROC_ADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *RL_VIRTUAL_ALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *RL_VIRTUAL_PROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI *RL_FLUSH_INSTRUCTION_CACHE)(HANDLE, LPCVOID, SIZE_T);
typedef BOOLEAN(WINAPI *RL_RTL_ADD_FUNCTION_TABLE)(PVOID, DWORD, DWORD64);
typedef BOOL(WINAPI *RL_DLL_MAIN)(HINSTANCE, DWORD, LPVOID);

#define RL_DIR_EXPORT 0
#define RL_DIR_IMPORT 1
#define RL_DIR_BASERELOC 5
#define RL_DIR_EXCEPTION 3
#define RL_REL_ABSOLUTE 0
#define RL_REL_DIR64 10
#define RL_ORDINAL_FLAG 0x8000000000000000ULL
#define RL_IMAGE_FILE_MACHINE_AMD64 0x8664
#define RL_MAGIC_PE32_PLUS 0x020B

//
// A byte copy that cannot be turned into a memcpy call. At this point the C
// runtime is a set of bytes inside the unmapped image, and its memcpy may
// consult an __isa_available global that loader initialization fills in later.
// The volatile accesses keep the compiler from recognizing the loop.
//
static void RlCopy(void *Destination, const void *Source, SIZE_T Size) {
  volatile unsigned char *destination = (volatile unsigned char *)Destination;
  const volatile unsigned char *source =
      (const volatile unsigned char *)Source;

  while (Size-- != 0)
    *destination++ = *source++;
}

static int RlAsciiEquals(const char *Left, const char *Right) {
  while (*Left != '\0' && *Left == *Right) {
    Left++;
    Right++;
  }
  return *Left == *Right;
}

static int RlWideNameEquals(const RL_UNICODE_STRING *Name, const char *Ansi) {
  unsigned int index;

  for (index = 0; index < Name->Length / sizeof(WCHAR); index++) {
    char left = (char)Name->Buffer[index];
    char right = Ansi[index];

    if (right == '\0')
      return 0;
    if (left >= 'a' && left <= 'z')
      left = (char)(left - ('a' - 'A'));
    if (right >= 'a' && right <= 'z')
      right = (char)(right - ('a' - 'A'));
    if (left != right)
      return 0;
  }
  return Ansi[index] == '\0';
}

static PVOID RlGetModuleBase(const char *AnsiName) {
  PRL_PEB peb = (PRL_PEB)__readgsqword(0x60);
  PLIST_ENTRY list;
  PLIST_ENTRY cursor;

  if (peb == NULL || peb->Ldr == NULL)
    return NULL;

  list = &peb->Ldr->InLoadOrderModuleList;
  for (cursor = list->Flink; cursor != list; cursor = cursor->Flink) {
    PRL_LDR_DATA_TABLE_ENTRY entry =
        CONTAINING_RECORD(cursor, RL_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (entry->DllBase == NULL)
      continue;
    if (RlWideNameEquals(&entry->BaseDllName, AnsiName))
      return entry->DllBase;
  }
  return NULL;
}

//
// Finds an export in an already mapped module. Only used to bootstrap
// GetProcAddress; once that is in hand, later symbols are resolved through it.
//
// Forwarders are followed rather than returned: most of kernel32's exports are
// "KERNELBASE.Something" strings, and handing one back as a function pointer
// would make the first call jump into the export directory. The target module
// is a dependency of the forwarder's, so it is already in the loader list and
// no LoadLibrary is needed to reach it.
//
static FARPROC RlFindExportDepth(PVOID ModuleBase, const char *Name,
                                 int Depth) {
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)ModuleBase;
  const IMAGE_NT_HEADERS *nt;
  const IMAGE_EXPORT_DIRECTORY *exports;
  DWORD exportDirRva;
  DWORD exportDirSize;
  const DWORD *names;
  const WORD *ordinals;
  const DWORD *functions;
  DWORD index;

  if (Depth > 4 || dos == NULL || dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  nt = (const IMAGE_NT_HEADERS *)((const BYTE *)ModuleBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  exportDirRva = nt->OptionalHeader.DataDirectory[RL_DIR_EXPORT].VirtualAddress;
  exportDirSize = nt->OptionalHeader.DataDirectory[RL_DIR_EXPORT].Size;
  exports = (const IMAGE_EXPORT_DIRECTORY *)((const BYTE *)ModuleBase +
                                             exportDirRva);
  if (exports->NumberOfNames == 0)
    return NULL;

  names = (const DWORD *)((const BYTE *)ModuleBase + exports->AddressOfNames);
  ordinals =
      (const WORD *)((const BYTE *)ModuleBase + exports->AddressOfNameOrdinals);
  functions =
      (const DWORD *)((const BYTE *)ModuleBase + exports->AddressOfFunctions);

  for (index = 0; index < exports->NumberOfNames; index++) {
    DWORD functionRva;

    if (!RlAsciiEquals((const char *)ModuleBase + names[index], Name))
      continue;

    functionRva = functions[ordinals[index]];

    if (functionRva >= exportDirRva &&
        functionRva - exportDirRva < exportDirSize) {
      const char *forwarder = (const char *)ModuleBase + functionRva;
      char moduleName[64];
      DWORD dotIndex = 0;
      const char *functionName;

      while (forwarder[dotIndex] != '\0' && forwarder[dotIndex] != '.' &&
             dotIndex < 60) {
        moduleName[dotIndex] = forwarder[dotIndex];
        dotIndex++;
      }
      if (forwarder[dotIndex] != '.')
        return NULL;
      moduleName[dotIndex] = '\0';
      functionName = forwarder + dotIndex + 1;

      //
      // The forwarder names the module without an extension ("KERNELBASE"),
      // while the loader list stores the full file name.
      //
      moduleName[dotIndex++] = '.';
      moduleName[dotIndex++] = 'd';
      moduleName[dotIndex++] = 'l';
      moduleName[dotIndex++] = 'l';
      moduleName[dotIndex] = '\0';

      return RlFindExportDepth(RlGetModuleBase(moduleName), functionName,
                               Depth + 1);
    }

    return (FARPROC)((const BYTE *)ModuleBase + functionRva);
  }
  return NULL;
}

static FARPROC RlFindExport(PVOID ModuleBase, const char *Name) {
  return RlFindExportDepth(ModuleBase, Name, 0);
}

//
// Walks back from Address, one page at a time, for a PE32+ header. The caller
// landed inside this image, so the MZ is at or above the region base and the
// scan reaches it before it can read past the allocation.
//
static PVOID RlFindOwnBase(PVOID Address) {
  ULONG_PTR candidate = ((ULONG_PTR)Address) & ~(ULONG_PTR)0xFFF;
  DWORD index;

  for (index = 0; index < 4096; index++) {
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)candidate;

    if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
        dos->e_lfanew < 0x100000) {
      const IMAGE_NT_HEADERS *nt =
          (const IMAGE_NT_HEADERS *)(candidate + dos->e_lfanew);
      if (nt->Signature == IMAGE_NT_SIGNATURE &&
          nt->OptionalHeader.Magic == RL_MAGIC_PE32_PLUS &&
          nt->FileHeader.Machine == RL_IMAGE_FILE_MACHINE_AMD64) {
        return (PVOID)candidate;
      }
    }
    candidate -= 0x1000;
  }
  return NULL;
}

static void RlApplyRelocations(BYTE *Base, const IMAGE_NT_HEADERS *Nt,
                               ULONG_PTR Delta) {
  const IMAGE_DATA_DIRECTORY *directory;
  const IMAGE_BASE_RELOCATION *block;
  const BYTE *end;

  if (Delta == 0)
    return;

  directory = &Nt->OptionalHeader.DataDirectory[RL_DIR_BASERELOC];
  if (directory->VirtualAddress == 0 || directory->Size == 0)
    return;

  block = (const IMAGE_BASE_RELOCATION *)(Base + directory->VirtualAddress);
  end = (const BYTE *)block + directory->Size;

  while ((const BYTE *)block + sizeof(IMAGE_BASE_RELOCATION) <= end) {
    const BYTE *item;
    const BYTE *blockEnd;

    if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
      break;
    blockEnd = (const BYTE *)block + block->SizeOfBlock;
    if (blockEnd > end)
      break;

    item = (const BYTE *)block + sizeof(IMAGE_BASE_RELOCATION);
    while (item + sizeof(WORD) <= blockEnd) {
      WORD packed = *(const WORD *)item;
      WORD type = (WORD)(packed >> 12);

      item += sizeof(WORD);
      if (type == RL_REL_ABSOLUTE)
        continue;
      if (type == RL_REL_DIR64) {
        ULONG target = block->VirtualAddress + (packed & 0x0FFF);
        *(ULONG_PTR *)(Base + target) += Delta;
      }
    }
    block = (const IMAGE_BASE_RELOCATION *)blockEnd;
  }
}

static BOOL RlBindImports(BYTE *Base, const IMAGE_NT_HEADERS *Nt,
                          RL_LOAD_LIBRARY_A LoadLibraryA,
                          RL_GET_PROC_ADDRESS GetProcAddress) {
  const IMAGE_DATA_DIRECTORY *directory =
      &Nt->OptionalHeader.DataDirectory[RL_DIR_IMPORT];
  const IMAGE_IMPORT_DESCRIPTOR *descriptor;
  const BYTE *end;

  if (directory->VirtualAddress == 0 || directory->Size == 0)
    return TRUE;

  descriptor = (const IMAGE_IMPORT_DESCRIPTOR *)(Base +
                                                 directory->VirtualAddress);
  end = (const BYTE *)descriptor + directory->Size;

  while ((const BYTE *)descriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= end) {
    HMODULE module;
    const ULONG_PTR *lookup;
    ULONG_PTR *address;

    if (descriptor->Name == 0)
      break;

    module = LoadLibraryA((const char *)(Base + descriptor->Name));
    if (module == NULL)
      return FALSE;

    lookup = (const ULONG_PTR *)(Base + (descriptor->OriginalFirstThunk != 0
                                             ? descriptor->OriginalFirstThunk
                                             : descriptor->FirstThunk));
    address = (ULONG_PTR *)(Base + descriptor->FirstThunk);

    for (;;) {
      ULONG_PTR target = *lookup;

      if (target == 0)
        break;

      if ((target & RL_ORDINAL_FLAG) != 0) {
        FARPROC resolved = GetProcAddress(module, (LPCSTR)(target & 0xFFFF));
        if (resolved == NULL)
          return FALSE;
        *address = (ULONG_PTR)resolved;
      } else {
        const IMAGE_IMPORT_BY_NAME *byName =
            (const IMAGE_IMPORT_BY_NAME *)(Base + (ULONG)target);
        FARPROC resolved = GetProcAddress(module, (LPCSTR)byName->Name);
        if (resolved == NULL)
          return FALSE;
        *address = (ULONG_PTR)resolved;
      }
      lookup++;
      address++;
    }
    descriptor++;
  }
  return TRUE;
}

static DWORD RlProtect(BYTE *Base, const IMAGE_NT_HEADERS *Nt,
                       RL_VIRTUAL_PROTECT VirtualProtect) {
  const IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(Nt);
  WORD index;

  for (index = 0; index < Nt->FileHeader.NumberOfSections; index++) {
    DWORD characteristics = sections[index].Characteristics;
    DWORD protect;
    DWORD oldProtect = 0;
    SIZE_T size = sections[index].Misc.VirtualSize;

    if (size == 0)
      size = sections[index].SizeOfRawData;
    if (size == 0)
      continue;

    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
        (characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
      protect = PAGE_EXECUTE_READWRITE;
    } else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
      protect = (characteristics & IMAGE_SCN_MEM_READ) != 0 ? PAGE_EXECUTE_READ
                                                            : PAGE_EXECUTE;
    } else if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
      protect = PAGE_READWRITE;
    } else {
      protect = PAGE_READONLY;
    }

    if (!VirtualProtect(Base + sections[index].VirtualAddress, size, protect,
                        &oldProtect)) {
      return FALSE;
    }
  }

  if (Nt->OptionalHeader.SizeOfHeaders != 0) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(Base, Nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY,
                        &oldProtect)) {
      return FALSE;
    }
  }
  return TRUE;
}

static void RlRegisterUnwind(BYTE *Base, const IMAGE_NT_HEADERS *Nt,
                             RL_RTL_ADD_FUNCTION_TABLE AddFunctionTable) {
  const IMAGE_DATA_DIRECTORY *directory =
      &Nt->OptionalHeader.DataDirectory[RL_DIR_EXCEPTION];

  if (AddFunctionTable == NULL || directory->VirtualAddress == 0 ||
      directory->Size == 0) {
    return;
  }
  AddFunctionTable(
      Base + directory->VirtualAddress,
      directory->Size / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
      (DWORD64)(ULONG_PTR)Base);
}

static ULONG_PTR RlMapImage(LPVOID Parameter) {
  PVOID rawBase;
  const IMAGE_NT_HEADERS *nt;
  PVOID kernel32;
  PVOID ntdll;
  RL_GET_PROC_ADDRESS getProcAddress;
  RL_LOAD_LIBRARY_A loadLibraryA;
  RL_VIRTUAL_ALLOC virtualAlloc;
  RL_VIRTUAL_PROTECT virtualProtect;
  RL_FLUSH_INSTRUCTION_CACHE flushInstructionCache;
  RL_RTL_ADD_FUNCTION_TABLE addFunctionTable;
  PVOID imageBase;
  ULONG_PTR delta;
  const IMAGE_SECTION_HEADER *sections;
  WORD index;
  RL_DLL_MAIN entry;

  rawBase = RlFindOwnBase((PVOID)&RlMapImage);
  if (rawBase == NULL)
    return 0;

  nt = (const IMAGE_NT_HEADERS *)((const BYTE *)rawBase +
                                  ((const IMAGE_DOS_HEADER *)rawBase)
                                      ->e_lfanew);

  kernel32 = RlGetModuleBase("kernel32.dll");
  if (kernel32 == NULL)
    return 0;
  getProcAddress = (RL_GET_PROC_ADDRESS)RlFindExport(kernel32,
                                                     "GetProcAddress");
  if (getProcAddress == NULL)
    return 0;

  loadLibraryA =
      (RL_LOAD_LIBRARY_A)getProcAddress((HMODULE)kernel32, "LoadLibraryA");
  virtualAlloc =
      (RL_VIRTUAL_ALLOC)getProcAddress((HMODULE)kernel32, "VirtualAlloc");
  virtualProtect =
      (RL_VIRTUAL_PROTECT)getProcAddress((HMODULE)kernel32, "VirtualProtect");
  flushInstructionCache = (RL_FLUSH_INSTRUCTION_CACHE)getProcAddress(
      (HMODULE)kernel32, "FlushInstructionCache");
  if (loadLibraryA == NULL || virtualAlloc == NULL || virtualProtect == NULL)
    return 0;

  ntdll = RlGetModuleBase("ntdll.dll");
  addFunctionTable = NULL;
  if (ntdll != NULL) {
    addFunctionTable = (RL_RTL_ADD_FUNCTION_TABLE)getProcAddress(
        (HMODULE)ntdll, "RtlAddFunctionTable");
  }

  //
  // Try the image's own preferred base first so no relocation is needed, then
  // fall back to anywhere. Both go through the resolved VirtualAlloc because
  // the IAT is still unbound.
  //
  imageBase = virtualAlloc((LPVOID)nt->OptionalHeader.ImageBase,
                           nt->OptionalHeader.SizeOfImage,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (imageBase == NULL) {
    imageBase = virtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }
  if (imageBase == NULL)
    return 0;

  //
  // Copy headers and sections from the raw file copy. VirtualAlloc zeroed the
  // reservation, so uninitialized sections need no explicit clear.
  //
  {
    SIZE_T headers = nt->OptionalHeader.SizeOfHeaders;
    if (headers > nt->OptionalHeader.SizeOfImage)
      headers = nt->OptionalHeader.SizeOfImage;
    RlCopy(imageBase, rawBase, headers);
  }

  sections = IMAGE_FIRST_SECTION(nt);
  for (index = 0; index < nt->FileHeader.NumberOfSections; index++) {
    if (sections[index].SizeOfRawData == 0)
      continue;
    RlCopy((BYTE *)imageBase + sections[index].VirtualAddress,
           (const BYTE *)rawBase + sections[index].PointerToRawData,
           sections[index].SizeOfRawData);
  }

  delta = (ULONG_PTR)imageBase - (ULONG_PTR)nt->OptionalHeader.ImageBase;
  RlApplyRelocations((BYTE *)imageBase, nt, delta);

  if (!RlBindImports((BYTE *)imageBase, nt, loadLibraryA, getProcAddress))
    return 0;

  if (!RlProtect((BYTE *)imageBase, nt, virtualProtect))
    return 0;

  RlRegisterUnwind((BYTE *)imageBase, nt, addFunctionTable);

  if (flushInstructionCache != NULL) {
    //
    // The current-process pseudo handle, spelled out rather than through
    // GetCurrentProcess: that call would go through the still-unbound IAT.
    //
    flushInstructionCache((HANDLE)(LONG_PTR)-1, imageBase,
                          nt->OptionalHeader.SizeOfImage);
  }

  entry = (RL_DLL_MAIN)((BYTE *)imageBase +
                        nt->OptionalHeader.AddressOfEntryPoint);
  entry((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, Parameter);

  return (ULONG_PTR)imageBase;
}

//
// The exported entry. Parameter points at a writable page the injector set
// aside. Because the injector queues this routine to every thread, the page's
// first field is a claim: only the thread that wins the compare-exchange maps
// the image, so the payload is brought up exactly once and the raw copy is not
// being read by a second mapper when the injector releases it.
//
// Layout, mirrored in Driver/NetProbeInject.c:
//   +0  LONG       claim, 0 free / 1 taken
//   +4  DWORD      RL_STATUS_MAGIC once mapping has finished
//   +8  ULONG_PTR  mapped image base, or 0 on failure
//
#define RL_STATUS_MAGIC 0x4E504C52UL /* 'RLPN' */

REFLECTIVE_LOADER_API ULONG_PTR WINAPI ReflectiveLoader(LPVOID Parameter) {
  ULONG_PTR imageBase;

  if (Parameter != NULL) {
    //
    // _InterlockedCompareExchange is a compiler intrinsic: a lock cmpxchg, not
    // a CRT call, which matters because the CRT is not up yet.
    //
    if (_InterlockedCompareExchange((volatile long *)Parameter, 1, 0) != 0)
      return 0;
  }

  imageBase = RlMapImage(Parameter);

  if (Parameter != NULL) {
    *(volatile DWORD *)((BYTE *)Parameter + 4) = RL_STATUS_MAGIC;
    *(volatile ULONG_PTR *)((BYTE *)Parameter + 8) = imageBase;
  }

  return imageBase;
}
