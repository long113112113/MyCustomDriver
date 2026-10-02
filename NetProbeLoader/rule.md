# NetProbeLoader — Engineering Rules

Audience: an AI agent or engineer editing this project. Every rule below is
backed by a measurement taken against this project. If a rule and a comment in
the code disagree, the code is wrong — fix the code.

## Scope

`NetProbeLoader.dll` manually maps `NetProbe.dll` into its own process and calls
its entry point. It is not an injector and must never grow into one. It reads
the payload from its own RCDATA resource (ID 1), maps it, applies relocations,
binds imports, registers unwind info, and calls `DllMain`.

It must remain free of dependencies beyond `KERNEL32.dll`, and must not depend
on the C runtime at runtime. Hand-rolled formatting into stack buffers is
deliberate, not a leftover.

## Rules

### 1. Hand-rolled PE structs must match the spec field for field

The PE structs in `include/LoaderPe.h` are hand-rolled on purpose: they decouple
the loader from the installed SDK version. That freedom carries an obligation —
every field width must match the PE specification exactly.

- Never narrow a field to a smaller integer to "save space". Padding absorbs the
  missing byte, so the damage is invisible until a value exceeds the truncation.
- Keep field *names* identical to the SDK, including quirks, so the struct can be
  diffed against `winnt.h` field by field. `AddressOfCallBacks` is capital-B in
  the SDK; match it.

`IMAGE_TLS_DIRECTORY64` has **four** leading 64-bit fields. A three-`UINT64`
version is 32 bytes instead of 40, which silently places `AddressOfCallBacks`
on top of `AddressOfIndex`.

Verify any struct change by compiling it against the SDK types:

```
cl /nologo /W3 /MT /I"include" /Fe:verify_structs.exe verify_structs.c
```

`verify_structs.c` (in `%TEMP%\opencode`) compares `sizeof` and every
`offsetof` against `IMAGE_*` from the SDK. It must report zero mismatches.
Treat a mismatch as a build failure.

### 2. Declare runtime-resolved ntdll functions from the SDK header

`winnt.h` carries three identical copies of these prototypes under `_AMD64_`,
`_ARM_`, and `_ARM64_`. All three agree. Copy from the header; do not reconstruct
a prototype from memory.

`RtlAddFunctionTable` takes three arguments, is `__cdecl`, and returns
`BOOLEAN` where `TRUE` means success. It is not `NTSTATUS`, and there is no
handle out-parameter. Reading the return value as an `NTSTATUS` inverts the
meaning of success and failure.

`RtlInstallFunctionTableCallback` is not a substitute for
`RtlAddFunctionTable`: it registers a callback invoked on lookup failure.

**Do not reason from "it works".** x64 Windows has a single calling convention;
`__cdecl` and `__stdcall` are not distinguishable, and an extra fourth argument
lands in a register that the callee ignores. A wrong prototype can pass every
test and still be wrong. Only the SDK declaration counts as evidence.

### 3. Every RVA read is range-checked before it is dereferenced

This includes directory entries, descriptor fields, and pointer chains. A
malformed payload is untrusted input, not a formality.

Write bounds as subtraction, never addition:

```c
/* correct */
if (rva == 0 || rva > size || need > size - rva) { fail; }

/* wrong: rva + need wraps and passes the check */
if (rva + need > size) { fail; }
```

Apply the same rule to every unsigned arithmetic on image-derived values.

### 4. A memory copy has two ends, and both need bounds

- Source: `PointerToRawData` and `SizeOfRawData` against the **file size**.
- Destination: `VirtualAddress` and `misc.VirtualSize` against `SizeOfImage`.

`LdrMapImage()` therefore takes `fileSize` explicitly. Do not reintroduce a
signature that lacks it.

On a section that does not fit, **fail** and release the reservation. Do not
`continue` and produce a half-built image; the resulting crash lands far from
the cause and destroys the evidence.

### 5. Every exit path after allocation releases the reservation

Once `VirtualAlloc` has succeeded, no return path may leak. Route all failures
through the single `Fail:` label and call `VirtualFree(base, 0, MEM_RELEASE)`.

`MEM_RELEASE` requires a size of 0.

Regression test — patch the payload's `CreateThread` import to `CreateThreap`,
load it, and query the region:

```
patch_import.exe <good loader> <broken loader>
verify_free.exe <broken loader>    -> ReflectiveLoad returns NULL, region MEM_FREE before AND after
verify_free.exe <good loader>      -> returns a pointer, region MEM_COMMIT after
```

### 6. Section protection derives from the section's own flags

Translate `IMAGE_SCN_MEM_READ` / `WRITE` / `EXECUTE` into the matching
`PAGE_*` bits. Do not collapse flags into a fixed pattern.

`EXECUTE` alone is `PAGE_EXECUTE_READ`, not `PAGE_EXECUTE_READWRITE`. Honor a
section that genuinely declares both write and execute, but never infer write
from a section name or from position.

Protect the PE headers `PAGE_READONLY` once imports are bound.

**Do not special-case `.textbss`.** Debug builds emit a `.textbss` section with
`EXECUTE|READ|WRITE` from the MSVC incremental build; that is a link-level
artifact, not something the loader should compensate for. Report it, do not
paper over it.

Flush the instruction cache after relocations and **before** calling the entry
point.

### 7. Bind imports from the INT, into the IAT

Read through `OriginalFirstThunk` and write through `FirstThunk`. Writing the
INT as well leaves the payload calling raw RVAs.

`IMAGE_IMPORT_BY_NAME` points at the 2-byte `Hint`; the function name starts two
bytes later. Passing `byName` itself to `GetProcAddress` is wrong.

Bound the walk by the smaller of the remaining INT and IAT bytes.

### 8. Track every module you load

`LoadLibraryA` calls must be recorded with matching `FreeLibrary` calls.
Without this, an unload path cannot unload what the payload pulled in.

`ReflectiveUnload()` is currently a **stub**, by decision. The OS never detaches
a manually mapped image, so `DllMain(DLL_PROCESS_DETACH)` never runs for the
payload either. Anything that assumes normal loading semantics — the detach
path, unload ordering, loader-lock waits — is currently dead code. Do not treat
it as verified, and do not build on it.

### 9. TLS is detected and refused, not invoked

The loader does not allocate a TLS index and does not publish raw data. Calling
an entry's TLS callbacks would hand them an unallocated TLS variable and crash
the host — a worse failure than the one being prevented.

So: if a TLS directory is present with callbacks, log a warning and continue
without invoking them. `AddressOfCallBacks` is a virtual address after
relocation, not an RVA.

Implementing TLS properly is a larger change — allocate an index from the
process's TLS table, publish the raw data, and copy plus zero-fill per new
thread. Treat it as a separate, reviewed task.

### 10. Resolve your own module from a code address

Use
`GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, &ReflectiveLoad, &self)`.

`GetModuleHandleA(NULL)` returns the **host executable's** handle, not the
loader's. That mistake produces a base address with an unrelated image size and
corrupts every offset derived from it.

### 11. No undefined behaviour in the logging path

`buffer[i++] = message[i]` mixes an unsequenced side effect with a read of `i` in
the same expression. Assign and increment in separate statements.

Apply the same scrutiny to array indexing generally: never index a lookup table
with values that are already characters.

### 12. Use SDK constants for directory indices

`IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` is 11 and
`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` is 13. There is no
`IMAGE_DIRECTORY_ENTRY_*` constant for DVRT — that data lives inside the Load
Config directory. Take every index from the SDK, never from memory.

Wrap each directory read in a `NumberOfRvaAndSizes` bounds check.

Current payload measurements: delay imports 0, bound imports 0, TLS directory RVA
0. The code paths for these exist for correctness, not because they fire today.

## Verification commands

```
MSBuild.exe NetProbeLoader.vcxproj /t:Rebuild /p:Configuration=Debug   /p:Platform=x64 /v:m /nologo
MSBuild.exe NetProbeLoader.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /v:m /nologo

host_reflective.exe <loader>   -> "RESULT: host survived, payload base 0x180000000", log shows PONG
verify_prot.exe    <loader>   -> per-page protect bits
verify_free.exe    <loader>   -> region state before and after
```

Build the payload project before the loader project; the loader stages the
payload as RCDATA at build time.

A solution-level Release build can fail with `LNK1104` on
`HostListener\host_listener.exe` while that process is running. Build the two
projects individually instead of killing a process you do not own.

## Facts you may rely on without re-measuring

- Both binaries import only `KERNEL32.dll`, in every configuration. The payload
  resolves `ws2_32.dll` at runtime, so `WS2_32.dll` does not appear in any
  import table here.
- Release layout: headers `R`, `.text` `RX`, `.rdata` `R`, `.data` `RW`,
  `.pdata` `R`. No `RWX` page exists in Release.
- `DllCharacteristics = 0x160` — high entropy VA, dynamic base, NX. CFG is off.
- Debug layout differs: `.textbss` is `RWX` at `+0x1000` and `SizeOfImage`
  grows to `0x1AA000`. This is the MSVC Debug artifact described in rule 6.
- Debug builds log a trace to `%TEMP%\NetProbeLoader.log`. Release builds do
  not, by design; an absent trace in Release is not a bug.

## Deliberate non-goals

Do not add these without a specific request:

- **Erasing or wiping headers after mapping.** This breaks
  `RtlPcToFileHeader`, which the unwinder and debugger rely on.
- **Making `ReflectiveUnload` real.** It would activate the loader-lock wait in
  the payload's stop path, which is a different piece of work.
- **Installing a function-table callback** as a way to "fix" exception
  registration. `RtlAddFunctionTable` is the correct API.
