# NetProbe — Engineering Rules

Audience: an AI agent or engineer editing this project. Every rule below is
backed by a measurement taken against this project. If a rule and a comment in
the code disagree, the code is wrong — fix the code.

## Scope

`NetProbe.dll` is the payload. A worker thread opens a TCP connection to a
configured endpoint on an interval, sends a probe, and validates the reply. It
can be brought up two ways: `NetProbeLoader.dll` maps it from a resource in a
user-mode host, or the kernel driver writes the raw file image into a target
process and queues a user-mode APC at this DLL's own `ReflectiveLoader`, which
maps the image in place. It is never intended to outlive an explicit shutdown
entry point.

## Reflective self-loader (kernel path)

`src/ReflectiveLoader.c` exports `ReflectiveLoader`, the classic
reflective-DLL entry: self-locating, self-mapping, no dependency on the OS
loader.

Rules that keep it runnable from a raw file copy:

- **Nothing may use the IAT, the C runtime, or an initialized global before the
  image is mapped.** When the stub starts it is executing out of the raw file,
  whose import table is still the RVAs the linker wrote. The few APIs it needs
  (`GetProcAddress`, `LoadLibraryA`, `VirtualAlloc`, `VirtualProtect`,
  `FlushInstructionCache`, `RtlAddFunctionTable`) are resolved by walking the
  PEB, and the function pointers are kept on the stack.
- **No switch statements.** A jump table is an array of absolute addresses that
  is not relocated yet at that point.
- **Find the base by scanning backwards for MZ/PE32+**, never from a passed-in
  address; the caller only knows the export's file offset.
- The file is compiled with `/GS- /GL- /guard- /Od` (see
  `NetProbe.vcxproj`), so no security cookie, no link-time rewriting, no CFG
  check, and no loop folded into a `memcpy` that reads an uninitialized ISA
  global. Verify any change with:

  ```
  dumpbin /disasm x64\Release\NetProbe.dll
    -> the ReflectiveLoader region must contain no __imp_ and no rip-relative
       memory access
  ```

- **Claim before mapping.** The driver queues the routine to every thread, so
  the status page's first dword is a claim; only the thread that wins the
  compare-exchange maps. The page layout, mirrored in
  `Driver/NetProbeInject.c`, is `+0` claim, `+4` magic, `+8` mapped base.
- `DllMain` stays thin on purpose; `NetProbeStart` is idempotent, so a lost
  race that still called it would not start a second worker, but only one
  thread should map in the first place.


## Rules

### 1. Static imports stay at KERNEL32 only

Load `ws2_32.dll` with `LoadLibraryA` plus `GetProcAddress` at runtime, and keep
it that way. This is verified in every configuration: `WS2_32.dll` appears in
no import table of this project.

Two reasons, both load-bearing:

- The loader rewrites the import table by hand. Every statically imported
  function is another entry that must be resolved correctly.
- Winsock is not loaded in the host process. A static dependency would demand
  it before any code here gets to run.

Do not add a static import to "simplify" something. If a new API is needed,
resolve it the same way.

### 2. Resolve the whole function table, or none

Load the library, then resolve every pointer it needs into one structure. If any
resolution fails, `FreeLibrary` the module, zero the structure, and fail. Do not
return a partially populated table — a null function pointer reached through a
successful-looking init is a crash inside an unrelated code path.

### 3. Function pointer prototypes must be exact

A wrong prototype is not caught by the compiler, because the compiler has no
declaration to compare against.

`ioctlsocket` is `int WSAAPI (SOCKET, long, u_long *)` — three fixed
parameters, not variadic. A variadic declaration happens to work on x64, where
all arguments are passed the same way, and is still wrong. Copy the real
prototype from the platform header.

### 4. Logging correctness is a correctness requirement

A broken formatter destroys the only evidence you get from failure paths, and
failure paths are the paths nobody exercises.

`LogHex` builds digits from a character table. Indexing that table with a value
that is *already* a character reads 32 to 54 bytes past a 17-byte array. The
observed symptom was silent, not loud: `0xC0000001` formatted as an empty
string. Errors looked like they had no cause.

Rules that follow:

- Never index a character table with something other than a nibble or a
  remainder value.
- Test the logging unit on its own, not only through a passing probe. Compile
  `src/ProbeLog.c` with a `main` that calls every entry point, then read
  `%TEMP%\NetProbe.log`. Correct output for `10061`, `0x0`, `0xC0000001` and
  `0x80004005` is the acceptance criterion.
- Escape control characters in anything received from the network, so one probe
  event always occupies exactly one log line.
- Keep the one-line-per-event invariant. The buffer is flushed once, after the
  whole line is composed.

Known cosmetic defect, deliberately left: `LogMsgCode` emits no space before
`0x`, producing `WSAStartup failed0xC0000001`. Fix it when you touch that
function; do not propagate the pattern.

### 5. No undefined behaviour anywhere

The general rule, since this code runs inside someone else's process:

- Never mix a side effect with a read of the same variable in one expression.
  `buf[i++] = src[i]` is undefined even though every compiler evaluates it the
  convenient way. Assign, then increment.
- No signed overflow, no out-of-bounds indexing, no reading a pointer the
  network gave you without a length check.

### 6. Byte order is explicit

Use `htons` / `ntohs` at every boundary. Never cast a host integer to a network
field by assigning it, and never assume the wire format matches memory layout.

### 7. Threading and shutdown

- Guard single-start with `InterlockedCompareExchange`, not a plain flag.
- Disable thread library notifications in `DllMain(DLL_PROCESS_DETACH)`.
- Every network operation carries a timeout, so an in-flight probe always
  unwinds on its own. A probe loop must not be able to block shutdown
  indefinitely.
- Keep the worker handle valid until the worker is confirmed gone.

**Loader-lock constraint.** Waiting on the worker from `DllMain`
(`DLL_PROCESS_DETACH`) runs while the loader lock is held. If the worker can
call `LoadLibraryA` — and the Winsock load path can — that wait will contend on
the same lock. This is currently unreachable, because a manually mapped image is
never detached by the OS and `ReflectiveUnload()` is a stub. It becomes a real
stall if this DLL is ever loaded normally, or if unload is implemented. The
correct shape is an exported shutdown entry point invoked before `FreeLibrary`,
not a detach-time wait. The current implementation bounds the wait at two
seconds, so it degrades into a delay rather than a permanent deadlock — but
bounded is not the same as correct.

### 8. Know which configuration you are testing

Debug builds emit a `.textbss` section with `EXECUTE|READ|WRITE`, produced by
the MSVC incremental build. Release does not.

Measured Release layout: headers `R`, `.text` `RX`, `.rdata` `R`, `.data` `RW`.
Measured Debug layout additionally has an `RWX` page at `+0x1000`, and
`SizeOfImage` grows to `0x1AA000`.

Consequences:

- Any W^X scanner, integrity check, or vulnerability assessment will flag the
  Debug binary. That finding is about the build configuration, not about this
  code. Say so explicitly rather than silently "fixing" it here.
- Compare memory layouts only between like configurations. A Release-to-Debug
  offset comparison produces noise.

### 9. Build the payload before the loader

`NetProbeLoader.vcxproj` stages this DLL into its own RCDATA at build time.
Building the loader alone silently ships the previous payload. In a solution
build the dependency ordering usually hides this; building a single project does
not.

## Verification commands

```
MSBuild.exe NetProbe.vcxproj /t:Rebuild /p:Configuration=Debug   /p:Platform=x64 /v:m /nologo
MSBuild.exe NetProbe.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /v:m /nologo
MSBuild.exe ..\NetProbeLoader\NetProbeLoader.vcxproj /t:Rebuild /p:Configuration=<same> /p:Platform=x64 /v:m /nologo

host_reflective.exe ..\x64\<Config>\NetProbeLoader.dll
```

Success is all three of: host survives, `ReflectiveLoad` returns non-NULL, and
`%TEMP%\NetProbe.log` contains `reply "PONG\n"` after the loader has been freed.

To exercise the failure paths, load the broken loader produced by
`patch_import.exe` — that is currently the only automated way to reach them.

## Facts you may rely on without re-measuring

- Static imports: `KERNEL32.dll` only, all configurations.
- TLS directory RVA 0, delay imports 0, bound imports 0.
- Runtime dependency resolution: `ws2_32.dll` via `LoadLibraryA`.
- Release: no `RWX` page. Debug: one, from `.textbss`.
- Debug builds log to `%TEMP%\NetProbe.log`; Release builds log to
  `OutputDebugStringA` only.

## Environment notes

- `host_listener.exe` runs elevated and cannot be stopped without elevation. A
  full solution Release build can fail `LNK1104` on its locked output. Build
  the individual projects instead.
- PowerShell `Add-Type` fails with a null `LIB` because `LIB` points at a
  non-existent npcap directory. Set `$env:LIB = $null` first.
