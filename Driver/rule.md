# LongsDriver — Engineering Rules

Audience: an AI agent or engineer editing this driver. Every rule below is
backed by a failure that actually happened while building the reflective
injection feature. If a rule and a comment in the code disagree, the code is
wrong — fix the code.

## Scope

`LongsDriver.sys` is a KMDF driver, normally mapped by kdmapper (`DmEntry`,
which disables PatchGuard first). On top of the existing process/thread DKOM,
ETW-TI control and task persistence, it carries a payload-DLL reader and a
kernel-side reflective loader launcher:

- `ProcessLookup`  — find a PID by image name
- `RemoteInject`   — allocate/write/protect/read inside a target process
- `PeImage`        — resolve an export in a raw PE image
- `ApcInject`      — queue a user-mode APC to every thread of a process
- `NetProbeImage`  — the embedded `NetProbe.dll` bytes (build product)
- `NetProbeInject` — orchestration + auto-start worker

It is not an injector in the "CreateRemoteThread + LoadLibrary" sense. It writes
the raw file image into the target and queues an APC at the image's own
`ReflectiveLoader`; the target maps itself.

## Rules

### 1. No process or thread list pointer is ever referenced directly

`ObReferenceObject` on an `EPROCESS`/`ETHREAD` taken from
`ActiveProcessLinks`/`ThreadListEntry` raises `REFERENCE_BY_POINTER`
(bugcheck `0x18`) when the object is being deleted. A once-per-second walk over
every process meets a dying one eventually. This was the first crash of the
feature.

- Processes come from a `ZwQuerySystemInformation(SystemProcessInformation)`
  snapshot and are resolved with `PsLookupProcessByProcessId`.
- Threads come from the same snapshot's thread array (TIDs) and are resolved
  with `PsLookupThreadByThreadId`.

Both of those are documented lookups that take their own reference and report a
vanished object instead of touching freed memory. Never reintroduce a hand
walk that references list nodes.

### 2. PsGetNextProcess is not a portable export

It is documented, but on the target kernel (10.0.26100) it is not in the
import library and `MmGetSystemRoutineAddress(L"PsGetNextProcess")` returns
NULL, which made the lookup answer `STATUS_DEVICE_CONFIGURATION_ERROR` and
silently never find the shell. The snapshot path above is what replaced it.

### 3. An RVA is not a file offset

The target holds a **raw file image**, so an export lives at
`base + file_offset`, not `base + rva`. The two differ by the section
alignment. `PeImage` returns both and the injector uses `FileOffset`; using the
RVA lands in the middle of the wrong bytes. Verified against the real DLL:
`ReflectiveLoader` RVA `0x2EE0` -> file offset `0x22E0`, and the bytes there are
the function prologue.

### 4. The whole APC library is declared by hand

The WDK 26100 km headers no longer declare `KAPC_ENVIRONMENT`,
`PKNORMAL_ROUTINE`, `PKKERNEL_ROUTINE`, `PKRUNDOWN_ROUTINE`,
`KeInitializeApc`, `KeInsertQueueApc` or `KeRemoveQueueApc`; only the `KAPC`
struct remains in `wdm.h`. ntoskrnl still exports all three routines and the
import library carries them, so `ApcInject.c` declares the documented shapes.
Do not "fix" this by removing the declarations or by resolving them by name.

### 5. Do not free a loader region while an APC may still run

The loader is queued as a user-mode APC to **every** thread of the target, so
most of those APCs are still pending when the first one completes. Their
`NormalRoutine` points into the raw image and touches the status page. Freeing
either region makes the next thread that reaches an alertable wait jump into
unmapped memory: explorer crashed and was restarted by Windows, which is why
the probe ran once and then vanished.

There is no reliable way to cancel a user APC that the kernel has already
dequeued for delivery, so `NetProbeInject` leaves the raw image and the status
page resident. They are small, one pair per injected process, and a late APC
now finds the claim already taken and returns harmlessly.

### 6. Only one APC may map the image

Because the routine is queued to every thread, multiple threads can run it at
once. The status page's first field is a claim: the loader does
`InterlockedCompareExchange(claim, 1, 0)` and only the winner maps. Without it,
several copies of the image are mapped and the status page is written by more
than one thread.

### 7. Remote memory is written attached, with no process handle

`RemoteInject` uses `KeStackAttachProcess` + `ZwAllocateVirtualMemory` /
`ZwProtectVirtualMemory` / `ZwFreeVirtualMemory` with `NtCurrentProcess()`. No
handle carrying `PROCESS_VM_OPERATION` is ever opened, which is both quieter and
the reason this driver's own `ProcessProtect` callback cannot block it (that
callback only strips rights at handle-open time).

- Every entry point requires `PASSIVE_LEVEL`: the Zw calls are PASSIVE-only and
  `KeStackAttachProcess` must not run at `DISPATCH_LEVEL` (bugcheck `0x5`).
- Allocation starts `PAGE_READWRITE` and flips to the caller's final protection
  only after the bytes are in; never leave an RWX window.
- Writes are `ProbeForWrite` + `__try` so a racing target turns into a status,
  not a kernel fault.
- Source buffers must be **kernel** addresses. While attached, the caller's own
  user addresses are not mapped.

### 8. The embedded payload is a build product

`NetProbeImageData.h` is generated at build time from
`x64\<Config>\NetProbe.dll` by `tools/Embed-Binary.ps1`, and the directory is
gitignored. If the DLL is missing the build must fail loudly, not embed a stale
or empty image.

### 9. Auto-injection is single-shot and logged

`NetProbeInjectAutoStart` runs after every other module is up, waits for
`explorer.exe` (2 s, then up to 30 x 1 s), finds the PID through `ProcessLookup`,
and injects once. Every stage goes to `DbgPrint` under `[LongsDriver]
NetProbeAuto:` / `NetProbeInject:`. It is deliberately not a retry loop: a shell
that restarts must not be re-injected behind the operator's back.

### 10. Build output location is part of the contract

`Client\embed-driver.ps1` reads the driver from `x64\<Config>\LongsDriver.sys`.
Building the `.vcxproj` on its own otherwise writes to `Driver\x64\`, and the
Client then embeds a stale image — which is how a fixed driver was tested
against the old one. The Driver project therefore pins
`OutDir`/`IntDir`, and a PostBuildEvent rebuilds the Client so its embedded blob
follows the fresh driver.

## Facts you may rely on without re-measuring

- Target kernel `10.0.26100` / x64. `EPROCESS.ActiveProcessLinks = 0x1d8`,
  `UniqueProcessId = 0x1d0`, `ImageFileName = 0x338`.
- `PsGetProcessImageFileName` is exported; in kernel mode it may return the full
  NT device path, so comparisons reduce both sides to the trailing name.
- `ZwQuerySystemInformation` is exported and linkable; `SystemProcessInformation`
  is class 5; the struct is not declared in the WDK and is defined locally.
- `PsLookupThreadByThreadId` is exported and declared in `ntifs.h`.
- The payload imports only `KERNEL32.dll`; it resolves `ws2_32.dll` at runtime.
- Nothing here mutates PatchGuard-relevant structures, so the injection path is
  safe in `g_PatchGuardBypassed == FALSE` too.
- Every project defaults to `Release|x64` (the Client maps both of its configs
  to the Release configuration). The injection feature is validated only in
  Release; a Debug payload is ~1.26 MB against ~118 KB, from `.textbss`.

## Verification

```
MSBuild.exe "Driver\KMDF Driver.vcxproj" /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal
```

The build must:
- print `Embedded ... NetProbe.dll (118272 bytes)`,
- write `x64\Release\LongsDriver.sys`,
- rebuild `x64\Release\Client.exe` from a freshly generated blob.

Confirm the image is the reviewed one:

```
dumpbin /imports "x64\Release\LongsDriver.sys"
  -> must contain ZwQuerySystemInformation, PsLookupProcessByProcessId,
     PsLookupThreadByThreadId
  -> must NOT contain ObfReferenceObject
```

Expected runtime log (WinDbg) after loading Client.exe:

```
[LongsDriver] ProcessLookup: explorer.exe -> pid <n> (1 live instance(s)).
[LongsDriver] NetProbeAuto: explorer.exe pid <n> found, injecting.
[LongsDriver] NetProbeInject: ReflectiveLoader RVA 0x2EE0, file offset 0x22E0.
[LongsDriver] ApcInject: pid <n> routine ... queued to <k>/<k> threads.
[LongsDriver] NetProbeInject: loader completed, mapped base 0000000180000000.
[LongsDriver] NetProbeInject: raw region ... and status page ... kept resident.
[NetProbe] ok probe in <n>ms reply "PONG\n"
```

## Deliberate non-goals

- Freeing the raw loader region or the status page (rule 5).
- Re-injecting after the shell restarts (rule 9).
- Per-section protection of the mapped payload from the driver; the target's
  own `ReflectiveLoader` does that.
- A trigger IOCTL: `NetProbeInjectIntoProcess` is called by the auto worker; a
  manual IOCTL is a separate, client-contract change.
