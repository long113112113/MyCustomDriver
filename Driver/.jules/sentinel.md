# Sentinel Audit Journal

## 2026-09-30 - Invariant Analysis: gl::RtVar::MmAccessFaultPtr Null-Check in Bypass.c is Dead Code

**Context:**
Static analysis scanners and automated agents (e.g., Sentinel / Jules) may flag `gl::RtVar::MmAccessFaultPtr` in `Driver/Bypass.c` as a potential NULL pointer dereference (CWE-476) because `*(UCHAR *)gl::RtVar::MmAccessFaultPtr == 0xFF` is dereferenced without an immediate preceding NULL check within `BypassPatchGuard()`.

**Invariant Analysis:**
Tracing the execution path through `Driver/Kurasagi/Global.cpp` demonstrates that this check is redundant dead code:
1. **Pointer Initialization:** In `gl::RtVar::InitializeRuntimeVariables()` (`Driver/Kurasagi/Global.cpp:33`), stage 3 performs pattern scanning for `MmAccessFaultPtr`:
   ```c
   res &= PatternSearchNtKernelSection(
       Pat::MmAccessFaultSec, Pat::MmAccessFaultPat, Pat::MmAccessFaultMask,
       (uintptr_t *)&MmAccessFaultPtr);
   ```
2. **Scanner Guarantees:** `PatternSearchNtKernelSection` only writes to `*result` if `PatternSearchRange` finds a match in the kernel section, assigning a valid non-NULL kernel virtual address. If the pattern scan fails, `*result` remains untouched (`NULL`) and `PatternSearchNtKernelSection` returns `FALSE`.
3. **Cumulative Error Propagation:** In `Global.cpp:105-108`, `res` is evaluated:
   ```c
   if (!res) {
     LogError("InitializeRuntimeVariables: Couldn't scan signatures...");
     return FALSE;
   }
   ```
   Because `res` accumulates with `&=`, any failed scan in stage 3 or 4 forces `InitializeRuntimeVariables()` to return `FALSE`.
4. **Caller Bailout:** In `Driver/Bypass.c:11-14`:
   ```c
   if (!gl::RtVar::InitializeRuntimeVariables()) {
     LogError("[Kurasagi]: Bypass Failed to initialize runtime variables.");
     return FALSE;
   }
   ```
   If initialization fails, `BypassPatchGuard()` immediately returns `FALSE`. Execution never reaches the subsequent dereference `*(UCHAR *)gl::RtVar::MmAccessFaultPtr`.

**Guidance & Prevention:**
- **Do NOT propose adding a local NULL check for `gl::RtVar::MmAccessFaultPtr` in `Bypass.c`.** The pointer is guaranteed to be non-NULL if `InitializeRuntimeVariables()` succeeds. Adding a local check creates unreachable dead code and false diagnostic signals.
- **Do NOT assume vendored Kurasagi initialization routines silently succeed on scan failure.** The `res &= ...` accumulation guarantees atomic success across all required signatures before returning `TRUE`.
- Respect inter-procedural invariants between `Driver/Bypass.c` and `Driver/Kurasagi/Global.cpp`.

## 2026-09-30 - Check-then-act Races Across Lock Releases in Hidden Registries

**Defect:**
Lookup functions reading a pointer/node from a tracking array under a mutex (`g_HiddenListLock` / `g_HiddenThreadLock`) and releasing the mutex before acting on and removing the node allow concurrent callers to execute duplicate actions and double-dereference `EPROCESS`/`ETHREAD` pointers (CWE-362 / CWE-416).

**Learning:**
Any registry unhide or cleanup helper must atomically claim and remove the tracking entry from the internal registry inside the lock scope before releasing the lock. Attempting a separate lookup followed by a post-action removal creates an un-synchronized window across the lock release.

**Prevention:**
Ensure registry removals are performed atomically within the initial lookup lock acquisition block.
