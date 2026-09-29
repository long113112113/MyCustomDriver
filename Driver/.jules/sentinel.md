# Sentinel Audit Journal

## 2026-09-29 - Validate Kurasagi Pointers at Seam Boundary

**Defect:** In `Driver/Bypass.c`, `gl::RtVar::MmAccessFaultPtr` was dereferenced directly after `InitializeRuntimeVariables()` without checking for `nullptr`.
**Learning:** Third-party vendored routines in Kurasagi may return success from initialization routines even when specific pattern scans fail or return null pointers. Assuming pointers provided across the vendor boundary are non-NULL causes catastrophic kernel bug checks (BSOD) at driver load time (`DmEntry`).
**Prevention:** Always explicitly validate all pointers handed back by `gl::RtVar::*` in `Bypass.c` before dereferencing them, and log appropriate diagnostics before returning `FALSE` to enter SAFE MODE.
