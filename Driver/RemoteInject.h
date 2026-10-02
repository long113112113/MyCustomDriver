#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Remote memory primitives for placing bytes inside a target user process from
// kernel mode: allocate, write, protect, free, and a one-call
// allocate + write + protect used by the injection feature.
//
// These routines move memory only. Turning the placed bytes into execution -
// mapping a PE image (relocations, imports, TLS) or handing the address to a
// loader - is a separate step and is not done here.
//
// Design notes
// ------------
// * No process handle is ever opened. The Zw virtual-memory calls address the
//   target through NtCurrentProcess() while the calling thread is attached to
//   it, so no handle carrying PROCESS_VM_OPERATION on the target is ever
//   created. That is deliberate: it leaves nothing for handle-based monitoring
//   to see, and it is not affected by this driver's own ProcessProtect module,
//   whose Ob callback only strips access rights at handle-open time.
//
// * Allocation starts PAGE_READWRITE and is flipped to the caller's final
//   protection only after the bytes are in place. Allocating RWX first - the
//   usual sample-code shape - exposes an executable writable region for the
//   whole copy, which is the pattern page-protection telemetry exists to flag.
//
// * Every entry point requires PASSIVE_LEVEL. The Zw memory calls are
//   documented PASSIVE_LEVEL-only, and KeStackAttachProcess must not be entered
//   at DISPATCH_LEVEL (bugcheck 0x5, INVALID_PROCESS_ATTACH_ATTEMPT). A higher
//   IRQL is refused with STATUS_INVALID_DEVICE_STATE instead of being allowed
//   to corrupt state.
//
// * Nothing here touches PatchGuard-relevant structures, so the module keeps
//   working in SAFE MODE (g_PatchGuardBypassed == FALSE).
//
// * TargetPid must identify a user process: PIDs 0 and 4 are refused, as is a
//   process that is already terminating.
//
// * Source buffers must be kernel addresses (an IRP SystemBuffer, a pool
//   allocation, a static buffer, ...). While the driver is attached to the
//   target, the caller's own user-mode addresses are not mapped, so a raw user
//   pointer would be interpreted in the target's address space.
//

//
// Allocates Size bytes at an address chosen by the target's memory manager,
// with the given page protection. Size is in/out: on success it receives the
// rounded-up size the memory manager actually reserved, which RemoteInjectFree
// does not need but per-section protection work does.
//
// Each entry point performs its own process lookup and attach, so the caller
// may hold no state between calls. RemoteInjectImage exists for the common
// case and does all of it under a single attach.
//
// Returns STATUS_SUCCESS, STATUS_INVALID_PARAMETER, the process-lookup status
// (STATUS_INVALID_CID, STATUS_PROCESS_IS_TERMINATING), or the ZwAllocate status.
//
NTSTATUS RemoteInjectAllocate(ULONG TargetPid, PSIZE_T Size, ULONG Protect,
                              PVOID *RemoteBase);

//
// Copies Size bytes from Source into the target's RemoteAddress. RemoteAddress
// must lie inside a region this module allocated (or an existing writable
// region of the target), and the region must still be writable: calling this
// after RemoteInjectProtect flipped it to read-only or execute-only fails with
// an access-violation status rather than faulting the kernel, because the copy
// is exception-guarded.
//
NTSTATUS RemoteInjectWrite(ULONG TargetPid, PVOID RemoteAddress,
                           const VOID *Source, SIZE_T Size);

//
// Reads Size bytes from the target's RemoteAddress into a local buffer.
// The counterpart of RemoteInjectWrite, used to poll a target for a value it
// publishes; the read is exception-guarded like the write.
//
NTSTATUS RemoteInjectRead(ULONG TargetPid, PVOID RemoteAddress, PVOID Buffer,
                          SIZE_T Size);

//
// Changes the page protection of Size bytes at RemoteAddress. NewProtect must
// be a PAGE_* value and must not be zero. OldProtect is optional and receives
// the protection that was in effect, as returned by the kernel.
//
// This is the per-section hook for manual PE mapping: a blanket
// PAGE_EXECUTE_READ over a whole image makes its .data/.bss unwritable, while
// PAGE_EXECUTE_READWRITE keeps the RWX pattern. Calling this once per section
// is the way to get both.
//
NTSTATUS RemoteInjectProtect(ULONG TargetPid, PVOID RemoteAddress, SIZE_T Size,
                             ULONG NewProtect, PULONG OldProtect);

//
// Releases a region returned by RemoteInjectAllocate / RemoteInjectImage.
// MEM_RELEASE frees exactly the allocation that starts at RemoteAddress, so no
// size is needed and passing anything but the base address fails.
//
NTSTATUS RemoteInjectFree(ULONG TargetPid, PVOID RemoteAddress);

//
// The full write path in one call: allocate ImageSize bytes as
// PAGE_READWRITE, copy ImageBuffer, then set FinalProtect on the whole
// allocation - all under one attach. This is the "attach, allocate, write,
// detach" sequence with the leaks and unchecked calls closed.
//
// All-or-nothing: if any step fails, the allocation is released before the
// detach, so the target is left exactly as it was found and the caller never
// receives an address it cannot free.
//
// FinalProtect is what the region ends up as; PAGE_EXECUTE_READ is the right
// answer for a self-contained payload that has no writable data. A mapped PE
// with writable sections needs per-section protection through
// RemoteInjectProtect instead, in which case use RemoteInjectAllocate +
// RemoteInjectWrite and skip this helper.
//
// RemoteSize is optional and receives the rounded-up allocation size.
//
NTSTATUS RemoteInjectImage(ULONG TargetPid, const VOID *ImageBuffer,
                           SIZE_T ImageSize, ULONG FinalProtect,
                           PVOID *RemoteBase, PSIZE_T RemoteSize);

#ifdef __cplusplus
}
#endif