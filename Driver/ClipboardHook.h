#pragma once
#include <ntddk.h>
#include "Shared.h"

//
// Clipboard hijack module lifecycle. Invoked from DriverEntry / DriverUnload.
// Resolves win32kfull!NtUserGetClipboardData at Initialize (read-only), keeps
// the hook uninstalled until ClipboardHookArm() is called by the client.
//
NTSTATUS ClipboardHookInitialize(VOID);
VOID ClipboardHookCleanup(VOID);

//
// Caches the replacement UTF-16 text (including NUL terminator) in non-paged
// memory. CharCount is the number of wide chars the caller provided; the
// buffer must be NUL-terminated within CLIP_MAX_TEXT_CHARS.
//
NTSTATUS ClipboardHookSetText(PWCHAR Text, ULONG CharCount);

//
// Installs / removes the inline hook. Arm verifies the current prologue bytes
// before patching so a mismatched win32kfull revision fails cleanly.
//
NTSTATUS ClipboardHookArm(VOID);
NTSTATUS ClipboardHookDisarm(VOID);

//
// Returns whether the hook is currently installed and armed.
//
NTSTATUS ClipboardHookStatus(PBOOLEAN Armed);