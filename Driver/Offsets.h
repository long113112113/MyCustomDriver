#pragma once
#include <ntddk.h>

#define WIN_1507 10240
#define WIN_1511 10586
#define WIN_1607 14393
#define WIN_1703 15063
#define WIN_1709 16299
#define WIN_1803 17134
#define WIN_1809 17763
#define WIN_1903 18362
#define WIN_1909 18363
#define WIN_11_24H2 26100
#define WIN_11_25H2 26200
#define WIN_LATEST WIN_11_25H2

extern ULONG g_WindowsBuildNumber;

// Query the current OS build
NTSTATUS OffsetsInitialize(VOID);

// EPROCESS.ActiveProcessLinks offset
ULONG GetActiveProcessLinksOffset(VOID);

// EPROCESS.ProcessLock offset. Guards the active process list: the kernel
// takes the owning EPROCESS push lock before it unlinks or relinks a node.
ULONG GetProcessLockOffset(VOID);

// ETHREAD.ThreadListEntry offset
ULONG GetThreadListEntryOffset(VOID);

// ETHREAD.ThreadLock offset. Guards ETHREAD.ThreadListEntry against
// concurrent thread enumeration and exit.
ULONG GetThreadLockOffset(VOID);

// EPROCESS.ThreadListHead offset (head of per-process thread doubly-linked list)
ULONG GetThreadListHeadOffset(VOID);