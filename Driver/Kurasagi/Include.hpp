/*
 * @file Include.hpp
 * @brief Header file to include necessary Windows kernel headers and definitions.
 */

#pragma once

#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdarg.h>
#include <ntstrsafe.h>

extern "C"
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_same_ VOID
KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

extern "C"
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ VOID
KeSignalCallDpcDone(_In_ PVOID SystemArgument1);

extern "C"
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ LOGICAL
KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

// I didn't want to include undocumented structure, but we have to do it.

namespace MiSystemVaType {
	constexpr INT32 MiVaUnused = 0x0;
	constexpr INT32 MiVaProcessSpace = 0x1;
	constexpr INT32 MiVaBootLoaded = 0x2;
	constexpr INT32 MiVaPfnDatabase = 0x3;
	constexpr INT32 MiVaNonPagedPool = 0x4;
	constexpr INT32 MiVaPagedPool = 0x5;
	constexpr INT32 MiVaNonCachedMappings = 0x6;
	constexpr INT32 MiVaSystemCache = 0x7;
	constexpr INT32 MiVaSystemPtes = 0x8;
	constexpr INT32 MiVaHal = 0x9;
	constexpr INT32 MiVaNonCachedMappingsLarge = 0xa;
	constexpr INT32 MiVaDriverImages = 0xb;
	constexpr INT32 MiVaSystemPtesLarge = 0xc;
	constexpr INT32 MiVaKernelStacks = 0xd;
	constexpr INT32 MiVaSecureNonPagedPool = 0xe;
	constexpr INT32 MiVaKernelShadowStacks = 0xf;
	constexpr INT32 MiVaSoftWsles = 0x10;
	constexpr INT32 MiVaSystemDataViews = 0x11;
	constexpr INT32 MiVaKernelControlFlowGuard = 0x12;
	constexpr INT32 MiVaKasan = 0x13;
	constexpr INT32 MiVaMaximumType = 0x14;
}

typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;				//0x0000(0x0008)
	PVOID MappedBase;			//0x0008(0x0008)
	PVOID ImageBase;			//0x0010(0x0008)
	ULONG ImageSize;			//0x0018(0x0004)
	ULONG Flags;				//0x001C(0x0004)
	USHORT LoadOrderIndex;		//0x0020(0x0002)
	USHORT InitOrderIndex;		//0x0022(0x0002)
	USHORT LoadCount;			//0x0024(0x0002)
	USHORT OffsetToFileName;	//0x0026(0x0002)
	UCHAR FullPathName[256];	//0x0028(0x0100)
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _MI_VISIBLE_STATE_STUB
{
	UCHAR Smth0[0x1468];
	UCHAR SystemVaType[256];
	UCHAR Smth1[344];
} MI_VISIBLE_STATE_STUB, * PMI_VISIBLE_STATE_STUB; // SIZEOF 0x16C0

typedef struct _KTIMER_TABLE_ENTRY
{
	unsigned __int64 Lock;
	LIST_ENTRY Entry;
	ULARGE_INTEGER Time;
} KTIMER_TABLE_ENTRY, *PKTIMER_TABLE_ENTRY;

#define TIMER_TABLE_ENTRY_COUNT 512
typedef struct _KTIMER_TABLE
{
	_KTIMER* TimerExpiry[64];
	_KTIMER_TABLE_ENTRY TimerEntries[TIMER_TABLE_ENTRY_COUNT];
	unsigned __int64 LastTimerExpiration[2];
	unsigned int LastTimerHand[2];
} KTIMER_TABLE, *PKTIMER_TABLE;

typedef struct _KPRCB_STUB
{
	UCHAR Pad0[0x48];
	unsigned __int64 HalReserved[8]; // +0x48
	UCHAR Pad1[88];
	void* AcpiReserved; // +0xe0
	UCHAR Pad2[16408];
	KTIMER_TABLE TimerTable; // +0x4100
	UCHAR Pad3[19432];
} KPRCB_STUB, * PKPRCB_STUB;

enum SYSTEM_INFORMATION_CLASS : __int32
{
	// ...
	SystemModuleInformation = 0xB,
	// ...
};

typedef NTSTATUS(*NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformaiton,
	ULONG SystemInformationLenght,
	PULONG ReturnLength
	);