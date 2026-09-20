#include "KernelWrite.h"
#include <intrin.h>

//
// Toggling CR0.WP only affects the current CPU. The ClipboardHook arm/disarm
// paths are serialized through the device control dispatch (single client), so
// a single CPU runs these writes. Raising to DPC_LEVEL plus masking
// interrupts keeps the WP window bounded and non-interruptible.
//
NTSTATUS KernelWrite(PVOID Destination, PVOID Source, SIZE_T Size) {
  if (Destination == NULL || Source == NULL || Size == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
  _disable();

  ULONG_PTR cr0 = __readcr0();
  __writecr0(cr0 & ~((ULONG_PTR)0x10000)); // clear WP bit

  RtlCopyMemory(Destination, Source, Size);

  __writecr0(cr0); // restore WP bit

  _enable();
  KeLowerIrql(oldIrql);

  return STATUS_SUCCESS;
}