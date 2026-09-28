#include "KernelWrite.h"
#include <intrin.h>

//
// Toggling CR0.WP only affects the current CPU. These writes are serialized
// through the device control dispatch (single client), so a single CPU runs
// them. Raising to DPC_LEVEL plus masking interrupts keeps the WP window
// bounded and non-interruptible.
//
// The exception handler deliberately covers only the copy. Cleanup must run
// unconditionally afterwards: if the handler could bypass it, a faulting write
// would leave CR0.WP clear, interrupts masked and the IRQL raised, which
// wedges the CPU instead of reporting a failure. The handler therefore only
// records the code and falls through.
//
NTSTATUS KernelWrite(PVOID Destination, PVOID Source, SIZE_T Size) {
  KIRQL oldIrql;
  ULONG_PTR cr0;
  NTSTATUS status = STATUS_SUCCESS;

  if (Destination == NULL || Source == NULL || Size == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  oldIrql = KeRaiseIrqlToDpcLevel();
  _disable();

  cr0 = __readcr0();
  __writecr0(cr0 & ~((ULONG_PTR)0x10000)); // clear WP bit

  __try {
    RtlCopyMemory(Destination, Source, Size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
  }

  __writecr0(cr0); // restore WP bit

  _enable();
  KeLowerIrql(oldIrql);

  return status;
}
