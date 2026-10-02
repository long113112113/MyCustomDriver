#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Minimal PE32+ reader for a DLL image held in a kernel buffer.
//
// It exists for one job: turn an export name into both the RVA the linker
// wrote and the offset of those same bytes inside the raw file image. The
// driver writes the raw file into the target, so the address to jump to is
// base + FileOffset, not base + Rva - the two differ by however the section
// was aligned, and using the RVA directly lands in the middle of the wrong
// bytes. Handing back both keeps that conversion out of the injector.
//
typedef struct _PE_EXPORT_LOCATION {
  // Offset of the function inside the image, as the export directory records
  // it.
  ULONG Rva;
  // Offset of the same bytes inside the raw file image, derived from the
  // section table.
  ULONG FileOffset;
} PE_EXPORT_LOCATION, *PPE_EXPORT_LOCATION;

//
// Looks up Name in Image's export directory.
//
// Image must point at the complete file image (MZ through the last section)
// and ImageSize must be that buffer's length; every RVA is bounds-checked
// against it before being dereferenced, because even an embedded image is
// data and a malformed one must fail here rather than be followed.
//
// Returns STATUS_SUCCESS, STATUS_NOT_FOUND (no such export, or it is a
// forwarded export, which cannot be relocated), or STATUS_INVALID_IMAGE_FORMAT
// (not a PE32+ AMD64 image, or a header/section/directory that does not fit
// the buffer).
//
NTSTATUS PeFindExportByName(_In_reads_bytes_(ImageSize) const VOID *Image,
                            _In_ SIZE_T ImageSize, _In_z_ PCSTR Name,
                            _Out_ PPE_EXPORT_LOCATION Location);

#ifdef __cplusplus
}
#endif