#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// The NetProbe payload, compiled into the driver as a byte image.
//
// The array itself is generated at build time from x64\<Config>\NetProbe.dll
// by tools/Embed-Binary.ps1, so the checked-in source only declares the
// accessor. This is the raw file image, not a mapped one: the target's
// ReflectiveLoader reads it in file layout.
//
// Returns NULL and a zero size when the generated header is absent, which
// should be impossible after a successful build but keeps a mis-ordered build
// from turning into a wild pointer.
//
const UCHAR *NetProbeImageData(_Out_ SIZE_T *SizeOut);

#ifdef __cplusplus
}
#endif