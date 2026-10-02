#include "NetProbeImage.h"

//
// The generated header only exists after tools/Embed-Binary.ps1 has run, which
// the PreBuildEvent does. The guard keeps an IDE parse or a stray manual
// compile from failing on a file the build is about to create anyway, and the
// accessor then reports "no image" instead of referring to an undefined array.
//
#if defined(__has_include)
#if __has_include("Generated/NetProbeImageData.h")
#include "Generated/NetProbeImageData.h"
#define NETPROBE_IMAGE_EMBEDDED 1
#endif
#endif

#ifndef NETPROBE_IMAGE_EMBEDDED
#define NETPROBE_IMAGE_EMBEDDED 0
#endif

const UCHAR *NetProbeImageData(SIZE_T *SizeOut) {
  if (SizeOut == NULL)
    return NULL;

#if NETPROBE_IMAGE_EMBEDDED
  *SizeOut = sizeof(g_NetProbeImage);
  return g_NetProbeImage;
#else
  *SizeOut = 0;
  return NULL;
#endif
}