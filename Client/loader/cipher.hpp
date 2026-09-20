#pragma once
#include <Windows.h>
#include <cstddef>

//
// RC4-drop-256 stream cipher used to conceal per-build binary payloads
// (driver blob and vulnerable-driver resource) at rest. Stream cipher so
// encryption == decryption; key material is regenerated every build by
// embed-driver.ps1.
//
namespace cipher {

inline bool Rc4Drop(const BYTE* key, SIZE_T keyLen, const BYTE* in,
                    SIZE_T inLen, BYTE* out) {
  if (key == nullptr || keyLen == 0 || (in == nullptr && inLen != 0))
    return false;
  BYTE s[256];
  for (int i = 0; i < 256; ++i)
    s[i] = (BYTE)i;
  int j = 0;
  for (int i = 0; i < 256; ++i) {
    j = (j + s[i] + key[i % keyLen]) & 0xFF;
    BYTE t = s[i];
    s[i] = s[j];
    s[j] = t;
  }
  int i = 0;
  j = 0;
  for (int k = 0; k < 256; ++k) { // RC4-drop: burn the weak keystream prefix
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    BYTE t = s[i];
    s[i] = s[j];
    s[j] = t;
  }
  for (SIZE_T n = 0; n < inLen; ++n) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    BYTE t = s[i];
    s[i] = s[j];
    s[j] = t;
    out[n] = in[n] ^ s[(s[i] + s[j]) & 0xFF];
  }
  return true;
}

} // namespace cipher