#include "Loader.h"

#include <iostream>

#if defined(_M_X64)
#include "loader/intel_driver.hpp"
#include "loader/kdmapper.hpp"
#include "loader/nt.hpp"
#include "loader/utils.hpp"
#if __has_include("loader/LongsDriverBlob.h")
#include "loader/LongsDriverBlob.h"
#endif
#endif

std::wstring ResolveDriverPath(const std::vector<std::wstring>& args) {
  wchar_t exePath[MAX_PATH] = {0};
  GetModuleFileNameW(NULL, exePath, MAX_PATH);
  std::wstring exeDir(exePath);
  size_t pos = exeDir.find_last_of(L"\\/");
  exeDir = (pos != std::wstring::npos) ? exeDir.substr(0, pos) : L".";

  for (const auto& a : args) {
    std::wstring lower = a;
    for (auto& ch : lower)
      ch = (wchar_t)towlower(ch);
    if (lower.size() > 4 && lower.compare(lower.size() - 4, 4, L".sys") == 0)
      return a;
  }
  for (size_t i = 0; i + 1 < args.size(); ++i) {
    if (args[i] == L"--driver" && !args[i + 1].empty())
      return args[i + 1];
  }

  static const wchar_t* candidates[] = {L"LongsDriver.sys"};
  for (const wchar_t* c : candidates) {
    std::wstring full = exeDir + L"\\" + c;
    if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES)
      return full;
  }
  return L"";
}

#if defined(_M_X64)
static HANDLE OpenDevice() {
  return CreateFileW(L"\\\\.\\LongsDriver", GENERIC_READ | GENERIC_WRITE, 0,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

// RC4-drop decryption of the embedded image (per-build random key, see
// embed-driver.ps1). Returns false on failure; `out` holds the plaintext.
static bool BlobDecrypt(const std::vector<BYTE>& in, const BYTE* key,
                        std::size_t keyLen, std::vector<BYTE>& out) {
  if (in.empty() || key == NULL || keyLen == 0)
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
  // RC4-drop: burn the first 256 keystream bytes.
  int i = 0;
  j = 0;
  for (int k = 0; k < 256; ++k) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    BYTE t = s[i];
    s[i] = s[j];
    s[j] = t;
  }
  out.resize(in.size());
  for (std::size_t n = 0; n < in.size(); ++n) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    BYTE t = s[i];
    s[i] = s[j];
    s[j] = t;
    out[n] = in[n] ^ s[(s[i] + s[j]) & 0xFF];
  }
  return !out.empty();
}
#endif

HANDLE OpenDriver(const std::vector<std::wstring>& args) {
#if !defined(_M_X64)
  std::cerr << "[!] Driver loader is x64-only; LongsDriver not loaded\n";
  return INVALID_HANDLE_VALUE;
#else
  HANDLE hDevice = OpenDevice();
  if (hDevice != INVALID_HANDLE_VALUE)
    return hDevice;

  std::wstring path = ResolveDriverPath(args);
  std::vector<BYTE> raw;
  if (!path.empty()) {
    std::wcout << L"[+] Driver not running, loading " << path << L"\n";
    if (!kdmUtils::ReadFileToMemory(path, &raw) || raw.empty()) {
      std::wcerr << L"[!] Failed to read " << path << L"\n";
      intel_driver::Unload();
      return INVALID_HANDLE_VALUE;
    }
  } else {
#ifdef LONGS_DRIVER_BLOB_H
    if (LongsDriverBlob::encrypted_size > 0 && LongsDriverBlob::size > 0) {
      const std::vector<BYTE> in(
          LongsDriverBlob::encrypted,
          LongsDriverBlob::encrypted + LongsDriverBlob::encrypted_size);
      if (BlobDecrypt(in, LongsDriverBlob::key,
                      sizeof(LongsDriverBlob::key), raw) &&
          raw.size() == LongsDriverBlob::size) {
        std::wcout << L"[+] Driver not running, loading embedded image ("
                   << raw.size() << L" bytes)\n";
      } else {
        std::cerr << "[!] Embedded image failed to decrypt\n";
        return INVALID_HANDLE_VALUE;
      }
    }
#endif
    if (raw.empty()) {
      std::cerr << "[!] No driver image found. Run Client\\embed-driver.ps1, "
                   "put LongsDriver.sys next to this exe, or pass --driver "
                   "<path>\n";
      return INVALID_HANDLE_VALUE;
    }
  }

  NTSTATUS loadStatus = intel_driver::Load();
  if (!NT_SUCCESS(loadStatus)) {
    std::cerr << "[!] intel_driver::Load failed (0x" << std::hex << loadStatus
              << std::dec
              << "). Run as admin and ensure CI policy "
                 "VulnerableDriverBlocklistEnable=0.\n";
    return INVALID_HANDLE_VALUE;
  }

  if (!intel_driver::IsRunning()) {
    std::cerr << "[!] Vulnerable driver did not start\n";
    intel_driver::Unload();
    return INVALID_HANDLE_VALUE;
  }

  NTSTATUS entryStatus = 0;
  ULONG64 mapping =
      kdmapper::MapDriver(raw.data(), 0, 0,
                          false, // keep image resident: the driver stays loaded
                          true,  // destroy header
                          kdmapper::AllocationMode::AllocateIndependentPages,
                          false, // pass allocation ptr as first param
                          nullptr, &entryStatus);

  intel_driver::Unload();

  if (mapping == 0) {
    std::cerr << "[!] MapDriver failed (DmEntry status 0x" << std::hex
              << entryStatus << std::dec << ")\n";
    return INVALID_HANDLE_VALUE;
  }

  std::cout << "[+] Driver mapped, DmEntry returned 0x" << std::hex
            << entryStatus << std::dec << "\n";

  // VirtualIOctl creates the device inside DmEntry; wait for it to appear.
  for (int i = 0; i < 25; ++i) {
    hDevice = OpenDevice();
    if (hDevice != INVALID_HANDLE_VALUE)
      return hDevice;
    Sleep(200);
  }

  std::cerr << "[!] Driver mapped but \\\\.\\LongsDriver never showed up\n";
  return INVALID_HANDLE_VALUE;
#endif
}