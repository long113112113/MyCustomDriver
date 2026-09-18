#include "Loader.h"

#include <iostream>

#if defined(_M_X64)
#include "loader/intel_driver.hpp"
#include "loader/kdmapper.hpp"
#include "loader/nt.hpp"
#include "loader/utils.hpp"
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

  static const wchar_t* candidates[] = {L"LongsDriver.sys", L"KMDFDriver.sys"};
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
  if (path.empty()) {
    std::cerr << "[!] No driver image found. Put LongsDriver.sys next to "
                 "this exe or pass --driver <path>\n";
    return INVALID_HANDLE_VALUE;
  }

  std::wcout << L"[+] Driver not running, loading " << path << L"\n";

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

  std::vector<BYTE> raw;
  if (!kdmUtils::ReadFileToMemory(path, &raw) || raw.empty()) {
    std::wcerr << L"[!] Failed to read " << path << L"\n";
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