#pragma once

#include <Windows.h>
#include <string>
#include <vector>

// Priority: any "*.sys" arg -> "--driver <path>" -> <exedir>\LongsDriver.sys
//          -> <exedir>\KMDFDriver.sys. Empty if nothing found.
std::wstring ResolveDriverPath(const std::vector<std::wstring>& args);

// Opens \\.\LongsDriver. If it is not running, tries to manual-map
// LongsDriver.sys via the kdmapper (Intel iqvw64e.sys) engine first.
// Returns a valid handle or INVALID_HANDLE_VALUE.
HANDLE OpenDriver(const std::vector<std::wstring>& args);