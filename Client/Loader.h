#pragma once

#include <Windows.h>
#include <string>
#include <vector>

std::wstring ResolveDriverPath(const std::vector<std::wstring> &args);

HANDLE OpenDriver(const std::vector<std::wstring> &args);