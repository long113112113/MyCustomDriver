#include "Shared.h"
#include <Windows.h>
#include <iostream>

int main() {
  // Open connect thru symbolic link
  HANDLE hDevice =
      CreateFileW(L"\\\\.\\LongsDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hDevice == INVALID_HANDLE_VALUE) {
    std::cerr << "Cannot open driver. Error: " << GetLastError() << std::endl;
    return 1;
  }

  std::cout << "Connected to driver\n";

  // ------------------------------------------------------
  // PING
  // ------------------------------------------------------
  DRIVER_RESPONSE response = {0};
  DWORD bytesReturned = 0;

  BOOL result = DeviceIoControl(hDevice, IOCTL_PING, NULL, 0, // Input
                                &response, sizeof(response),  // Output
                                &bytesReturned, NULL);

  if (result) {
    std::cout << "PING response: 0x" << std::hex << response.Data << std::endl;
  } else {
    std::cerr << "PING failed. Error: " << GetLastError() << std::endl;
  }
  CloseHandle(hDevice);
  return 0;
}