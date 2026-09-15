#include "Shared.h"
#include <Windows.h>
#include <iostream>

static bool HideProcess(HANDLE hDevice, ULONG pid) {
  PROCESS_REQUEST req = {0};
  req.ProcessId = pid;
  DWORD bytesReturned = 0;

  BOOL result = DeviceIoControl(hDevice, IOCTL_HIDE_PROCESS, &req, sizeof(req),
                                NULL, 0, &bytesReturned, NULL);
  if (result)
    std::cout << "Hidden PID " << pid << std::endl;
  else
    std::cerr << "Hide PID " << pid << " failed. Error: " << GetLastError()
              << std::endl;
  return result;
}

static bool UnhideProcess(HANDLE hDevice, ULONG pid) {
  PROCESS_REQUEST req = {0};
  req.ProcessId = pid;
  DWORD bytesReturned = 0;

  BOOL result = DeviceIoControl(hDevice, IOCTL_UNHIDE_PROCESS, &req,
                                sizeof(req), NULL, 0, &bytesReturned, NULL);
  if (result)
    std::cout << "Revealed PID " << pid << std::endl;
  else
    std::cerr << "Unhide PID " << pid << " failed. Error: " << GetLastError()
              << std::endl;
  return result;
}

static bool ListHiddenProcesses(HANDLE hDevice) {
  PROCESS_LIST_RESPONSE response = {0};
  DWORD bytesReturned = 0;

  BOOL result =
      DeviceIoControl(hDevice, IOCTL_LIST_HIDDEN_PROCESSES, NULL, 0, &response,
                      sizeof(response), &bytesReturned, NULL);
  if (!result) {
    std::cerr << "List hidden failed. Error: " << GetLastError() << std::endl;
    return false;
  }

  std::cout << "Hidden processes (" << response.Count << "): ";
  for (ULONG i = 0; i < response.Count && i < MAX_HIDDEN_PROCESSES; i++)
    std::cout << response.ProcessIds[i] << (i + 1 < response.Count ? ", " : "");
  std::cout << std::endl;
  return true;
}

int main(int argc, char *argv[]) {
  ULONG targetPid = 1234;

  if (argc > 1)
    targetPid = atoi(argv[1]);

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
    std::cout << "PING response: 0x" << std::hex << response.Data << std::dec
              << std::endl;
  } else {
    std::cerr << "PING failed. Error: " << GetLastError() << std::endl;
  }

  HideProcess(hDevice, targetPid);
  ListHiddenProcesses(hDevice);
  Sleep(10000);
  UnhideProcess(hDevice, targetPid);
  ListHiddenProcesses(hDevice);

  CloseHandle(hDevice);
  return 0;
}