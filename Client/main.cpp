#include "Shared.h"
#include "Loader.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <taskschd.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "taskschd.lib")

enum CmdId {
  CMD_PING = 1,
  CMD_HIDE_PROCESS,
  CMD_UNHIDE_PROCESS,
  CMD_LIST_PROCESSES,
  CMD_HIDE_THREAD,
  CMD_UNHIDE_THREAD,
  CMD_LIST_THREADS,
  CMD_FIND_TARGET,
  CMD_DELAY,
  CMD_PG_STATUS,
  CMD_ENABLE_TASK,
  CMD_DISABLE_TASK,
  CMD_EXIT = 0
};

enum TaskState { TASK_MISSING, TASK_DISABLED, TASK_ENABLED, TASK_ERROR };

struct ClientCommand {
  int id;
  const char* name;
  bool needsParam;
  const char* prompt;
};

static const ClientCommand kCommands[] = {
    {CMD_PING, "Ping", false, NULL},
    {CMD_HIDE_PROCESS, "Hide Process", true, "PID (Enter=target)"},
    {CMD_UNHIDE_PROCESS, "Unhide Process", true, "PID (Enter=target)"},
    {CMD_LIST_PROCESSES, "List Processes", false, NULL},
    {CMD_HIDE_THREAD, "Hide Thread", true, "TID (Enter=target)"},
    {CMD_UNHIDE_THREAD, "Unhide Thread", true, "TID (Enter=target)"},
    {CMD_LIST_THREADS, "List Threads", false, NULL},
    {CMD_FIND_TARGET, "Find Target", false, NULL},
    {CMD_DELAY, "Delay", true, "seconds"},
    {CMD_PG_STATUS, "PG Status", false, NULL},
    {CMD_ENABLE_TASK, "Enable Task", true, "task name (Enter=LongsDriver)"},
    {CMD_DISABLE_TASK, "Disable Task", true, "task name (Enter=LongsDriver)"},
};

static std::string g_targetName;
static ULONG g_targetPid = 0;
static ULONG g_targetTid = 0;
static std::wstring g_taskName = L"LongsDriver";

static void PrintMenu() {
  std::cout << "\n=== LongsDriver ===\n";
  if (g_targetPid)
    std::cout << "Target: " << g_targetName << " PID=" << g_targetPid
              << " TID=" << g_targetTid << "\n";
  for (const auto& c : kCommands)
    std::cout << " [" << c.id << "] " << c.name
              << (c.needsParam ? " <value>" : "") << "\n";
  std::cout << " [0] Run & Exit\n";
  std::cout << "Select (comma separated): ";
}

static bool ParseSelection(const std::string& input, std::vector<int>& out) {
  std::stringstream ss(input);
  std::string token;
  while (std::getline(ss, token, ',')) {
    if (token.empty())
      continue;
    int v = strtol(token.c_str(), NULL, 10);
    if (v == CMD_EXIT)
      continue;
    for (const auto& c : kCommands)
      if (c.id == v) {
        out.push_back(v);
        break;
      }
  }
  return !out.empty();
}

static void FindTarget() {
  std::cout << "Process name: ";
  std::string name;
  std::getline(std::cin, name);
  if (name.empty())
    return;

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return;

  PROCESSENTRY32W pe = {sizeof(pe)};
  bool found = false;
  if (Process32FirstW(snap, &pe)) {
    do {
      char an[MAX_PATH] = {0};
      WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, an, sizeof(an), NULL,
                          NULL);
      std::string sname(an);
      for (auto& ch : sname)
        ch = (char)tolower(ch);
      std::string needle = name;
      for (auto& ch : needle)
        ch = (char)tolower(ch);
      // match "notepad" -> notepad.exe and exact name too
      std::string base = sname;
      size_t dot = base.find('.');
      if (dot != std::string::npos)
        base = base.substr(0, dot);
      if (sname.find(needle) != std::string::npos || base == needle) {
        if (!found) {
          found = true;
          g_targetName = sname;
          g_targetPid = pe.th32ProcessID;
        }
        std::cout << "  " << sname << " PID=" << pe.th32ProcessID << "\n";
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  if (!found) {
    std::cout << "  No matching process\n";
    return;
  }

  // First thread of the selected target.
  snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return;
  THREADENTRY32 te = {sizeof(te)};
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID == g_targetPid) {
        g_targetTid = te.th32ThreadID;
        break;
      }
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  std::cout << "  Target set: " << g_targetName << " PID=" << g_targetPid
            << " TID=" << g_targetTid << "\n";
}

static bool SendCtrl(HANDLE h, DWORD ioctl, const void* in, DWORD inLen) {
  DWORD ret = 0;
  return DeviceIoControl(h, ioctl, (void*)in, inLen, NULL, 0, &ret, NULL) != 0;
}

static void RunPing(HANDLE h) {
  DRIVER_RESPONSE r = {0};
  DWORD ret = 0;
  if (DeviceIoControl(h, IOCTL_PING, NULL, 0, &r, sizeof(r), &ret, NULL))
    std::cout << "  Ping -> 0x" << std::hex << r.Data << std::dec << "\n";
  else
    std::cout << "  Ping failed (0x" << std::hex << GetLastError() << std::dec
              << ")\n";
}

static void RunPgStatus(HANDLE h) {
  DRIVER_RESPONSE r = {0};
  DWORD ret = 0;
  if (DeviceIoControl(h, IOCTL_GET_PG_STATUS, NULL, 0, &r, sizeof(r), &ret,
                      NULL))
    std::cout << "  PatchGuard bypassed: "
              << (r.Data ? "YES (full mode)" : "NO (safe mode)") << "\n";
  else
    std::cout << "  PG status query failed (0x" << std::hex << GetLastError()
              << std::dec << ")\n";
}

static void PromptTaskName() {
  std::cout << "  Task name (Enter=LongsDriver): ";
  std::string line;
  std::getline(std::cin, line);
  if (!line.empty()) {
    int len = MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, NULL, 0);
    g_taskName.resize(len - 1);
    MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, &g_taskName[0], len);
  }
}

static std::string Narrow(const std::wstring& w) {
  if (w.empty())
    return std::string();
  int len = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
  std::string s(len - 1, 0);
  WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &s[0], len, NULL, NULL);
  return s;
}

static TaskState QueryTaskState(const std::wstring& name) {
  HRESULT coinit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
  bool needUninit = (coinit == S_OK);

  ITaskService* svc = NULL;
  HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                                IID_ITaskService, (void**)&svc);
  if (FAILED(hr)) {
    if (needUninit)
      CoUninitialize();
    return TASK_ERROR;
  }

  TaskState state = TASK_ERROR;
  hr = svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
  if (SUCCEEDED(hr)) {
    ITaskFolder* folder = NULL;
    hr = svc->GetFolder(_bstr_t(L"\\"), &folder);
    if (SUCCEEDED(hr)) {
      IRegisteredTask* task = NULL;
      hr = folder->GetTask(_bstr_t(name.c_str()), &task);
      if (SUCCEEDED(hr) && task) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if (SUCCEEDED(task->get_Enabled(&enabled)))
          state = enabled ? TASK_ENABLED : TASK_DISABLED;
        task->Release();
      } else {
        state = TASK_MISSING;
      }
      folder->Release();
    }
  }
  svc->Release();
  if (needUninit)
    CoUninitialize();
  return state;
}

static void ChangeTask(const std::wstring& name, bool enable) {
  std::string action = enable ? "enable" : "disable";
  std::string sName = Narrow(name);
  switch (QueryTaskState(name)) {
  case TASK_MISSING:
    std::cout << "  Task '" << sName << "' not found\n";
    return;
  case TASK_ENABLED:
    if (enable) {
      std::cout << "  Task '" << sName << "' already enabled, nothing to do\n";
      return;
    }
    break;
  case TASK_DISABLED:
    if (!enable) {
      std::cout << "  Task '" << sName
                << "' already disabled, nothing to do\n";
      return;
    }
    break;
  case TASK_ERROR:
    std::cout << "  [warn] Could not query task state, attempting " << action
              << " anyway\n";
    break;
  }

  std::cout << "  " << action << " task '" << sName << "'\n";
  std::wstring cmdline =
      L"schtasks /Change /TN \"" + name + L"\" " + (enable ? L"/ENABLE"
                                                          : L"/DISABLE");
  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi = {0};
  std::wstring cmdBuf = cmdline;
  DWORD code = 0;
  if (CreateProcessW(NULL, &cmdBuf[0], NULL, NULL, FALSE, CREATE_NO_WINDOW,
                     NULL, NULL, &si, &pi)) {
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    std::cout << "  schtasks exit " << code << "\n";
  } else {
    std::cout << "  schtasks launch failed (0x" << std::hex << GetLastError()
              << std::dec << ")\n";
  }
}

static void RunProcessList(HANDLE h) {
  PROCESS_LIST_RESPONSE resp = {0};
  DWORD ret = 0;
  if (DeviceIoControl(h, IOCTL_LIST_HIDDEN_PROCESSES, NULL, 0, &resp,
                      sizeof(resp), &ret, NULL)) {
    std::cout << "  Hidden: " << resp.Count;
    for (ULONG i = 0; i < resp.Count; i++)
      std::cout << " " << resp.ProcessIds[i];
    std::cout << "\n";
  }
}

static void RunThreadList(HANDLE h) {
  THREAD_LIST_RESPONSE resp = {0};
  DWORD ret = 0;
  if (DeviceIoControl(h, IOCTL_LIST_HIDDEN_THREADS, NULL, 0, &resp,
                      sizeof(resp), &ret, NULL)) {
    std::cout << "  Hidden: " << resp.Count;
    for (ULONG i = 0; i < resp.Count; i++)
      std::cout << " " << resp.ThreadIds[i];
    std::cout << "\n";
  }
}

static void WarnIfConflict(const std::vector<ULONG>& hideP,
                           const std::vector<ULONG>& unhideP,
                           const std::vector<ULONG>& hideT,
                           const std::vector<ULONG>& unhideT) {
  for (ULONG p : unhideP) {
    bool paired = false;
    for (ULONG h : hideP)
      paired |= (h == p);
    if (!paired)
      std::cout << "  [warn] Unhide " << p << " without matching Hide\n";
    else
      std::cout << "  [warn] Hide+Unhide same PID " << p << "\n";
  }
  for (ULONG t : unhideT) {
    bool paired = false;
    for (ULONG h : hideT)
      paired |= (h == t);
    if (!paired)
      std::cout << "  [warn] Unhide " << t << " without matching Hide\n";
    else
      std::cout << "  [warn] Hide+Unhide same TID " << t << "\n";
  }
}

int wmain(int argc, wchar_t* argv[]) {
  std::vector<std::wstring> args;
  for (int i = 1; i < argc; ++i)
    args.push_back(argv[i]);

  std::cout << "Opening LongsDriver\n";
  HANDLE hDevice = OpenDriver(args);

  if (hDevice == INVALID_HANDLE_VALUE) {
    std::cerr << "Cannot open driver" << std::endl;
    return 1;
  }

  std::cout << "Connected\n";

  for (;;) {
    PrintMenu();

    std::string sel;
    std::getline(std::cin, sel);
    if (sel.empty())
      continue;
    if (sel == "0")
      break;

    std::vector<int> cmds;
    if (!ParseSelection(sel, cmds))
      continue;

    std::vector<ULONG> params(cmds.size(), 0);
    std::vector<ULONG> hideP, unhideP, hideT, unhideT;

    for (size_t i = 0; i < cmds.size(); i++) {
      const ClientCommand* cc = NULL;
      for (const auto& c : kCommands)
        if (c.id == cmds[i])
          cc = &c;
      if (!cc)
        continue;

      if (cmds[i] == CMD_FIND_TARGET) {
        FindTarget();
        params[i] = g_targetPid;
        continue;
      }

      if (cmds[i] == CMD_ENABLE_TASK || cmds[i] == CMD_DISABLE_TASK) {
        PromptTaskName();
        continue;
      }

      if (cc->needsParam) {
        std::cout << "  " << cc->prompt << ": ";
        std::string line;
        std::getline(std::cin, line);
        if (!line.empty()) {
          params[i] = strtoul(line.c_str(), NULL, 0);
        } else if (cmds[i] == CMD_HIDE_PROCESS ||
                   cmds[i] == CMD_UNHIDE_PROCESS) {
          params[i] = g_targetPid ? g_targetPid : GetCurrentProcessId();
        } else {
          params[i] = g_targetTid ? g_targetTid : GetCurrentThreadId();
        }
        if (cmds[i] == CMD_HIDE_PROCESS)
          hideP.push_back(params[i]);
        else if (cmds[i] == CMD_UNHIDE_PROCESS)
          unhideP.push_back(params[i]);
        else if (cmds[i] == CMD_HIDE_THREAD)
          hideT.push_back(params[i]);
        else if (cmds[i] == CMD_UNHIDE_THREAD)
          unhideT.push_back(params[i]);
      }
    }

    WarnIfConflict(hideP, unhideP, hideT, unhideT);

    std::cout << "--- Executing ---\n";
    for (size_t i = 0; i < cmds.size(); i++) {
      switch (cmds[i]) {
      case CMD_PING:
        RunPing(hDevice);
        break;
      case CMD_HIDE_PROCESS: {
        PROCESS_REQUEST req = {params[i]};
        std::cout << "  Hide Process " << params[i] << " -> "
                  << (SendCtrl(hDevice, IOCTL_HIDE_PROCESS, &req, sizeof(req))
                          ? "ok"
                          : "failed")
                  << "\n";
        break;
      }
      case CMD_UNHIDE_PROCESS: {
        PROCESS_REQUEST req = {params[i]};
        std::cout << "  Unhide Process " << params[i] << " -> "
                  << (SendCtrl(hDevice, IOCTL_UNHIDE_PROCESS, &req, sizeof(req))
                          ? "ok"
                          : "failed")
                  << "\n";
        break;
      }
      case CMD_LIST_PROCESSES:
        RunProcessList(hDevice);
        break;
      case CMD_HIDE_THREAD: {
        THREAD_REQUEST req = {params[i]};
        std::cout << "  Hide Thread " << params[i] << " -> "
                  << (SendCtrl(hDevice, IOCTL_HIDE_THREAD, &req, sizeof(req))
                          ? "ok"
                          : "failed")
                  << "\n";
        break;
      }
      case CMD_UNHIDE_THREAD: {
        THREAD_REQUEST req = {params[i]};
        std::cout << "  Unhide Thread " << params[i] << " -> "
                  << (SendCtrl(hDevice, IOCTL_UNHIDE_THREAD, &req, sizeof(req))
                          ? "ok"
                          : "failed")
                  << "\n";
        break;
      }
      case CMD_LIST_THREADS:
        RunThreadList(hDevice);
        break;
      case CMD_PG_STATUS:
        RunPgStatus(hDevice);
        break;
      case CMD_ENABLE_TASK:
        ChangeTask(g_taskName, true);
        break;
      case CMD_DISABLE_TASK:
        ChangeTask(g_taskName, false);
        break;
      case CMD_DELAY:
        std::cout << "  Sleeping " << params[i] << "s\n";
        Sleep(params[i] * 1000);
        break;
      case CMD_FIND_TARGET:
        break; // handled during collection
      default:
        break;
      }
    }
    std::cout << "--- Done ---\n";
  }

  CloseHandle(hDevice);
  return 0;
}