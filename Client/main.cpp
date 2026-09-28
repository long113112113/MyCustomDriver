#include "Shared.h"
#include "Loader.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <taskschd.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iostream>
// Link Task Scheduler COM (/link or pragma) without touching the project file.
#pragma comment(lib, "taskschd.lib")
#include <sstream>
#include <string>
#include <vector>

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
  CMD_AUTO_LOAD,
  CMD_PROTECT_PROCESS,
  CMD_UNPROTECT_PROCESS,
  CMD_LIST_PROTECTED,
  CMD_EXIT = 0
};

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
    {CMD_AUTO_LOAD, "Auto Load", false, NULL},
    {CMD_PROTECT_PROCESS, "Protect Process", true, "PID (Enter=target)"},
    {CMD_UNPROTECT_PROCESS, "Unprotect Process", true, "PID (Enter=target)"},
      {CMD_LIST_PROTECTED, "List Protected", false, NULL},
  };

static std::string g_targetName;
static ULONG g_targetPid = 0;
static ULONG g_targetTid = 0;
static bool g_autoEnabled = false;

static void PrintMenu() {
  std::cout << "\n=== LongsDriver ===\n";
  if (g_targetPid)
    std::cout << "Target: " << g_targetName << " PID=" << g_targetPid
              << " TID=" << g_targetTid << "\n";
  std::cout << "Auto load: " << (g_autoEnabled ? "ON" : "OFF") << "\n";
  for (const auto& c : kCommands) {
    std::cout << " [" << c.id << "] ";
    if (c.id == CMD_AUTO_LOAD)
      std::cout << (g_autoEnabled ? "Disable Auto Load" : "Enable Auto Load")
                << "\n";
    else
      std::cout << c.name << (c.needsParam ? " <value>" : "") << "\n";
  }
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

//
// Auto-load task state is managed entirely by the driver
// (Driver/TaskPersistence.c). Enable/disable/query ride one IOCTL.
//
static void RunTaskControl(HANDLE h, ULONG op) {
  TASK_REQUEST req = {op};
  DRIVER_RESPONSE r = {0};
  DWORD ret = 0;
  if (!DeviceIoControl(h, IOCTL_TASK_CONTROL, &req, sizeof(req), &r,
                       sizeof(r), &ret, NULL)) {
    std::cout << "  Task control IOCTL failed (0x" << std::hex << GetLastError()
              << std::dec << ")\n";
    return;
  }
  if (!NT_SUCCESS(r.Status)) {
    std::cout << "  Task control failed (status 0x" << std::hex << r.Status
              << std::dec << ")\n";
    return;
  }
  g_autoEnabled = (r.Data != 0);
  switch (op) {
  case TASK_OP_ENABLE:
    std::cout << "  Auto-load task enabled\n";
    break;
  case TASK_OP_DISABLE:
    std::cout << "  Auto-load task disabled\n";
    break;
  default:
    std::cout << "  Auto load: " << (g_autoEnabled ? "ON" : "OFF") << "\n";
    break;
  }
}

// The boot task relaunches us as SYSTEM after every reboot. When there is no
// console (the boot context), we end cleanly right after the driver is mapped.
static bool HasConsoleInput() {
  HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
  if (hIn == NULL || hIn == INVALID_HANDLE_VALUE)
    return false;
  DWORD mode = 0;
  return GetConsoleMode(hIn, &mode) != 0;
}

static ITaskDefinition *g_taskDef = NULL;

// Auto-load task registration via the Task Scheduler COM API. This replaces
// the earlier schtasks.exe child-process approach (which faulted) with an
// in-process COM call: no subprocess, no temp files, no redirected handles.
// Registering a SYSTEM-level task requires elevation; on already-registered
// machines this is a fast no-op.
static void EnsureTaskRegistered() {
  const wchar_t kTaskName[] = L"LongsDriver";
  HRESULT hr = 0;
  bool needUninit = false;
  bool done = false;

  hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  if (hr == S_OK || hr == S_FALSE)
    needUninit = true;

  ITaskService *svc = NULL;
  hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                        IID_ITaskService, (void **)&svc);
  if (FAILED(hr)) {
    std::cout << "  Could not reach Task Scheduler (hr 0x" << std::hex << hr
              << std::dec << ")\n";
    hr = 0;
    goto Out;
  }
  {
    VARIANT vEmpty = {0};
    vEmpty.vt = VT_EMPTY;
    hr = svc->Connect(vEmpty, vEmpty, vEmpty, vEmpty);
  }
  if (FAILED(hr))
    goto Out;

  {
    ITaskFolder *folder = NULL;
    BSTR bRoot = SysAllocString(L"\\");
    hr = bRoot != NULL ? svc->GetFolder(bRoot, &folder)
                       : E_OUTOFMEMORY;
    if (bRoot != NULL)
      SysFreeString(bRoot);
    if (FAILED(hr))
      goto Out;

    IRegisteredTask *existing = NULL;
    BSTR bName = SysAllocString(kTaskName);
    hr = bName != NULL ? folder->GetTask(bName, &existing)
                       : E_OUTOFMEMORY;
    if (bName != NULL)
      SysFreeString(bName);
    if (SUCCEEDED(hr)) {
      existing->Release();
      done = true; // already registered - no-op
      folder->Release();
      goto Out;
    }

    hr = svc->NewTask(0, &g_taskDef);
    if (FAILED(hr)) {
      folder->Release();
      goto Out;
    }

    {
      ITriggerCollection *trigs = NULL;
      if (SUCCEEDED(g_taskDef->get_Triggers(&trigs))) {
        ITrigger *trig = NULL;
        if (SUCCEEDED(trigs->Create(TASK_TRIGGER_BOOT, &trig)) &&
            trig != NULL)
          trig->Release();
        trigs->Release();
      }
    }

    {
      IActionCollection *acts = NULL;
      if (SUCCEEDED(g_taskDef->get_Actions(&acts))) {
        IAction *act = NULL;
        if (SUCCEEDED(acts->Create(TASK_ACTION_EXEC, &act)) && act != NULL) {
          IExecAction *exec = NULL;
          if (SUCCEEDED(
                  act->QueryInterface(IID_IExecAction, (void **)&exec)) &&
              exec != NULL) {
            wchar_t image[MAX_PATH] = {0};
            GetModuleFileNameW(NULL, image, MAX_PATH);
            BSTR path = SysAllocString(image);
            if (path != NULL)
              exec->put_Path(path);
            if (path != NULL)
              SysFreeString(path);
            exec->Release();
          }
          act->Release();
        }
        acts->Release();
      }
    }

    {
      IPrincipal *prin = NULL;
      if (SUCCEEDED(g_taskDef->get_Principal(&prin)) && prin != NULL) {
        BSTR sys = SysAllocString(L"S-1-5-18");
        if (sys != NULL)
          prin->put_UserId(sys);
        if (sys != NULL)
          SysFreeString(sys);
        prin->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        prin->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        prin->Release();
      }
    }

    {
      ITaskSettings *set = NULL;
      if (SUCCEEDED(g_taskDef->get_Settings(&set)) && set != NULL) {
        set->put_Hidden(VARIANT_TRUE);
        set->put_StartWhenAvailable(VARIANT_TRUE);
        set->Release();
      }
    }

    {
      IRegisteredTask *reg = NULL;
      BSTR bName = SysAllocString(kTaskName);
      VARIANT vEmpty = {0};
      vEmpty.vt = VT_EMPTY;
      hr = bName != NULL
               ? folder->RegisterTaskDefinition(
                     bName, g_taskDef, TASK_CREATE_OR_UPDATE, vEmpty, vEmpty,
                     TASK_LOGON_SERVICE_ACCOUNT, vEmpty, &reg)
               : E_OUTOFMEMORY;
      if (bName != NULL)
        SysFreeString(bName);
      if (SUCCEEDED(hr) && reg != NULL) {
        done = true;
        reg->Release();
        std::cout << "  Auto-register boot task: OK\n";
      }
      g_taskDef->Release();
      g_taskDef = NULL;
    }

    folder->Release();
    hr = 0;
  }

Out:
  if (svc != NULL)
    svc->Release();
  if (needUninit)
    CoUninitialize();

  if (!done && FAILED(hr)) {
    std::cout << "  Auto-register boot task needs an elevated prompt: run once"
              << "\n  as admin or use: schtasks /Create /TN LongsDriver /XML "
                 "C:\\Windows\\System32\\Tasks\\LongsDriver /F (hr 0x"
              << std::hex << hr << std::dec << ")\n";
  }
}

// Registration must never swallow the menu; guard it against unexpected
// faults. Standalone function: __try cannot live in a frame needing unwind.
static void RegisterTaskSafely() {
  __try {
    EnsureTaskRegistered();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    std::cout << "  Registration helper faulted (0x" << std::hex
              << GetExceptionCode() << std::dec << ")\n";
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

//
// Anti-kill: the driver strips terminate/VM/thread access from handles opened
// to these PIDs. Requires PG bypass - otherwise the driver answers
// STATUS_DEVICE_CONFIGURATION_ERROR and the command is refused.
//
static void RunProtect(HANDLE h, ULONG pid, bool protect) {
  PROCESS_REQUEST req = {pid};
  DRIVER_RESPONSE r = {0};
  DWORD ret = 0;
  const char* verb = protect ? "Protect" : "Unprotect";

  // Catch a mistyped or non-numeric PID here: the driver rejects PID <= 4 and
  // the NTSTATUS comes back to user mode as Win32 error 87, which is
  // indistinguishable from a buffer-size failure.
  if (pid <= SYSTEM_PROCESS_PID) {
    std::cout << "  " << verb << ": PID " << pid
              << " is not a user process (must be > "
              << SYSTEM_PROCESS_PID << "). Use Find Target first.\n";
    return;
  }

  std::cout << "  " << verb << " PID " << pid << " -> ";
  if (!DeviceIoControl(h, protect ? IOCTL_PROTECT_PROCESS
                                   : IOCTL_UNPROTECT_PROCESS,
                       &req, sizeof(req), &r, sizeof(r), &ret, NULL)) {
    DWORD err = GetLastError();
    std::cout << "failed (0x" << std::hex << err << std::dec << ")\n";
    std::cout << "    run \"List Protected\" to see why the callback is not "
                 "armed\n";
    return;
  }
  if (!NT_SUCCESS(r.Status)) {
    std::cout << "refused, NTSTATUS 0x" << std::hex << r.Status << std::dec;
    if (r.Status == (NTSTATUS)0xC00400A0)
      std::cout << " (PatchGuard bypass inactive - feature disabled)";
    std::cout << "\n";
    return;
  }
  std::cout << "ok\n";
}

static void RunProtectedList(HANDLE h) {
  PROTECT_STATUS_RESPONSE st = {0};
  DWORD ret = 0;

  if (DeviceIoControl(h, IOCTL_GET_PROTECT_STATUS, NULL, 0, &st, sizeof(st),
                      &ret, NULL)) {
    if (st.CallbackActive) {
      std::cout << "  Callback: ARMED (InitStatus 0x" << std::hex
                << st.InitStatus << std::dec << ", gate patch 0x" << st.GatePatchStatus
                << (st.GatePatchApplied ? ", applied" : ", NOT applied")
                << ")\n";
    } else {
      std::cout << "  Callback: DISARMED\n";
      std::cout << "    InitStatus = 0x" << std::hex << st.InitStatus
                << std::dec;
      if (st.InitStatus == (NTSTATUS)0xC0000182)
        std::cout << " STATUS_DEVICE_CONFIGURATION_ERROR"
                     " -> PatchGuard bypass inactive (safe mode)";
      else if (st.InitStatus == (NTSTATUS)0xC0000022)
        std::cout << " STATUS_ACCESS_DENIED"
                     " -> ntoskrnl refused the callback";
      else if (st.InitStatus == (NTSTATUS)0xC000000D)
        std::cout << " STATUS_INVALID_PARAMETER"
                     " -> ObRegisterCallbacks rejected the registration"
                     " (check the altitude string)";
      std::cout << "\n";

      //
      // ACCESS_DENIED on its own is ambiguous: it is what the gate returns
      // whether or not we managed to patch it. Report the patch result
      // separately so the two causes are not conflated.
      //
      std::cout << "    GatePatchStatus = 0x" << std::hex << st.GatePatchStatus
                << std::dec << " ";
      if (st.GatePatchApplied) {
        std::cout << "(patched, gate relaxed - refusal came from elsewhere)\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC0000059) {
        std::cout << "STATUS_REVISION_MISMATCH"
                  << " -> ntoskrnl bytes differ from the recorded signature,"
                     " patch refused; see DbgPrint for actual bytes\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC0000182) {
        std::cout << "STATUS_DEVICE_CONFIGURATION_ERROR"
                  << " -> patch declined on purpose (PatchGuard inactive)\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC0000225) {
        std::cout << "STATUS_NOT_FOUND"
                  << " -> ntoskrnl image base could not be resolved\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC0000184) {
        std::cout << "STATUS_INVALID_DEVICE_STATE"
                  << " -> not at PASSIVE_LEVEL when the patch was attempted\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC000000D) {
        std::cout << "STATUS_INVALID_PARAMETER"
                  << " -> target RVA lies outside the ntoskrnl image, so the"
                     " recorded signature is stale for this build\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xC0000005) {
        std::cout << "STATUS_ACCESS_VIOLATION"
                  << " -> write to ntoskrnl faulted, memory integrity is"
                     " enforcing\n";
      } else if (st.GatePatchStatus == (NTSTATUS)0xFFFFFFFF) {
        std::cout << "(apply never reached - PatchGuard bypass was inactive,"
                   " so registration was never attempted)\n";
      } else if (NT_SUCCESS(st.GatePatchStatus)) {
        std::cout << "(success, but already reverted - patch was applied then"
                     " rolled back)\n";
      } else {
        std::cout << "(see DbgPrint for the reason)\n";
      }
    }
  } else {
    std::cout << "  status query failed (0x" << std::hex << GetLastError()
              << std::dec << ")\n";
  }

  PROTECTED_PROCESS_LIST_RESPONSE resp = {0};
  if (DeviceIoControl(h, IOCTL_LIST_PROTECTED_PROCESSES, NULL, 0, &resp,
                      sizeof(resp), &ret, NULL)) {
      //
      // Separates "callback never ran" from "ran but the handle predates
      // protection" from "ran and stripped, yet the kill still worked".
      //
      std::cout << "  PreOp: total " << st.PreOpTotal << ", protected-hit "
                << st.PreOpProtectedHits << ", stripped "
                << st.PreOpStripped;
      if (st.PreOpTotal > 0 && st.PreOpProtectedHits == 0)
        std::cout << "  <- callback live but never saw a protected PID:"
                     " consumers reuse handles opened before protection";
      std::cout << "\n";

      std::cout << "  Protected: " << resp.Count;
    for (ULONG i = 0; i < resp.Count; i++)
      std::cout << " " << resp.ProcessIds[i];
    std::cout << "\n";
  }
}

//
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
  std::cout << "[build 2026-09-19.5]\n";
  HANDLE hDevice = OpenDriver(args);

  if (hDevice == INVALID_HANDLE_VALUE) {
    std::cerr << "Cannot open driver" << std::endl;
    return 1;
  }

  std::cout << "Connected\n";

  // Hand the driver our own Win32 path so the auto-load task starts this
  // exact image ("C:\...") instead of a \Device\ NT path the scheduler
  // refuses to launch.
  WCHAR imagePath[MAX_PATH] = {0};
  if (GetModuleFileNameW(NULL, imagePath, MAX_PATH) > 0) {
    DWORD tr = 0;
    if (DeviceIoControl(hDevice, IOCTL_TASK_SET_IMAGE_PATH, imagePath,
                        (DWORD)((wcslen(imagePath) + 1) * sizeof(WCHAR)), NULL,
                        0, &tr, NULL)) {
      std::wcout << "  Task image path: " << imagePath << L"\n";
    } else {
      std::cout << "  Set task image path failed (0x" << std::hex
                << GetLastError() << std::dec << ")\n";
    }
  }

  // The driver creates the auto-load task on first load and owns its state;
  // we only report it.
  RunTaskControl(hDevice, TASK_OP_QUERY);

  // When launched from the boot task there is no console, so we map the driver
  // and exit immediately; the menu is for the interactive session.
  if (!HasConsoleInput()) {
    std::cout << "Boot instance: driver loaded, ending cleanly.\n";
    freopen_s(NULL, "NUL", "r", stdin);
  } else {
    // One-time registration so the machine needs no manual schtasks step.
    // Wrapped so a helper failure can never swallow the menu.
    RegisterTaskSafely();
  }

  for (;;) {
    PrintMenu();

    std::string sel;
    std::getline(std::cin, sel);
    if (!std::cin)
      break; // EOF in the boot instance (SYSTEM) - exit cleanly.
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

      if (cc->needsParam) {
        std::cout << "  " << cc->prompt << ": ";
        std::string line;
        std::getline(std::cin, line);
        if (!line.empty()) {
          params[i] = strtoul(line.c_str(), NULL, 0);
        } else if (cmds[i] == CMD_HIDE_PROCESS ||
                   cmds[i] == CMD_UNHIDE_PROCESS ||
                   cmds[i] == CMD_PROTECT_PROCESS ||
                   cmds[i] == CMD_UNPROTECT_PROCESS) {
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
      case CMD_PROTECT_PROCESS:
        RunProtect(hDevice, params[i], true);
        break;
      case CMD_UNPROTECT_PROCESS:
        RunProtect(hDevice, params[i], false);
        break;
      case CMD_LIST_PROTECTED:
        RunProtectedList(hDevice);
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
      case CMD_AUTO_LOAD:
        RunTaskControl(hDevice, g_autoEnabled ? TASK_OP_DISABLE : TASK_OP_ENABLE);
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