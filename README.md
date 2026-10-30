# LongsDriver

A Windows x64 kernel-mode research driver. Built as part of a rootkit research internship.

> **For educational / research purposes only. Use in a VM.**

---

## How It Works

`Client.exe` is a **self-contained single binary**. It embeds the kernel driver (`LongsDriver.sys`) internally as an RC4-encrypted, deflate-compressed resource. When run on the target machine (VM), it automatically:

1. Decrypts and inflates the embedded driver image in memory
2. Loads the vulnerable Intel network adapter driver as a mapper (kdmapper technique)
3. Manually maps `LongsDriver.sys` into the kernel — bypassing DSE (Driver Signature Enforcement)
4. Unloads the Intel driver and opens a handle to `\\.\LongsDriver`
5. Shows an interactive menu to control all driver features

No separate `LongsDriver.sys` file is needed on the target machine.

---

## Architecture

| Component | Description |
|---|---|
| `Driver/` | Kernel-mode driver (`LongsDriver.sys`) |
| `Client/` | User-mode client (`Client.exe`) — embeds the driver, loads it, sends IOCTLs |
| `Client/loader/` | kdmapper-based manual mapper (Intel vulnerable driver technique) |
| `HostListener/` | Host-side listener utility |
| `NetProbe/` | Network inspection DLL injected by the driver |
| `NetProbeLoader/` | Loader DLL for NetProbe |
| `Shared/` | Shared IOCTL codes and structures between driver and client |

---

## Features

- **PatchGuard bypass** — disables PG DPCs, patches Context7/MCA detonators, arms NX barricade on load
- **Process DKOM** — hide / unhide processes from the system process list via EPROCESS list unlinking
- **Thread DKOM** — hide / unhide threads
- **Process protection** — ObRegisterCallbacks-based anti-kill for arbitrary PIDs
- **Privilege escalation** — swap caller thread token to SYSTEM (`SelfElevate`)
- **ETW-TI suppression** — patches the ETW Threat Intelligence provider to blind kernel telemetry
- **Persistence** — creates a Windows Task Scheduler task to auto-reload the client on boot
- **NetProbe injection** — reflectively injects `NetProbe.dll` into `explorer.exe` via kernel APC

---

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with **KMDF / WDK** workload
- WDK (Windows Driver Kit) matching your VS version
- Administrator privileges to run `Client.exe`

---

## Build

The build is a **two-step process** managed by [`embed-driver.ps1`](Client/embed-driver.ps1):

1. Build `LongsDriver.sys` (the kernel driver)
2. Encrypt + compress the `.sys` and embed it into `Client.exe` as a resource
3. Rebuild `Client.exe` with the new embedded blob

### Quick build (recommended)

```powershell
# From the repo root — builds driver, generates blob, rebuilds client
.\Client\embed-driver.ps1
```

### Manual driver-only build

```bat
& "D:\VS2022\MSBuild\Current\Bin\MSBuild.exe" ^
    "D:\PJ\KMDF Driver\Driver\KMDF Driver.vcxproj" ^
    /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal
```

> [!IMPORTANT]
> Building `Driver\KMDF Driver.vcxproj` alone **does not** re-embed the driver into `Client.exe`. Always run `embed-driver.ps1` (or build the full solution) so the client contains the latest driver image.

### Output

`x64\Release\Client.exe` — the single self-contained binary to copy to the VM.

---

## IOCTL Reference

| IOCTL | Direction | Description |
|---|---|---|
| `IOCTL_PING` | → `DRIVER_RESPONSE` | Liveness check (returns `0xDEADBEEF`) |
| `IOCTL_GET_PG_STATUS` | → `DRIVER_RESPONSE` | PatchGuard bypass status |
| `IOCTL_HIDE_PROCESS` | `PROCESS_REQUEST` → | Unlink process from EPROCESS list |
| `IOCTL_UNHIDE_PROCESS` | `PROCESS_REQUEST` → | Restore process link |
| `IOCTL_LIST_HIDDEN_PROCESSES` | → `PROCESS_LIST_RESPONSE` | Enumerate hidden PIDs |
| `IOCTL_HIDE_THREAD` | `THREAD_REQUEST` → | Unlink thread from ETHREAD list |
| `IOCTL_UNHIDE_THREAD` | `THREAD_REQUEST` → | Restore thread link |
| `IOCTL_LIST_HIDDEN_THREADS` | → `THREAD_LIST_RESPONSE` | Enumerate hidden TIDs |
| `IOCTL_PROTECT_PROCESS` | `PROCESS_REQUEST` → | Register ObCallback anti-kill |
| `IOCTL_UNPROTECT_PROCESS` | `PROCESS_REQUEST` → | Remove ObCallback |
| `IOCTL_LIST_PROTECTED_PROCESSES` | → `PROTECTED_PROCESS_LIST_RESPONSE` | List protected PIDs |
| `IOCTL_ELEVATE_SELF` | → `ELEVATE_STATUS_RESPONSE` | Elevate caller to SYSTEM |
| `IOCTL_UNELEVATE_SELF` | → `ELEVATE_STATUS_RESPONSE` | Restore original token |
| `IOCTL_QUERY_ELEVATION` | → `ELEVATE_STATUS_RESPONSE` | Query current elevation state |
| `IOCTL_ETWTI_STATUS` | → `ETWTI_STATUS_RESPONSE` | ETW-TI patch status |
| `IOCTL_TASK_CONTROL` | `TASK_REQUEST` → `DRIVER_RESPONSE` | Create / delete boot task |
| `IOCTL_TASK_SET_IMAGE_PATH` | `WCHAR[]` → | Set client image path for boot task |

---

## Project Structure

```
KMDF Driver/
├── Driver/           # Kernel driver source (C)
├── Client/           # User-mode client (C++)
│   └── loader/       # kdmapper-based manual mapper
├── HostListener/     # Host listener utility
├── NetProbe/         # Injected network probe DLL
├── NetProbeLoader/   # Loader for NetProbe
├── Shared/           # Shared headers (IOCTL codes, structs)
├── Symbols/          # PDB / symbol helpers
├── Tools/            # Auxiliary scripts (Secure Boot audit, etc.)
├── VM_Logs/          # Captured VM artifacts for analysis
└── x64/              # Build output
```

---

## Disclaimer

This project is for **security research and education only**. Do not use on systems you do not own or have explicit permission to test.

