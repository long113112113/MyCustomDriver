#include "WskClient.h"
#include <wsk.h>

#define WSK_POOL_TAG 'kWsW'

//
// ---------------------------------------------------------------------------
// Connection target - EDIT THESE
// ---------------------------------------------------------------------------
//
// Host machine as seen from the VMware guest. The driver dials this over the
// normal TCP/IP stack of the guest, so the NAT translation VMware performs on
// the way out is handled by Windows and not by anything here.
//
// WSK_PROBE_HOST is a placeholder: 203.0.113.10 is RFC 5737 TEST-NET-3, a
// documentation range that nothing routes, so a probe against it fails at the
// connect step. Replace it with the real address before testing.
//
// For a first smoke test from a NAT guest, the fastest address to use is the
// host's own address on the vmnet8 adapter rather than its public one: VMware
// places the host at <vmnet8 subnet>.2 and the gateway at .1, so a listener
// bound to 0.0.0.0 on the host is reachable from the guest at that address with
// no port forwarding involved. That separates "does WSK work at all" from "is
// the public route and firewall set up". Substitute the public address once the
// NAT path itself needs verifying.
//
#define WSK_PROBE_HOST "203.0.113.10"
#define WSK_PROBE_PORT 8080

//
// Line sent to the host. A bare newline-delimited token, so a listener can be
// answered with `nc -l 8080` and whatever it echoes comes straight back.
//
#define WSK_PROBE_REQUEST "PING\n"

//
// Per-step budget. Four of these is the worst case for one probe, which is why
// each step is timed separately rather than the whole sequence: a probe that
// fails on connect should not also have to wait out send, receive and
// disconnect.
//
#define WSK_PROBE_STEP_TIMEOUT_MS 5000

//
// Bytes of the host's answer kept for logging, including the terminating NUL.
// The probe asks for WSK_PROBE_READ_MAX on the wire, which is larger, so a
// reply too long to keep here is detected and reported rather than silently
// cut at the logging boundary.
//
#define WSK_PROBE_MAX_REPLY 256

//
// Bytes asked for on the receive.
//
#define WSK_PROBE_READ_MAX 512

//
// Gap between probes. The driver runs this loop on its own once loaded, so no
// client is involved in triggering it and the host side just leaves its
// listener running.
//
#define WSK_PROBE_INTERVAL_MS 5000

//
// How long to wait for a provider before giving up and reporting rather than
// sitting in WskCaptureProviderNPI forever. A machine with no bound transport
// (a VM with no NIC, or one still enumerating adapters at boot) would
// otherwise never reach the probe loop, and the absence of any output would be
// indistinguishable from a working loop that silently fails.
//
#define WSK_CAPTURE_TIMEOUT_MS 30000

//
// ---------------------------------------------------------------------------
// Resolved WSK entry points. These live in netio.sys; see WskClient.h for why
// they are looked up at runtime rather than imported.
//
// wsk.h declares no prototype for the four registration entry points - it only
// documents them, and they exist solely as netio.sys exports. The signatures
// below are therefore transcribed rather than inherited, so they are worth
// re-checking against wsk.doc whenever the SDK is updated.
// ---------------------------------------------------------------------------
//
typedef NTSTATUS(WSKAPI *PFN_WSK_REGISTER_FN)(_In_ PWSK_CLIENT_NPI ClientNpi,
                                              _Out_ PWSK_REGISTRATION
                                                  Registration);

typedef NTSTATUS(WSKAPI *PFN_WSK_CAPTURE_PROVIDER_NPI_FN)(
    _In_ PWSK_REGISTRATION Registration,
    _In_ ULONG Timeout,
    _Out_ PWSK_PROVIDER_NPI ProviderNpi);

typedef VOID(WSKAPI *PFN_WSK_RELEASE_PROVIDER_NPI_FN)(
    _In_ PWSK_REGISTRATION Registration);

typedef VOID(WSKAPI *PFN_WSK_DEREGISTER_FN)(
    _In_ PWSK_REGISTRATION Registration);

//
// Must outlive the registration: WSK reads this after WskRegister returns, so a
// stack copy would be a use-after-return. Version 1.0 defines no client-wide
// event types, hence the NULL callback.
//
static WSK_CLIENT_DISPATCH g_WskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0,
                                                  NULL};

typedef struct _WSK_CLIENT_GLOBAL {
  PFN_WSK_REGISTER_FN Register;
  PFN_WSK_CAPTURE_PROVIDER_NPI_FN CaptureProviderNPI;
  PFN_WSK_RELEASE_PROVIDER_NPI_FN ReleaseProviderNPI;
  PFN_WSK_DEREGISTER_FN Deregister;

  PWSK_REGISTRATION Registration;
  PWSK_CLIENT Client;

  //
  // WSK hands out its provider table as CONST. Keeping that const here rather
  // than casting it away means the compiler still checks every call against the
  // dispatch table's real shape.
  //
  CONST WSK_PROVIDER_DISPATCH *Provider;

  //
  // Registered and ProviderCaptured are the two facts cleanup acts on, so they
  // are the only state kept. Everything else the module used to record for a
  // client-facing status query - init and capture status, provider version,
  // whether netio.sys had to be loaded - is now only ever logged, so storing it
  // would be writing state nothing reads.
  //
  BOOLEAN Registered;
  BOOLEAN ProviderCaptured;
  BOOLEAN WorkerStarted;

  KEVENT WorkerDone;
  KEVENT Stop;
  FAST_MUTEX Lock;
} WSK_CLIENT_GLOBAL;

static WSK_CLIENT_GLOBAL g_Wsk;

//
// ---------------------------------------------------------------------------
// Outcome of one probe.
//
// Private to this file since the IOCTL that used to hand it to a client is
// gone. Step statuses stay separate because a probe that connected but got no
// answer is a different fault from one that never connected, and the overall
// status alone cannot tell them apart - which is the whole point of the log
// line the probe loop prints.
//
typedef struct _WSK_PROBE_RESULT {
  // First failing step, or STATUS_SUCCESS when the round trip completed.
  NTSTATUS Status;
  NTSTATUS SocketStatus;
  NTSTATUS ConnectStatus;
  NTSTATUS SendStatus;
  NTSTATUS ReceiveStatus;
  // 1 once the TCP handshake completed. Gates the disconnect.
  BOOLEAN Connected;
  ULONG BytesSent;
  ULONG BytesReceived;
  // 1 when the reply was longer than WSK_PROBE_MAX_REPLY and was cut short.
  BOOLEAN ReplyTruncated;
  // Local port the kernel bound for the connection, network byte order. This is
  // what the NAT gateway's mapping can be matched against.
  USHORT LocalPort;
  // Reply text, NUL terminated, for logging.
  CHAR Reply[WSK_PROBE_MAX_REPLY];
} WSK_PROBE_RESULT, *PWSK_PROBE_RESULT;

//
// ---------------------------------------------------------------------------
// IRP plumbing. Every WSK call takes an IRP as its completion vehicle, so each
// one is turned into a synchronous call by parking that IRP on an event.
// ---------------------------------------------------------------------------
//
typedef struct _WSK_CALL_CONTEXT {
  KEVENT Event;
  NTSTATUS Status;
  SIZE_T Information;
} WSK_CALL_CONTEXT, *PWSK_CALL_CONTEXT;

//
// IO_COMPLETION_ROUTINE returns NTSTATUS, not VOID, and must hand the IRP on
// with STATUS_CONTINUE_COMPLETION - this routine only observes the completion,
// it never owns it. Returning STATUS_MORE_PROCESSING_REQUIRED here would strand
// the IRP, and the wait would then hang until it timed out.
//
static NTSTATUS NTAPI WskCallComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                                      PVOID Context) {
  PWSK_CALL_CONTEXT ctx = (PWSK_CALL_CONTEXT)Context;

  UNREFERENCED_PARAMETER(DeviceObject);

  ctx->Status = Irp->IoStatus.Status;
  ctx->Information = Irp->IoStatus.Information;
  KeSetEvent(&ctx->Event, IO_NO_INCREMENT, FALSE);

  return STATUS_CONTINUE_COMPLETION;
}

static NTSTATUS WskBeginCall(PWSK_CALL_CONTEXT ctx, PIRP *outIrp) {
  PIRP irp;

  *outIrp = NULL;

  irp = IoAllocateIrp(1, POOL_FLAG_NON_PAGED);
  if (irp == NULL)
    return STATUS_INSUFFICIENT_RESOURCES;

  KeInitializeEvent(&ctx->Event, NotificationEvent, FALSE);
  ctx->Status = STATUS_SUCCESS;
  ctx->Information = 0;

  //
  // InvokeOnSuccess so an inline completion still reports through the context.
  // Inline completion is the normal case for the fast steps, and reading
  // Irp->IoStatus directly would race the routine. InvokeOnCancel is off: the
  // cancel path is a timeout, which the wait detects through its own return
  // value, and firing the routine there as well would only produce a second
  // spurious signal.
  //
  IoSetCompletionRoutine(irp, WskCallComplete, ctx, TRUE, TRUE, FALSE);

  *outIrp = irp;
  return STATUS_SUCCESS;
}

static NTSTATUS WskWaitForCall(PWSK_CALL_CONTEXT ctx, PIRP irp,
                               NTSTATUS callStatus, ULONG timeoutMs) {
  LARGE_INTEGER timeout;
  NTSTATUS waitStatus;

  if (callStatus == STATUS_PENDING) {
    timeout.QuadPart = -((LONGLONG)timeoutMs * 10000LL);

    //
    // Argument order here is (Object, WaitReason, WaitMode, Alertable, Timeout).
    // Alertable must be FALSE: a kernel thread waiting alertably would return
    // STATUS_ALERTED if an APC arrived while parked here, and that would be
    // indistinguishable from a real timeout.
    //
    waitStatus = KeWaitForSingleObject(&ctx->Event, Executive, KernelMode,
                                       FALSE, &timeout);
    if (waitStatus != STATUS_SUCCESS) {
      //
      // The caller is about to release the buffers this IRP points at, so the
      // cancellation has to be driven to completion before returning rather
      // than left in flight.
      //
      IoCancelIrp(irp);
      (void)KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, FALSE,
                                  NULL);
      return waitStatus;
    }
    return ctx->Status;
  }

  if (NT_SUCCESS(callStatus)) {
    //
    // Inline completion: WSK already finished the IRP, so the routine has run.
    // Polled without blocking so this is correct even mid-flight.
    //
    (void)KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, FALSE, NULL);
    return ctx->Status;
  }

  //
  // Hard failure: the IRP was never queued, so IoStatus is meaningless and the
  // call status is the real result.
  //
  return callStatus;
}

//
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
//
static PVOID WskResolveExport(PCWSTR name) {
  UNICODE_STRING routineName;

  RtlInitUnicodeString(&routineName, name);
  return MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS WskResolveEntryPoints(VOID) {
  g_Wsk.Register = (PFN_WSK_REGISTER_FN)WskResolveExport(L"WskRegister");
  g_Wsk.CaptureProviderNPI = (PFN_WSK_CAPTURE_PROVIDER_NPI_FN)WskResolveExport(
      L"WskCaptureProviderNPI");
  g_Wsk.ReleaseProviderNPI = (PFN_WSK_RELEASE_PROVIDER_NPI_FN)WskResolveExport(
      L"WskReleaseProviderNPI");
  g_Wsk.Deregister = (PFN_WSK_DEREGISTER_FN)WskResolveExport(L"WskDeregister");

  if (g_Wsk.Register == NULL || g_Wsk.CaptureProviderNPI == NULL ||
      g_Wsk.ReleaseProviderNPI == NULL || g_Wsk.Deregister == NULL) {
    return STATUS_NOT_FOUND;
  }
  return STATUS_SUCCESS;
}

//
// netio.sys is a system driver and is normally already mapped when a
// mapped-load driver runs, so this is a fallback rather than the expected path.
// Loading it explicitly covers the case where it is registered but not yet
// started. The lookup is retried regardless: a ZwLoadDriver that fails because
// the driver is already loaded still leaves a resolvable provider behind.
//
static BOOLEAN WskEnsureNetioLoaded(VOID) {
  UNICODE_STRING imagePath;

  if (g_Wsk.Register != NULL)
    return TRUE;

  //
  // ZwLoadDriver here is the kernel-mode export: it takes only the path, unlike
  // the two-argument form a user-mode loader uses. PASSIVE_LEVEL only, which
  // init and the capture worker both satisfy.
  //
  RtlInitUnicodeString(&imagePath, L"\\SystemRoot\\System32\\drivers\\netio.sys");
  (void)ZwLoadDriver(&imagePath);

  (void)WskResolveEntryPoints();
  return g_Wsk.Register != NULL;
}

//
// Dotted quad to the value S_un.S_addr expects. IPv4 network byte order is
// big-endian, so shifting the octets into place yields the right value directly
// and no byte-swap routine is needed.
//
static BOOLEAN WskParseIpv4(PCSTR text, PULONG outAddress) {
  ULONG octet[4];
  USHORT i;
  ULONG value;
  ULONG digits;

  if (text == NULL)
    return FALSE;

  for (i = 0; i < 4; i++) {
    value = 0;
    digits = 0;

    while (*text >= '0' && *text <= '9') {
      value = value * 10 + (ULONG)(*text - '0');
      if (++digits > 3 || value > 255)
        return FALSE;
      text++;
    }
    if (digits == 0)
      return FALSE;

    octet[i] = value;

    if (i < 3) {
      if (*text != '.')
        return FALSE;
      text++;
    }
  }

  if (*text != '\0')
    return FALSE;

  *outAddress = (octet[0] << 24) | (octet[1] << 16) | (octet[2] << 8) | octet[3];
  return TRUE;
}

static USHORT WskHtons(USHORT value) {
  return (USHORT)(((value & 0xFF) << 8) | (value >> 8));
}

//
// ---------------------------------------------------------------------------
// Worker: capture the provider once, then probe the host on a fixed interval
// for the lifetime of the module.
//
// One thread rather than two, because the probe cannot run before the capture
// completes and splitting them would only add a second thing to synchronise.
// ---------------------------------------------------------------------------
//
static NTSTATUS WskClientProbe(PWSK_PROBE_RESULT Result);

static VOID WskRunProbeLoop(VOID) {
  WSK_PROBE_RESULT report;
  LARGE_INTEGER interval;
  NTSTATUS status;

  interval.QuadPart = -((LONGLONG)WSK_PROBE_INTERVAL_MS * 10000LL);

  DbgPrint("[LongsDriver] WSK: probing %s:%u every %lu ms\n", WSK_PROBE_HOST,
           WSK_PROBE_PORT, (ULONG)WSK_PROBE_INTERVAL_MS);

  for (;;) {
    RtlZeroMemory(&report, sizeof(report));
    status = WskClientProbe(&report);

    if (NT_SUCCESS(status)) {
      DbgPrint("[LongsDriver] WSK: ok  sent %lu got %lu  local port %u  "
               "reply \"%s\"%s\n",
               report.BytesSent, report.BytesReceived,
               WskHtons(report.LocalPort),
               (report.Reply[0] != '\0') ? report.Reply : "<none>",
               report.ReplyTruncated ? " (truncated)" : "");
    } else {
      //
      // Only the step that failed is worth spelling out - the rest are all
      // zero on an early exit and just add noise to the log.
      //
      DbgPrint("[LongsDriver] WSK: FAILED 0x%X  (socket 0x%X connect 0x%X "
               "send 0x%X recv 0x%X)\n",
               status, report.SocketStatus, report.ConnectStatus,
               report.SendStatus, report.ReceiveStatus);
    }

    //
    // Sleeping on an event rather than KeDelayExecutionThread so a stop
    // request interrupts the wait instead of being held for up to a full
    // interval. STATUS_TIMEOUT is the normal path and simply means the next
    // tick is due.
    //
    status = KeWaitForSingleObject(&g_Wsk.Stop, Executive, KernelMode, FALSE,
                                   &interval);
    if (status == STATUS_SUCCESS) {
      DbgPrint("[LongsDriver] WSK: probe loop stopping\n");
      return;
    }
  }
}

static NTSTATUS NTAPI WskCaptureThread(PVOID StartContext) {
  WSK_PROVIDER_NPI providerNpi;
  LARGE_INTEGER captureTimeout;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(StartContext);

  RtlZeroMemory(&providerNpi, sizeof(providerNpi));
  captureTimeout.QuadPart = -((LONGLONG)WSK_CAPTURE_TIMEOUT_MS * 10000LL);

  //
  // A bounded wait, unlike the infinite one this used to use. A provider that
  // never appears has to become a reported state rather than a thread that
  // never returns, otherwise the driver looks alive but never probes and there
  // is nothing in the log to explain why.
  //
  status = g_Wsk.CaptureProviderNPI(g_Wsk.Registration, WSK_CAPTURE_TIMEOUT_MS,
                                    &providerNpi);

  ExAcquireFastMutex(&g_Wsk.Lock);

  if (NT_SUCCESS(status)) {
    g_Wsk.Client = providerNpi.Client;
    g_Wsk.Provider = providerNpi.Dispatch;
    g_Wsk.ProviderCaptured = TRUE;
    DbgPrint("[LongsDriver] WSK: provider NPI captured, version %u.%u\n",
             WSK_MAJOR_VERSION(providerNpi.Dispatch->Version),
             WSK_MINOR_VERSION(providerNpi.Dispatch->Version));
  } else {
    DbgPrint("[LongsDriver] WSK: no provider (0x%X) after %lu ms; probes will "
             "report STATUS_DEVICE_NOT_READY.\n",
             status, (ULONG)WSK_CAPTURE_TIMEOUT_MS);
  }

  ExReleaseFastMutex(&g_Wsk.Lock);

  //
  // Signalled before the probe loop, not after it. Cleanup waits on this to know
  // the capture is over; it is what lets a deregister racing a still-running
  // loop tell the two apart.
  //
  KeSetEvent(&g_Wsk.WorkerDone, IO_NO_INCREMENT, FALSE);

  if (NT_SUCCESS(status))
    WskRunProbeLoop();

  return STATUS_SUCCESS;
}

//
// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------
//
NTSTATUS WskClientInitialize(VOID) {
  WSK_CLIENT_NPI clientNpi;
  OBJECT_ATTRIBUTES attributes;
  UNICODE_STRING threadName;
  NTSTATUS status;
  HANDLE thread = NULL;

  ExInitializeFastMutex(&g_Wsk.Lock);
  KeInitializeEvent(&g_Wsk.WorkerDone, NotificationEvent, FALSE);
  KeInitializeEvent(&g_Wsk.Stop, NotificationEvent, FALSE);

  status = WskResolveEntryPoints();
  if (!NT_SUCCESS(status)) {
    if (WskEnsureNetioLoaded()) {
      DbgPrint("[LongsDriver] WSK: netio.sys was not mapped at init and was "
               "loaded on demand.\n");
    } else {
      DbgPrint("[LongsDriver] WSK: entry points not resolvable; WSK "
               "disabled.\n");
      return STATUS_NOT_FOUND;
    }
  }

  RtlZeroMemory(&clientNpi, sizeof(clientNpi));
  clientNpi.ClientContext = NULL;
  clientNpi.Dispatch = &g_WskClientDispatch;

  //
  // Inline, unlike the capture below: this only records the client and does not
  // wait on the network stack, so it cannot stall the entry.
  //
  status = g_Wsk.Register(&clientNpi, g_Wsk.Registration);

  ExAcquireFastMutex(&g_Wsk.Lock);
  if (NT_SUCCESS(status))
    g_Wsk.Registered = TRUE;
  ExReleaseFastMutex(&g_Wsk.Lock);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] WSK: WskRegister failed 0x%X; WSK disabled.\n",
             status);
    return status;
  }

  RtlInitUnicodeString(&threadName, L"\\LongsWskCapture");
  InitializeObjectAttributes(&attributes, &threadName,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL,
                             NULL);

  status = PsCreateSystemThread(&thread, 0, &attributes, NULL, NULL,
                                WskCaptureThread, NULL);
  if (!NT_SUCCESS(status) || thread == NULL) {
    DbgPrint("[LongsDriver] WSK: capture thread could not be started (0x%X).\n",
             status);
    if (thread != NULL)
      ZwClose(thread);

    //
    // No worker means nothing will ever capture, so drop the registration
    // again rather than leaving a handle WSK keeps on our behalf.
    //
    g_Wsk.Deregister(g_Wsk.Registration);

    ExAcquireFastMutex(&g_Wsk.Lock);
    g_Wsk.Registered = FALSE;
    ExReleaseFastMutex(&g_Wsk.Lock);
    return status;
  }

  ZwClose(thread);
  g_Wsk.WorkerStarted = TRUE;

  DbgPrint("[LongsDriver] WSK: registered, target %s:%u, probing every %lu ms "
           "with no client involved.\n",
           WSK_PROBE_HOST, WSK_PROBE_PORT, (ULONG)WSK_PROBE_INTERVAL_MS);
  return STATUS_SUCCESS;
}

VOID WskClientCleanup(VOID) {
  BOOLEAN mustWait;
  BOOLEAN captured;

  //
  // Break the interval wait first, so a worker sitting between two probes
  // returns promptly instead of the cleanup below having to wait out a full
  // interval.
  //
  if (g_Wsk.WorkerStarted) {
    KeSetEvent(&g_Wsk.Stop, IO_NO_INCREMENT, FALSE);
  }

  //
  // Decide and deregister in one critical section rather than testing the
  // flags unlocked. The worker publishes ProviderCaptured under the same lock,
  // so reading it outside would allow the worker to capture the NPI between the
  // test and the deregister - leaving a captured NPI on a registration that is
  // about to be torn down.
  //
  ExAcquireFastMutex(&g_Wsk.Lock);
  mustWait = g_Wsk.Registered && !g_Wsk.ProviderCaptured;
  if (mustWait) {
    //
    // Deregistering is what unblocks a worker parked in
    // WskCaptureProviderNPI: a capture waiting for a provider returns
    // STATUS_DEVICE_NOT_READY once WskDeregister runs. It has to happen before
    // the wait below, or the wait never ends.
    //
    g_Wsk.Deregister(g_Wsk.Registration);
    g_Wsk.Registered = FALSE;
  }
  ExReleaseFastMutex(&g_Wsk.Lock);

  if (mustWait && g_Wsk.WorkerStarted) {
    (void)KeWaitForSingleObject(&g_Wsk.WorkerDone, Executive, KernelMode, FALSE,
                                NULL);
  }

  //
  // A worker that already captured is inside the probe loop rather than inside
  // the capture call, so deregistering will not unblock it - the stop event
  // set above is what ends it. Wait for that before touching the registration.
  //
  if (g_Wsk.WorkerStarted && !mustWait) {
    (void)KeWaitForSingleObject(&g_Wsk.WorkerDone, Executive, KernelMode, FALSE,
                                NULL);
  }

  //
  // Release the NPI before deregistering, and never after: WSK tears the
  // registration down as it deregisters, so a release ordered behind it would
  // touch freed state.
  //
  ExAcquireFastMutex(&g_Wsk.Lock);
  captured = g_Wsk.ProviderCaptured;
  if (captured) {
    g_Wsk.ReleaseProviderNPI(g_Wsk.Registration);
    g_Wsk.ProviderCaptured = FALSE;
  }
  if (g_Wsk.Registered) {
    g_Wsk.Deregister(g_Wsk.Registration);
    g_Wsk.Registered = FALSE;
  }
  ExReleaseFastMutex(&g_Wsk.Lock);
}

static NTSTATUS WskClientProbe(PWSK_PROBE_RESULT Result) {
  PWSK_CLIENT client;
  CONST WSK_PROVIDER_DISPATCH *provider;
  PWSK_PROVIDER_CONNECTION_DISPATCH dispatch;
  PWSK_SOCKET socket;
  WSK_CALL_CONTEXT ctx;
  WSK_BUF buffer;
  SOCKADDR_INET remote;
  SOCKADDR_INET local;
  CHAR request[sizeof(WSK_PROBE_REQUEST)];
  PCHAR readBuffer;
  PIRP irp;
  PMDL mdl;
  ULONG hostOctet;
  ULONG replyCopy;
  NTSTATUS status;

  if (Result == NULL)
    return STATUS_INVALID_PARAMETER;

  RtlZeroMemory(Result, sizeof(*Result));

  socket = NULL;
  dispatch = NULL;
  readBuffer = NULL;
  irp = NULL;
  mdl = NULL;

  //
  // Snapshot under the lock, then release it. The whole probe must not be
  // serialized against the capture worker, and the captured NPI stays valid for
  // as long as this module holds it.
  //
  ExAcquireFastMutex(&g_Wsk.Lock);
  client = g_Wsk.Client;
  provider = g_Wsk.Provider;
  ExReleaseFastMutex(&g_Wsk.Lock);

  if (!g_Wsk.Registered || client == NULL || provider == NULL) {
    Result->Status = STATUS_DEVICE_NOT_READY;
    Result->SocketStatus = STATUS_DEVICE_NOT_READY;
    Result->ConnectStatus = STATUS_DEVICE_NOT_READY;
    Result->SendStatus = STATUS_DEVICE_NOT_READY;
    Result->ReceiveStatus = STATUS_DEVICE_NOT_READY;
    return STATUS_DEVICE_NOT_READY;
  }

  if (!WskParseIpv4(WSK_PROBE_HOST, &hostOctet)) {
    DbgPrint("[LongsDriver] WSK: WSK_PROBE_HOST is not a dotted quad: %s\n",
             WSK_PROBE_HOST);
    Result->Status = STATUS_INVALID_PARAMETER;
    Result->SocketStatus = STATUS_INVALID_PARAMETER;
    return STATUS_INVALID_PARAMETER;
  }

  RtlCopyMemory(request, WSK_PROBE_REQUEST, sizeof(request));

  //
  // Create the socket. AF_INET only: the guest talks to the host over IPv4, and
  // pinning the family here means nothing downstream has to cope with a v6
  // answer. No client dispatch table, because every step below waits on its own
  // IRP rather than relying on callbacks.
  //
  status = WskBeginCall(&ctx, &irp);
  if (!NT_SUCCESS(status)) {
    Result->Status = status;
    Result->SocketStatus = status;
    goto Finish;
  }

  status = provider->WskSocket(client, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                               WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL,
                               NULL, NULL, irp);
  Result->SocketStatus =
      WskWaitForCall(&ctx, irp, status, WSK_PROBE_STEP_TIMEOUT_MS);
  IoFreeIrp(irp);
  irp = NULL;

  if (!NT_SUCCESS(Result->SocketStatus) ||
      ctx.Information < sizeof(PWSK_SOCKET)) {
    if (NT_SUCCESS(Result->SocketStatus))
      Result->SocketStatus = STATUS_UNSUCCESSFUL;
    goto Finish;
  }

  socket = (PWSK_SOCKET)ctx.Information;

  //
  // A connection socket gets WSK_PROVIDER_CONNECTION_DISPATCH. In C the basic
  // table is an anonymous member, so its entries are reached through dispatch
  // itself rather than through a named "Basic" field.
  //
  dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch;

  RtlZeroMemory(&remote, sizeof(remote));
  remote.Ipv4.sin_family = AF_INET;
  remote.Ipv4.sin_port = WskHtons(WSK_PROBE_PORT);
  remote.Ipv4.sin_addr.S_un.S_addr = hostOctet;

  //
  // Connect.
  //
  status = WskBeginCall(&ctx, &irp);
  if (!NT_SUCCESS(status)) {
    Result->ConnectStatus = status;
    goto Finish;
  }

  status = dispatch->WskConnect(socket, (PSOCKADDR)&remote, 0, irp);
  Result->ConnectStatus =
      WskWaitForCall(&ctx, irp, status, WSK_PROBE_STEP_TIMEOUT_MS);
  IoFreeIrp(irp);
  irp = NULL;

  if (!NT_SUCCESS(Result->ConnectStatus))
    goto Finish;

  Result->Connected = 1;

  //
  // Ask which local port was assigned. The guest is behind NAT, so this is the
  // port the gateway will show in its mapping table and the only way to
  // correlate this probe with anything observed on the host. Failure is not
  // fatal - the probe still means something without it.
  //
  RtlZeroMemory(&local, sizeof(local));
  status = WskBeginCall(&ctx, &irp);
  if (NT_SUCCESS(status)) {
    status = dispatch->WskGetLocalAddress(socket, (PSOCKADDR)&local, irp);
    (void)WskWaitForCall(&ctx, irp, status, WSK_PROBE_STEP_TIMEOUT_MS);
    IoFreeIrp(irp);
    irp = NULL;
    if (NT_SUCCESS(ctx.Status) && local.Ipv4.sin_family == AF_INET)
      Result->LocalPort = local.Ipv4.sin_port;
  }

  //
  // Send the request. WSK passes the MDL straight to the transport, so it has
  // to describe nonpaged memory; the request lives on the kernel stack, which
  // qualifies.
  //
  status = WskBeginCall(&ctx, &irp);
  if (!NT_SUCCESS(status)) {
    Result->SendStatus = status;
    goto Finish;
  }

  mdl = IoAllocateMdl(request, sizeof(request) - 1, FALSE, FALSE, NULL);
  if (mdl == NULL) {
    status = STATUS_INSUFFICIENT_RESOURCES;
    IoFreeIrp(irp);
    irp = NULL;
    Result->SendStatus = status;
    goto Finish;
  }

  buffer.Mdl = mdl;
  buffer.Offset = 0;
  buffer.Length = sizeof(request) - 1;

  status = dispatch->WskSend(socket, &buffer, WSK_FLAG_NODELAY, irp);
  Result->SendStatus =
      WskWaitForCall(&ctx, irp, status, WSK_PROBE_STEP_TIMEOUT_MS);
  IoFreeIrp(irp);
  irp = NULL;
  IoFreeMdl(mdl);
  mdl = NULL;

  if (!NT_SUCCESS(Result->SendStatus))
    goto Finish;

  Result->BytesSent = (ULONG)ctx.Information;

  //
  // Receive the reply.
  //
  status = WskBeginCall(&ctx, &irp);
  if (!NT_SUCCESS(status)) {
    Result->ReceiveStatus = status;
    goto Finish;
  }

  readBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, WSK_PROBE_READ_MAX,
                                WSK_POOL_TAG);
  if (readBuffer == NULL) {
    status = STATUS_INSUFFICIENT_RESOURCES;
    IoFreeIrp(irp);
    irp = NULL;
    Result->ReceiveStatus = status;
    goto Finish;
  }

  RtlZeroMemory(readBuffer, WSK_PROBE_READ_MAX);

  mdl = IoAllocateMdl(readBuffer, WSK_PROBE_READ_MAX, FALSE, FALSE, NULL);
  if (mdl == NULL) {
    status = STATUS_INSUFFICIENT_RESOURCES;
    IoFreeIrp(irp);
    irp = NULL;
    Result->ReceiveStatus = status;
    goto Finish;
  }

  buffer.Mdl = mdl;
  buffer.Offset = 0;
  buffer.Length = WSK_PROBE_READ_MAX;

  status = dispatch->WskReceive(socket, &buffer, 0, irp);
  Result->ReceiveStatus =
      WskWaitForCall(&ctx, irp, status, WSK_PROBE_STEP_TIMEOUT_MS);
  IoFreeIrp(irp);
  irp = NULL;
  IoFreeMdl(mdl);
  mdl = NULL;

  if (!NT_SUCCESS(Result->ReceiveStatus))
    goto Finish;

  //
  // Information is what the transport actually delivered, capped at what was
  // asked for. Anything past what the log can hold is flagged rather than
  // dropped silently.
  //
  Result->BytesReceived = (ULONG)ctx.Information;
  if (Result->BytesReceived > WSK_PROBE_READ_MAX)
    Result->BytesReceived = WSK_PROBE_READ_MAX;

  replyCopy = Result->BytesReceived;
  if (replyCopy > WSK_PROBE_MAX_REPLY - 1) {
    replyCopy = WSK_PROBE_MAX_REPLY - 1;
    Result->ReplyTruncated = 1;
  }

  RtlCopyMemory(Result->Reply, readBuffer, replyCopy);
  Result->Reply[replyCopy] = '\0';

Finish:
  if (mdl != NULL)
    IoFreeMdl(mdl);
  if (readBuffer != NULL)
    ExFreePoolWithTag(readBuffer, WSK_POOL_TAG);
  if (irp != NULL)
    IoFreeIrp(irp);

  //
  // socket and dispatch are assigned together, so a non-NULL socket implies a
  // dispatch table; the extra check keeps the teardown honest if a provider ever
  // hands back a socket with no table rather than trusting that pairing.
  //
  if (socket != NULL && dispatch != NULL) {
    NTSTATUS disconnectStatus = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;
    WSK_CALL_CONTEXT tailCtx;
    PIRP tailIrp;

    //
    // Abortive disconnect. Graceful would wait for the peer's FIN, which a
    // half-open NAT mapping can turn into a wait out of proportion to a probe;
    // nothing here needs the peer's shutdown to be acknowledged.
    //
    if (Result->Connected) {
      WSK_BUF emptyBuffer;

      RtlZeroMemory(&emptyBuffer, sizeof(emptyBuffer));

      tailIrp = NULL;
      if (NT_SUCCESS(WskBeginCall(&tailCtx, &tailIrp))) {
        status = dispatch->WskDisconnect(socket, &emptyBuffer,
                                        WSK_FLAG_ABORTIVE, tailIrp);
        disconnectStatus = WskWaitForCall(&tailCtx, tailIrp, status,
                                          WSK_PROBE_STEP_TIMEOUT_MS);
        IoFreeIrp(tailIrp);
      } else {
        disconnectStatus = STATUS_INSUFFICIENT_RESOURCES;
      }
    }

    tailIrp = NULL;
    if (NT_SUCCESS(WskBeginCall(&tailCtx, &tailIrp))) {
      status = dispatch->WskCloseSocket(socket, tailIrp);
      closeStatus = WskWaitForCall(&tailCtx, tailIrp, status,
                                   WSK_PROBE_STEP_TIMEOUT_MS);
      IoFreeIrp(tailIrp);
    }
    //
    // Teardown failures are logged rather than folded into Status: the socket
    // is gone either way, and overwriting a successful round trip with a
    // cleanup complaint would misreport the probe.
    //
    if (!NT_SUCCESS(disconnectStatus) || !NT_SUCCESS(closeStatus)) {
      DbgPrint("[LongsDriver] WSK: teardown reported disconnect 0x%X close "
               "0x%X.\n",
               disconnectStatus, closeStatus);
    }
  }

  //
  // Overall result is the first step that failed, with the per-step statuses
  // left intact so the log says how far it got.
  //
  if (!NT_SUCCESS(Result->SocketStatus))
    Result->Status = Result->SocketStatus;
  else if (!NT_SUCCESS(Result->ConnectStatus))
    Result->Status = Result->ConnectStatus;
  else if (!NT_SUCCESS(Result->SendStatus))
    Result->Status = Result->SendStatus;
  else if (!NT_SUCCESS(Result->ReceiveStatus))
    Result->Status = Result->ReceiveStatus;
  else
    Result->Status = STATUS_SUCCESS;

  return Result->Status;
}