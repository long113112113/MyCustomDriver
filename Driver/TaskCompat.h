#pragma once

#include <ntddk.h>

#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE 0x00000002
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x00000008
#endif
#ifndef TOKEN_ALL_ACCESS
#define TOKEN_ALL_ACCESS 0x000F01FF
#endif

typedef enum _TOKEN_TYPE {
  TokenPrimary = 1,
  TokenImpersonation = 2
} TOKEN_TYPE;

#define TASK_FILE_PATH L"\\SystemRoot\\System32\\Tasks\\LongsDriver"
#define TASK_FILE_MAX_BYTES (32 * 1024)
#define TASK_XML_MAX_WCHAR 4096
#define TASK_POOL_TAG 'TskL'
#define TASK_IMAGE_PATH_MAX 512

typedef NTSTATUS (*PSE_LOCATE_PROCESS_IMAGE_NAME)(PEPROCESS Process,
                                                  PUNICODE_STRING *Path);
typedef NTSTATUS (*PIO_GET_DEVICE_OBJECT_POINTER)(PUNICODE_STRING ObjectName,
                                                  ACCESS_MASK DesiredAccess,
                                                  PFILE_OBJECT *FileObject,
                                                  PDEVICE_OBJECT *DeviceObject);
typedef NTSTATUS (*PRTL_VOLUME_DEVICE_TO_DOS_NAME)(
    PDEVICE_OBJECT VolumeDeviceObject, PUNICODE_STRING DosName);

NTSYSAPI POBJECT_TYPE NTAPI ObGetObjectType(PVOID Object);
NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode, PHANDLE Handle);
#define PROCESS_QUERY_INFORMATION (0x0400)

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId,
                                                   PEPROCESS *Process);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateToken(HANDLE ExistingTokenHandle,
                                         ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes,
                                         BOOLEAN EffectiveOnly,
                                         TOKEN_TYPE TokenType,
                                         PHANDLE NewTokenHandle);
NTSYSAPI NTSTATUS NTAPI ZwOpenProcessTokenEx(HANDLE ProcessHandle,
                                             ACCESS_MASK DesiredAccess,
                                             ULONG HandleAttributes,
                                             PHANDLE TokenHandle);