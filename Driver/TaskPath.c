#include "TaskInternal.h"

NTSTATUS TaskImagePathToDos(PUNICODE_STRING imagePath,
                            PUNICODE_STRING outPath) {
  ULONG chars = imagePath->Length / sizeof(WCHAR);
  NTSTATUS status;

  outPath->Buffer = NULL;
  outPath->Length = 0;
  outPath->MaximumLength = 0;

  if (chars < 8 || RtlEqualMemory(imagePath->Buffer, L"\\Device\\",
                                  8 * sizeof(WCHAR)) == FALSE)
    return STATUS_UNSUCCESSFUL;

  ULONG k = 8;
  for (; k < chars; k++)
    if (imagePath->Buffer[k] == L'\\')
      break;
  if (k >= chars)
    return STATUS_UNSUCCESSFUL;

  if (k - 8 >= 16)
    return STATUS_UNSUCCESSFUL;
  WCHAR volBuf[16];
  RtlCopyMemory(volBuf, imagePath->Buffer + 8, (k - 8) * sizeof(WCHAR));
  volBuf[k - 8] = L'\0';

  PIO_GET_DEVICE_OBJECT_POINTER getDeviceObject =
      (PIO_GET_DEVICE_OBJECT_POINTER)ResolveExportByWChar(
          L"IoGetDeviceObjectPointer");
  PRTL_VOLUME_DEVICE_TO_DOS_NAME volumeToDos =
      (PRTL_VOLUME_DEVICE_TO_DOS_NAME)ResolveExportByWChar(
          L"RtlVolumeDeviceToDosName");
  if (getDeviceObject == NULL || volumeToDos == NULL) {
    DbgPrint("[LongsDriver] ImagePathToDos: resolver missing\n");
    return STATUS_PROCEDURE_NOT_FOUND;
  }

  UNICODE_STRING volName;
  RtlInitUnicodeString(&volName, volBuf);

  PFILE_OBJECT fileObject = NULL;
  PDEVICE_OBJECT deviceObject = NULL;
  status = getDeviceObject(&volName, FILE_READ_ATTRIBUTES, &fileObject,
                           &deviceObject);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ImagePathToDos: IoGetDeviceObjectPointer(%wZ) "
             "failed 0x%X\n",
             &volName, status);
    return status;
  }

  PDEVICE_OBJECT volumeObj = deviceObject;
  if (deviceObject->Vpb != NULL && deviceObject->Vpb->DeviceObject != NULL)
    volumeObj = deviceObject->Vpb->DeviceObject;
  UNICODE_STRING dosName;
  RtlInitEmptyUnicodeString(&dosName, NULL, 0);
  status = volumeToDos(volumeObj, &dosName);
  ObDereferenceObject(fileObject);
  if (NT_SUCCESS(status)) {
    DbgPrint("[LongsDriver] ImagePathToDos: volume \"%wZ\" -> dos \"%wZ\"\n",
             &volName, &dosName);
  } else {
    DbgPrint("[LongsDriver] ImagePathToDos: RtlVolumeDeviceToDosName failed "
             "0x%X\n",
             status);
  }
  if (!NT_SUCCESS(status))
    return status;

  ULONG dosChars = dosName.Length / sizeof(WCHAR);
  if (dosChars < 3 || dosName.Buffer == NULL) {
    status = STATUS_UNSUCCESSFUL;
    goto done;
  }

  ULONG restChars = chars - k;
  ULONG total = (2 + restChars) * sizeof(WCHAR);
  outPath->Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, total + sizeof(WCHAR),
                                    TASK_POOL_TAG);
  if (outPath->Buffer == NULL) {
    status = STATUS_INSUFFICIENT_RESOURCES;
    goto done;
  }
  outPath->Buffer[0] = dosName.Buffer[dosChars - 2]; // drive letter
  outPath->Buffer[1] = L':';
  RtlCopyMemory(outPath->Buffer + 2, imagePath->Buffer + k,
                restChars * sizeof(WCHAR));
  outPath->Buffer[2 + restChars] = L'\0';
  outPath->Length = (USHORT)total;
  outPath->MaximumLength = (USHORT)(total + sizeof(WCHAR));
  status = STATUS_SUCCESS;

done:
  RtlFreeUnicodeString(&dosName);
  return status;
}