#include <ntifs.h>
#include <windef.h>
#include "..\CR3\CR3.c"
#include "../Memory/Memory.c"
#include "../Utilities/Utils.h"

UNICODE_STRING name, link;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBigPoolInformation = 0x42,
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

typedef struct _SYSTEM_BIGPOOL_ENTRY {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _ReadWrite {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
    BOOLEAN Write;
} ReadWrite, * pReadWrite;

typedef struct _BaseAddress {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG* Address;
} BaseAddress, * pBaseAddress;

typedef struct _GuardedRegion {
    INT32 Security;
    ULONGLONG* Address;
} GuardedRegion, * pGuardedRegion;

UINT64 TranslateLinear(UINT64 directoryTableBase, UINT64 virtualAddress) {
    directoryTableBase &= ~0xf;

    UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
    UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
    UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
    UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
    UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

    SIZE_T readsize = 0;
    UINT64 pdpe = 0;
    ReadMemory(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1)
        return 0;

    UINT64 pde = 0;
    ReadMemory(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
    if (~pde & 1)
        return 0;

    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

    UINT64 pteAddr = 0;
    ReadMemory(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
    if (~pteAddr & 1)
        return 0;

    if (pteAddr & 0x80)
        return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

    virtualAddress = 0;
    ReadMemory(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
    virtualAddress &= PMASK;

    if (!virtualAddress)
        return 0;

    return virtualAddress + pageOffset;
}

ULONG64 FindMin(INT32 a, SIZE_T b) {
    return ((a) < (b)) ? (a) : (b);
}

NTSTATUS HandleReadWrite(pReadWrite x) {
    if (x->ProcessId != CODE_SECURITY)
        return STATUS_UNSUCCESSFUL;

    if (!x->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS process = NULL;
    PsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
    if (!process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG process_base = GetCR3(process);
    ObDereferenceObject(process);

    SIZE_T total_size = x->Size;

    INT64 physical_address = TranslateLinear(process_base, (ULONG64)x->Address);
    if (!physical_address)
        return STATUS_UNSUCCESSFUL;

    ULONG64 final_size = FindMin(PAGE_SIZE - (physical_address & 0xFFF), total_size);
    SIZE_T bytes_transferred = 0;

    if (x->Write) {
        WriteMemory(PVOID(physical_address), (PVOID)x->Buffer, final_size, &bytes_transferred);
    }
    else {
        WriteMemory(PVOID(physical_address), (PVOID)x->Buffer, final_size, &bytes_transferred);
    }

    return STATUS_SUCCESS;
}

NTSTATUS GetBaseAddress(pBaseAddress x) {
    if (x->Security != CODE_SECURITY)
        return STATUS_UNSUCCESSFUL;

    if (!x->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS process = NULL;
    PsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
    if (!process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);
    if (!image_base)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(x->Address, &image_base, sizeof(image_base));
    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

NTSTATUS GetGuardedRegion(pGuardedRegion x) {
    if (x->Security != CODE_SECURITY)
        return STATUS_UNSUCCESSFUL;

    ULONG infoLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
    PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = NULL;

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (pPoolInfo)
            ExFreePool(pPoolInfo);

        pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
        status = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
    }

    if (pPoolInfo) {
        for (unsigned int i = 0; i < pPoolInfo->Count; i++) {
            SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
            PVOID VirtualAddress;
            VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
            SIZE_T SizeInBytes = Entry->SizeInBytes;
            BOOLEAN NonPaged = Entry->NonPaged;

            if (Entry->NonPaged && Entry->SizeInBytes == 0x200000) {
                UCHAR expectedTag[] = "TnoC";  // Tag should be a string, not a ulong
                if (memcmp(Entry->Tag, expectedTag, sizeof(expectedTag)) == 0) {
                    RtlCopyMemory((void*)x->Address, &Entry->VirtualAddress, sizeof(Entry->VirtualAddress));
                    return STATUS_SUCCESS;
                }
            }
        }

        ExFreePool(pPoolInfo);
    }

    return STATUS_SUCCESS;
}

NTSTATUS IoController(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

    if (code == IOCTL_READWRITE) {
        if (size == sizeof(ReadWrite)) {
            pReadWrite req = (pReadWrite)(irp->AssociatedIrp.SystemBuffer);
            status = HandleReadWrite(req);
            bytes = sizeof(ReadWrite);
        }
        else {
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (code == IOCTL_GET_BASE_ADDRESS) {
        if (size == sizeof(BaseAddress)) {
            pBaseAddress req = (pBaseAddress)(irp->AssociatedIrp.SystemBuffer);
            status = GetBaseAddress(req);
            bytes = sizeof(BaseAddress);
        }
        else {
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (code == IOCTL_GET_GUARDED_REGION) {
        if (size == sizeof(GuardedRegion)) {
            pGuardedRegion req = (pGuardedRegion)(irp->AssociatedIrp.SystemBuffer);
            status = GetGuardedRegion(req);
            bytes = sizeof(GuardedRegion);
        }
        else {
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else {
        status = STATUS_NOT_IMPLEMENTED;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return irp->IoStatus.Status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        break;
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT drv_obj) {
    NTSTATUS status = STATUS_SUCCESS;

    status = IoDeleteSymbolicLink(&link);
    if (!NT_SUCCESS(status))
        return;

    IoDeleteDevice(drv_obj->DeviceObject);
}

NTSTATUS InitDriver(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT device_obj = NULL;

    UNICODE_STRING name, link;
    RtlInitUnicodeString(&name, L"\\Device\\{8C8A1200-F1AC-4EB6-88C3-6E24A426553C}");
    RtlInitUnicodeString(&link, L"\\DosDevices\\{8C8A1200-F1AC-4EB6-88C3-6E24A426553C}");

    // Create the device
    status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create a symbolic link
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_obj);
        return status;
    }

    // Set up IRP dispatch functions
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        drv_obj->MajorFunction[i] = &UnsupportedDispatch;
    }

    drv_obj->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
    drv_obj->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
    drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoController;
    drv_obj->DriverUnload = &UnloadDriver;

    // Configure device flags
    device_obj->Flags |= DO_BUFFERED_IO;
    device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return IoCreateDriver(NULL, &InitDriver);
}
