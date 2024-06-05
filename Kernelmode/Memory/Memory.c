#include "Memory.h"

NTSTATUS ReadMemory(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
    MM_COPY_ADDRESS to_read = { 0 };
    to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;
    return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
}

NTSTATUS WriteMemory(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_written) {
    if (!target_address)
        return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS AddrToWrite = { 0 };
    AddrToWrite.QuadPart = (LONGLONG)target_address;

    PVOID mapped_mem = MmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);
    if (!mapped_mem)
        return STATUS_UNSUCCESSFUL;

    memcpy(mapped_mem, buffer, size);

    *bytes_written = size;
    MmUnmapIoSpace(mapped_mem, size);
    return STATUS_SUCCESS;
}