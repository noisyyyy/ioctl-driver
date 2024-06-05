#include "ntifs.h"

NTSTATUS ReadMemory(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read);
NTSTATUS WriteMemory(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_written);