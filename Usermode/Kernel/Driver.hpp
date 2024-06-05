#include <Windows.h>
#include <stdio.h>
#include "TlHelp32.h"
#include <cstdint>

#define IOCTL_READWRITE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_BASE_ADDRESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_GUARDED_REGION     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_SECURITY        0x12A3B45

class Structs {
public:
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
private:
};

class Kernel {
public:

    HANDLE DeviceHandle;
    INT32 ProcessID;
    uintptr_t BaseAddress;

    auto InitializeCommunication() -> bool {
        DeviceHandle = CreateFileW((L"\\\\.\\{8C8A1200-F1AC-4EB6-88C3-6E24A426553C}"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (!DeviceHandle || (DeviceHandle == INVALID_HANDLE_VALUE)) {
            printf("[i] Driver not loaded.");
            return false;
        }

        return true;

    }

    auto GetBaseAddress() -> uintptr_t {
        uintptr_t image_address = { NULL };
        Structs::_BaseAddress data = { NULL };

        data.Security = CODE_SECURITY;
        data.ProcessId = ProcessID;
        data.Address = (ULONGLONG*)&image_address;

        DeviceIoControl(DeviceHandle, IOCTL_GET_BASE_ADDRESS, &data, sizeof(data), nullptr, NULL, NULL, NULL);

        return image_address;
    }

    auto GetGuardedRegion() -> uintptr_t {
        uintptr_t guarded_region_address = { NULL };
        Structs::_GuardedRegion data = { NULL };

        data.Security = CODE_SECURITY;
        data.Address = (ULONGLONG*)&guarded_region_address;

        DeviceIoControl(DeviceHandle, IOCTL_GET_GUARDED_REGION, &data, sizeof(data), nullptr, NULL, NULL, NULL);

        return guarded_region_address;
    }

    auto FindProcessWindow(LPCTSTR process_name) -> INT32 {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name)) {
                    CloseHandle(hsnap);
                    ProcessID = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);

        return { NULL };
    }

    auto ReadProcessMemory(PVOID address, PVOID buffer, DWORD size) -> void {
        Structs::_ReadWrite data = { 0 };

        data.Security = CODE_SECURITY;
        data.Address = (ULONGLONG)address;
        data.Buffer = (ULONGLONG)buffer;
        data.Size = size;
        data.ProcessId = ProcessID;
        data.Write = FALSE;

        DeviceIoControl(DeviceHandle, IOCTL_READWRITE, &data, sizeof(data), nullptr, NULL, NULL, NULL);
    }

    template <typename T>
    T ReadPhysicalMemory(uint64_t address) {
        T buffer{ };
        ReadProcessMemory((PVOID)address, &buffer, sizeof(T));
        return buffer;
    }

};

Kernel* DriverCommunication = new Kernel();