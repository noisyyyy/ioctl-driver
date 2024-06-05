#include "CR3.h"

#include <ntifs.h>

INT32 GetWinver() {
    RTL_OSVERSIONINFOW ver = { 0 };
    RtlGetVersion(&ver);
    switch (ver.dwBuildNumber) {
    case 17134: return 0x0278; // Windows 10 version 1803
    case 17763: return 0x0278; // Windows 10 version 1809
    case 18362: return 0x0280; // Windows 10 version 1903
    case 18363: return 0x0280; // Windows 10 version 1909
    case 19041: return 0x0388; // Windows 10 version 2004
    case 19569: return 0x0388; // Windows 10 version 20H2
    case 20180: return 0x0388; // Windows 10 version 21H1
    default: return 0x0388; // Default
    }
}


UINT64 GetCR3(const PEPROCESS pProcess) {
    PUCHAR process = (PUCHAR)pProcess;
    ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);

    if (process_dirbase == 0) {
        INT32 UserDirOffset = GetWinver();
        ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
        return process_userdirbase;
    }

    return process_dirbase;
}