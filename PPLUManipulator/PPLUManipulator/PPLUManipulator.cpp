#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>

// IOCTL definitions
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

#define IOCTL_GET_PROTECTION    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROTECTION    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PROTECTION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

// PS_PROTECTION structure 
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        } Flags;
    } u;
} PS_PROTECTION, * PPS_PROTECTION;

// Helper: print protection level in human-readable form
void PrintProtectionLevel(UCHAR level) {
    PS_PROTECTION prot;
    prot.u.Level = level;

    const char* typeStr;
    switch (prot.u.Flags.Type) {
    case 0:  typeStr = "None"; break;
    case 1:  typeStr = "Protected Light"; break;
    case 2:  typeStr = "Protected"; break;
    case 3:  typeStr = "Protected + Protected Light"; break; // rare
    default: typeStr = "Unknown"; break;
    }

    const char* signerStr;
    switch (prot.u.Flags.Signer) {
    case 0:  signerStr = "None"; break;
    case 1:  signerStr = "WinSystem"; break;
    case 2:  signerStr = "Windows"; break;
    case 3:  signerStr = "Antimalware"; break;
    case 6:  signerStr = "Lsa"; break;
    case 7:  signerStr = "Windows Defender"; break;
    default: signerStr = "Unknown"; break;
    }

    printf("Protection Level: 0x%02X\n", level);
    printf("  Type   : %s (%d)\n", typeStr, prot.u.Flags.Type);
    printf("  Signer : %s (%d)\n", signerStr, prot.u.Flags.Signer);
    printf("  Audit  : %s\n", prot.u.Flags.Audit ? "Yes" : "No");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"\nUsage:\n");
        wprintf(L"  %s <PID> get                 show current protection\n", argv[0]);
        wprintf(L"  %s <PID> protect             set Protected Light + Antimalware\n", argv[0]);
        wprintf(L"  %s <PID> unprotect           remove protection\n", argv[0]);
        wprintf(L"\nExamples:\n");
        wprintf(L"  %s 1234 get\n", argv[0]);
        wprintf(L"  %s 5678 protect\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    if (swscanf_s(argv[1], L"%u", &pid) != 1 || pid == 0) {
        wprintf(L"[!] Invalid PID\n");
        return 1;
    }

    const wchar_t* action = argv[2];

    // Open device
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\PPLManipulator",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wprintf(L"[!] Failed to open \\\\.\\PPLManipulator, Error %u (0x%X)\n", err, err);
        if (err == 2) {
            wprintf(L"    Make sure the driver is loaded and the device exists.\n");
        }
        return 1;
    }

    DWORD bytesReturned = 0;
    NTSTATUS status = STATUS_SUCCESS;
    bool success = false;

    if (_wcsicmp(action, L"get") == 0) {
        UCHAR protectionLevel = 0;

        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_PROTECTION,
            &pid, sizeof(DWORD),
            &protectionLevel, sizeof(UCHAR),
            &bytesReturned,
            NULL
        );

        if (success) {
            printf("[PID %u]\n", pid);
            PrintProtectionLevel(protectionLevel);
        }
    }
    else if (_wcsicmp(action, L"protect") == 0 || _wcsicmp(action, L"add") == 0) {
        success = DeviceIoControl(
            hDevice,
            IOCTL_ADD_PROTECTION,
            &pid, sizeof(DWORD),
            NULL, 0,
            &bytesReturned,
            NULL
        );

        if (success) {
            wprintf(L"[+] Protection added to PID %u (Protected Light + Antimalware)\n", pid);
        }
    }
    else if (_wcsicmp(action, L"unprotect") == 0 || _wcsicmp(action, L"clear") == 0) {
        success = DeviceIoControl(
            hDevice,
            IOCTL_CLEAR_PROTECTION,
            &pid, sizeof(DWORD),
            NULL, 0,
            &bytesReturned,
            NULL
        );

        if (success) {
            wprintf(L"[+] Protection removed from PID %u\n", pid);
        }
    }
    else {
        wprintf(L"[!] Unknown action: %s\n", action);
        wprintf(L"    Use: get | protect | unprotect\n");
        success = false;
    }

    if (!success) {
        DWORD err = GetLastError();
        wprintf(L"[!] DeviceIoControl failed. Error %u (0x%X)\n", err, err);

        if (err == 87) {
            wprintf(L"    (invalid parameter) check PID exists and driver supports it\n");
        }
        else if (err == 31) {
            wprintf(L"    (function failed in driver) most likely process lookup failed or invalid PID\n");
        }
    }

    CloseHandle(hDevice);
    return success ? 0 : 1;
}