#include <ntifs.h>
#include <ntddk.h>

// Define multiple IOCTL codes for different operations
#define IOCTL_GET_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * The PS_PROTECTION structure is used to define the protection level of a process.
 */
typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        } Flags;
    } u;
} PS_PROTECTION, * PPS_PROTECTION;

NTSTATUS IrpCreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_CREATE handled\n");
    return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Unloaded\n");
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    ULONG ProcessId = 0;
    PEPROCESS Process;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IOCTL received\n");

    ProcessId = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ProcessId: %d\n", ProcessId);

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to lookup process: %x\n", status);
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    // Offset for PS_PROTECTION (e.g., 0x5fa on Windows 11; verify with WinDbg dt nt!_EPROCESS)
    PS_PROTECTION* protectionPtr = (PS_PROTECTION*)((UCHAR*)Process + 0x5fa);
    PS_PROTECTION protection = *protectionPtr;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_PROTECTION:
        // Read and return the protection level
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process Protection Level: %02x\n", protection.u.Level);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Type: %d, Audit: %d, Signer: %d\n", protection.u.Flags.Type, protection.u.Flags.Audit, protection.u.Flags.Signer);
        *(UCHAR*)Irp->AssociatedIrp.SystemBuffer = protection.u.Level;
        bytes = sizeof(UCHAR);
        break;

    case IOCTL_ADD_PROTECTION:
        // Set to ProtectedLight with Antimalware signer
        protectionPtr->u.Flags.Type = 1;   // PsProtectedTypeProtectedLight
        protectionPtr->u.Flags.Signer = 3; // PsProtectedSignerAntimalware
        protectionPtr->u.Flags.Audit = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Protection added (Type:1, Signer:3)\n");
        break;

    case IOCTL_CLEAR_PROTECTION:
        // Clear protection
        protectionPtr->u.Level = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Protection cleared\n");
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Create Device
    UNICODE_STRING dev, dos;
    RtlInitUnicodeString(&dev, L"\\Device\\PPLManipulator");
    RtlInitUnicodeString(&dos, L"\\DosDevices\\PPLManipulator");

    PDEVICE_OBJECT DeviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create device: %x\n", status);
        return status;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Device Created\n");
    }

    // Create Symbolic Link (delete if exists first)
    IoDeleteSymbolicLink(&dos);
    status = IoCreateSymbolicLink(&dos, &dev);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create symbolic link: %x\n", status);
        IoDeleteDevice(DeviceObject);
        return status;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Symbolic Link Created\n");
    }

    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Loaded\n");

    return STATUS_SUCCESS;
}