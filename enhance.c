#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <stdlib.h>

typedef NTSTATUS(NTAPI *NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID *ClientId);
typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *NtClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI *NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T BytesRead);
typedef NTSTATUS(NTAPI *NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T BytesWritten);
typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI *NtQueryVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T BufferSize, PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);

BOOL LoadNtApiFunctions() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return FALSE;
    }

    NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtdll, "NtOpenProcess");
    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    NtClose_t pNtClose = (NtClose_t)GetProcAddress(hNtdll, "NtClose");
    NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtQueryVirtualMemory_t pNtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    NtFlushInstructionCache_t pNtFlushInstructionCache = (NtFlushInstructionCache_t)GetProcAddress(hNtdll, "NtFlushInstructionCache");

    return pNtOpenProcess && pNtQuerySystemInformation && pNtClose && pNtReadVirtualMemory && pNtWriteVirtualMemory && pNtAllocateVirtualMemory && pNtQueryVirtualMemory && pNtFlushInstructionCache;
}

HANDLE NtOpenProcess(DWORD pid) {
    HANDLE hProcess = NULL;
    NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");

    if (pNtOpenProcess) {
        OBJECT_ATTRIBUTES objAttr;
        CLIENT_ID clientId;

        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        
        clientId.UniqueProcess = (HANDLE)pid;
        clientId.UniqueThread = NULL;

        NTSTATUS status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status != STATUS_SUCCESS) {
            hProcess = NULL;
        }
    }
    return hProcess;
}

DWORD GetProcessIdByName(const char* processName) {
    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);
    if (!processInfo) {
        return 0;
    }
    ULONG returnLength = 0;

    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!pNtQuerySystemInformation) {
        free(processInfo);
        return 0;
    }

    status = pNtQuerySystemInformation(SystemProcessInformation, processInfo, bufferSize, &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize = returnLength;
        PSYSTEM_PROCESS_INFORMATION tempInfo = (PSYSTEM_PROCESS_INFORMATION)realloc(processInfo, bufferSize);
        if (!tempInfo) {
            free(processInfo);
            return 0;
        }
        processInfo = tempInfo;
        status = pNtQuerySystemInformation(SystemProcessInformation, processInfo, bufferSize, &returnLength);
    }

    if (status != STATUS_SUCCESS) {
        free(processInfo);
        return 0;
    }

    DWORD pid = 0;
    PSYSTEM_PROCESS_INFORMATION currentProcess = processInfo;

    do {
        if (currentProcess->ImageName.Length > 0 && strcmp(currentProcess->ImageName.Buffer, processName) == 0) {
            pid = (DWORD)(uintptr_t)currentProcess->UniqueProcessId;
            break;
        }
        currentProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)currentProcess + currentProcess->NextEntryOffset);
    } while (currentProcess->NextEntryOffset != 0);

    free(processInfo);
    return pid;
}

NTSTATUS ReadProcessMemory(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T bufferSize, PSIZE_T bytesRead) {
    NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    if (pNtReadVirtualMemory) {
        return pNtReadVirtualMemory(hProcess, baseAddress, buffer, bufferSize, bytesRead);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WriteProcessMemory(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T bufferSize, PSIZE_T bytesWritten) {
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory) {
        return pNtWriteVirtualMemory(hProcess, baseAddress, buffer, bufferSize, bytesWritten);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS AllocateProcessMemory(HANDLE hProcess, PVOID *baseAddress, SIZE_T size) {
    SIZE_T regionSize = size;
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory) {
        return pNtAllocateVirtualMemory(hProcess, baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS QueryVirtualMemory(HANDLE hProcess, PVOID baseAddress, PMEMORY_BASIC_INFORMATION memoryInfo) {
    NtQueryVirtualMemory_t pNtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
    if (pNtQueryVirtualMemory) {
        SIZE_T returnLength;
        return pNtQueryVirtualMemory(hProcess, baseAddress, MemoryBasicInformation, memoryInfo, sizeof(MEMORY_BASIC_INFORMATION), &returnLength);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FlushInstructionCache(HANDLE hProcess, PVOID baseAddress, SIZE_T length) {
    NtFlushInstructionCache_t pNtFlushInstructionCache = (NtFlushInstructionCache_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFlushInstructionCache");
    if (pNtFlushInstructionCache) {
        return pNtFlushInstructionCache(hProcess, baseAddress, length);
    }
    return STATUS_UNSUCCESSFUL;
