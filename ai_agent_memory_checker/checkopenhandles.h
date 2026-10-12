// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHECKOPENHANDLES_H
#define CHECKOPENHANDLES_H

#define SystemHandleInformation 16

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>

constexpr DWORD STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI *pfnNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

inline std::string CheckOpenHandles(DWORD targetProcessId) {
    std::ostringstream stream;
    stream << "[*] Scanning open handles held by PID: " << targetProcessId << std::endl;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return stream.str();

    pfnNtQuerySystemInformation NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return stream.str();

    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return stream.str();

        status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &bufferSize);
    }

    if (!NT_SUCCESS(status)) {
        stream << "[-] Failed to query system handle information. Status: 0x" << std::hex << status << std::endl;
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);

        return stream.str();
    }

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
    int suspiciousCount = 0;

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        const auto &handle = handleInfo->Handles[i];

        if (handle.UniqueProcessId == targetProcessId) {
            if (handle.GrantedAccess & 0x0010) {
                suspiciousCount++;
                stream << " [!] Found Handle -> Target PID: " << targetProcessId
                       << " | Handle Value: 0x" << std::hex << handle.HandleValue
                       << " | Access Mask: 0x" << handle.GrantedAccess << std::dec << std::endl;
            }
        }
    }

    stream << "----------------------------------------" << std::endl;
    stream << " Scan complete. Suspicious read handles found: " << suspiciousCount << std::endl;
    if (suspiciousCount > 0)
        stream << "[!] WARNING: Target process is holding memory-read privileges!" << std::endl;
    else
        stream << "[+] No suspicious process-read handles held by this PID." << std::endl;

    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);

    return stream.str();
}

#endif