// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ALLSYSTEMHANDLESEX_H
#define ALLSYSTEMHANDLESEX_H

#include "common.h"

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex; // important
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

inline std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> QueryAllSystemHandlesEx() {
    ULONG bufferSize = 0x100000;
    PVOID buffer = nullptr;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return {};
    auto NtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) return {};

    do {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return {};

        ULONG returnLength = 0;
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 0x10000;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> resultHandles;
    if (NT_SUCCESS(status)) {
        auto sysInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;
        for (ULONG_PTR i = 0; i < sysInfo->NumberOfHandles; ++i) {
            resultHandles.push_back(sysInfo->Handles[i]);
        }
    }

    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    return resultHandles;
}

inline std::string InspectTargetHandles(const std::wstring &name) {
    std::stringstream ss;
    DWORD codexPid = GetProcessIdByName(name);
    if (codexPid == 0) {
        ss << "[-] Target is not currently running.\n";
        return ss.str();
    }
    ss << "[+] Target found, PID: " << codexPid << "\n";

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> qash = QueryAllSystemHandlesEx();
    if (qash.empty()) {
        ss << "[-] Failed to query system extended handles.\n";
        return ss.str();
    }

    ss << "=== Handle Forensic Report: (PID: " << codexPid << ") ===\n";
    ss << "Total System Handles Scanned: " << qash.size() << "\n";
    ss << "---------------------------------------------------------\n";

    size_t matchCount = 0;
    for (const auto &entry : qash) {
        if (entry.UniqueProcessId == codexPid) {
            matchCount++;
            ss << "  > Object: " << entry.Object
                << " | Handle: 0x" << std::hex << entry.HandleValue
                << " | TypeIdx: " << std::dec << entry.ObjectTypeIndex
                << " | Access: 0x" << std::hex << entry.GrantedAccess
                << std::dec << "\n";
        }
    }

    ss << "---------------------------------------------------------\n";
    ss << "Matched Handles: " << matchCount << "\n";

    return ss.str();
}

#endif
