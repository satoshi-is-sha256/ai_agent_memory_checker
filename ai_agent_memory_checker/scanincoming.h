// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCANINCOMING_H
#define SCANINCOMING_H

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_OBJECT)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

inline std::string ScanIncomingProcessAccess(DWORD monitoredPid, const std::string &monitoredName) {
    std::stringstream ss;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySystemInformation = (NTSTATUS(NTAPI *)(ULONG, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtQueryObject = (PFN_NT_QUERY_OBJECT)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQuerySystemInformation || !NtQueryObject) {
        ss << "[-] Failed to query system handle table for reverse scan.\n";
        return ss.str();
    }

    ULONG bufferSize = 1024 * 1024 * 10;
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status = NtQuerySystemInformation(0x40, buffer.data(), (ULONG)buffer.size(), &bufferSize);

    if (status != 0) {
        ss << "[-] Failed to query system handle table for reverse scan.\n";
        return ss.str();
    }

    auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
    ss << "=== Reverse Handle Audit (Incoming Access to PID: " << monitoredPid << ") ===\n";

    size_t detectedCount = 0;

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i) {
        const auto &entry = handleInfo->Handles[i];
        DWORD holderPid = static_cast<DWORD>(entry.UniqueProcessId);

        if (holderPid == 0 || holderPid == 4 || holderPid == monitoredPid) continue;

        HANDLE hHolderProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, holderPid);
        if (!hHolderProcess) continue;

        HANDLE hDuped = nullptr;
        if (DuplicateHandle(hHolderProcess, reinterpret_cast<HANDLE>(entry.HandleValue), GetCurrentProcess(), &hDuped, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            BYTE typeBuffer[512] = { 0 };
            ULONG returnLength = 0;
            if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)2 /* ObjectTypeInformation */, typeBuffer, sizeof(typeBuffer), &returnLength) >= 0) {
                auto typeInfo = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(typeBuffer);
                if (typeInfo->TypeName.Buffer && wcscmp(typeInfo->TypeName.Buffer, L"Process") == 0) {
                    DWORD targetPid = GetProcessId(hDuped);
                    if (targetPid == monitoredPid) {
                        ULONG access = entry.GrantedAccess;

                        bool isDangerous = (access & PROCESS_VM_READ) ||
                            (access & PROCESS_VM_WRITE) ||
                            (access & PROCESS_CREATE_THREAD) ||
                            ((access & 0x1FFFFF) == 0x1FFFFF);

                        if (isDangerous) {
                            detectedCount++;
                            ss << "  [!] [ALERT] External Process Holding Handle to Target!\n"
                                << "      -> Holder PID: " << holderPid << "\n"
                                << "      -> Target PID: " << targetPid << " (" << monitoredName << ")\n"
                                << "      -> Rights: 0x" << std::hex << access << std::dec << "\n";
                        }
                    }
                }
            }
            CloseHandle(hDuped);
        }
        CloseHandle(hHolderProcess);
    }

    if (detectedCount == 0) {
        ss << "  (No unauthorized incoming process handles detected for this PID)\n";
    }
    ss << "--------------------------------------------------------------------\n";

    return ss.str();
}

#endif
