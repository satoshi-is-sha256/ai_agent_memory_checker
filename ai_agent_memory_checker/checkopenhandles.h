// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHECKOPENHANDLES_H
#define CHECKOPENHANDLES_H

#include "common.h"

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

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[16];
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

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

inline bool GetHandleDetails(HANDLE hTargetProcess, HANDLE hRemoteHandle, std::string &outTypeName, std::string &outObjectName) {
    HMODULE mod = GetModuleHandleW(L"ntdll.dll");
    if (!mod) return false;

    pfnNtQueryObject NtQueryObject = reinterpret_cast<pfnNtQueryObject>(GetProcAddress(mod, "NtQueryObject"));
    if (!NtQueryObject) return false;

    HANDLE hLocalHandle = nullptr;
    if (!DuplicateHandle(hTargetProcess, hRemoteHandle, GetCurrentProcess(), &hLocalHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) 
        return false;

    BYTE typeBuffer[0x200] = { 0 };
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryObject(hLocalHandle, (OBJECT_INFORMATION_CLASS)ObjectTypeInformation, typeBuffer, sizeof(typeBuffer), &returnLength);
    if (NT_SUCCESS(status)) {
        const auto *typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeBuffer);
        if (typeInfo->TypeName.Buffer) {
            std::wstring outTypeNamew;
            outTypeNamew.assign(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
            outTypeName = WStringToString(outTypeNamew);
        }
    }

    BYTE nameBuffer[0x1000] = { 0 };
    status = NtQueryObject(hLocalHandle, ObjectNameInformation, nameBuffer, sizeof(nameBuffer), &returnLength);
    if (NT_SUCCESS(status)) {
        const auto *nameInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(nameBuffer);
        if (nameInfo->Name.Buffer) {
            std::wstring outObjectNamew;
            outObjectNamew.assign(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
            outObjectName = WStringToString(outObjectNamew);
        }
    }

    CloseHandle(hLocalHandle);
    return true;
}

#endif