#ifndef COMMEMORY_H
#define COMMEMORY_H

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_OBJECT)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength,PULONG ReturnLength);

typedef struct _PUBLIC_OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
    WCHAR NameBuffer[1];
} PUBLIC_OBJECT_NAME_INFORMATION, * PPUBLIC_OBJECT_NAME_INFORMATION;

typedef struct _SYSTEM_EXTENDED_HANDLE_TABLE_ENTRY_INFO {
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_EXTENDED_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_EXTENDED_HANDLE_TABLE_ENTRY_INFO;

inline std::string InspectSectionObjects(DWORD targetPid, const std::string &processName) {
    std::stringstream ss;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySystemInformation = (NTSTATUS(NTAPI *)(ULONG, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtQueryObject = (PFN_NT_QUERY_OBJECT)GetProcAddress(hNtdll, "NtQueryObject");
    if (!NtQuerySystemInformation || !NtQueryObject) {
        ss << "[-] Failed to query system handle table for sections.\n";
        return ss.str();
    }

    ULONG bufferSize = 1024 * 1024 * 10;
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status = NtQuerySystemInformation(0x40, buffer.data(), (ULONG)buffer.size(), &bufferSize);
    if (status != 0) {
        std::cout << "[-] Failed to query system handle table for sections.\n";
        return ss.str();
    }

    auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
    ss << "=== Section (Shared Memory) Report: " << processName << " (PID: " << targetPid << ") ===\n";

    size_t sectionCount = 0;

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i) {
        const auto &entry = handleInfo->Handles[i];
        DWORD currentPid = static_cast<DWORD>(entry.UniqueProcessId);

        if (currentPid != targetPid) continue;

        HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, targetPid);
        if (!hTargetProcess) continue;

        HANDLE hDuped = nullptr;
        if (DuplicateHandle(hTargetProcess, reinterpret_cast<HANDLE>(entry.HandleValue), GetCurrentProcess(), &hDuped, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

            BYTE typeBuffer[512] = { 0 };
            ULONG returnLength = 0;
            if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)2 /* ObjectTypeInformation */, typeBuffer, sizeof(typeBuffer), &returnLength) >= 0) {
                auto typeInfo = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(typeBuffer);

                if (typeInfo->TypeName.Buffer && wcscmp(typeInfo->TypeName.Buffer, L"Section") == 0) {
                    sectionCount++;

                    std::wstring sectionName = L"(Unnamed Section)";
                    BYTE nameBuffer[1024] = { 0 };
                    if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)1 /* ObjectNameInformation */, nameBuffer, sizeof(nameBuffer), &returnLength) >= 0) {
                        auto nameInfo = reinterpret_cast<PPUBLIC_OBJECT_NAME_INFORMATION>(nameBuffer);
                        if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                            sectionName = nameInfo->Name.Buffer;
                        }
                    }

                    std::string sectionNameA = WStringToString(sectionName);

                    ss << "  > [SECTION] Handle: 0x" << std::hex << entry.HandleValue
                       << " | Rights: 0x" << entry.GrantedAccess
                       << " | Name: " << sectionNameA << "\n";
                }
            }
            CloseHandle(hDuped);
        }
        CloseHandle(hTargetProcess);
    }

    if (sectionCount == 0) {
        ss << "  (No active Section/Shared Memory handles found for this PID)\n";
    }
    ss << "--------------------------------------------------------------------\n";

    return ss.str();
}

#endif