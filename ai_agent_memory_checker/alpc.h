#ifndef ALPC_H
#define ALPC_H

#include "common.h"

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_OBJECT)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

inline std::string InspectAlpcAndPipes(DWORD targetPid, const std::string &processName) {
    std::stringstream ss;
    ss << "[-] Failed to system handle table for IPC inspection.\n";

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySystemInformation = (NTSTATUS(NTAPI *)(ULONG, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtQueryObject = (PFN_NT_QUERY_OBJECT)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQuerySystemInformation || !NtQueryObject) return ss.str();

    ULONG bufferSize = 1024 * 1024 * 10;
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status = NtQuerySystemInformation(0x40, buffer.data(), (ULONG)buffer.size(), &bufferSize);
    if (status != 0) {
        return ss.str();
    }

    auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
    ss << "=== IPC Report (ALPC & Named Pipes): " << processName << " (PID: " << targetPid << ") ===\n";

    size_t ipcCount = 0;
    HANDLE hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hTargetProcess) {
        ss << "  (Failed to open target process for handle duplication)\n";
        ss << "--------------------------------------------------------------------\n";
        return ss.str();
    }

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i) {
        auto& entry = handleInfo->Handles[i];
        DWORD currentPid = static_cast<DWORD>(entry.UniqueProcessId);

        if (currentPid != targetPid) continue;

        HANDLE hDuped = nullptr;
        if (DuplicateHandle(hTargetProcess, reinterpret_cast<HANDLE>(entry.HandleValue), GetCurrentProcess(), &hDuped, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            BYTE typeBuffer[512] = { 0 };
            ULONG returnLength = 0;
            if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)2 /* ObjectTypeInformation */, typeBuffer, sizeof(typeBuffer), &returnLength) >= 0) {
                auto typeInfo = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(typeBuffer);
                if (typeInfo->TypeName.Buffer) {
                    std::wstring typeName = typeInfo->TypeName.Buffer;
                    bool isTargetType = false;
                    std::string category = "";
                    if (typeName == L"File") {
                        BYTE nameBuffer[1024] = { 0 };
                        if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)1, nameBuffer, sizeof(nameBuffer), &returnLength) >= 0) {
                            auto nameInfo = reinterpret_cast<PPUBLIC_OBJECT_NAME_INFORMATION>(nameBuffer);
                            if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                                std::wstring objName = nameInfo->Name.Buffer;
                                if (objName.find(L"\\Device\\NamedPipe\\") != std::wstring::npos) {
                                    isTargetType = true;
                                    category = "[NAMED PIPE]";
                                }
                            }
                        }
                    }
                    else if (typeName == L"ALPC Port") {
                        isTargetType = true;
                        category = "[ALPC PORT]";
                    }

                    if (isTargetType) {
                        ipcCount++;
                        std::wstring objName = L"(Unnamed)";
                        BYTE nameBuffer[1024] = { 0 };
                        if (NtQueryObject(hDuped, (OBJECT_INFORMATION_CLASS)1, nameBuffer, sizeof(nameBuffer), &returnLength) >= 0) {
                            auto nameInfo = reinterpret_cast<PPUBLIC_OBJECT_NAME_INFORMATION>(nameBuffer);
                            if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                                objName = nameInfo->Name.Buffer;
                            }
                        }

                        ss << "  > " << category << " Handle: 0x" << std::hex << entry.HandleValue
                           << " | Rights: 0x" << entry.GrantedAccess
                           << " | Name: " << WStringToString(objName) << "\n";
                    }
                }
            }
            CloseHandle(hDuped);
        }
    }
    CloseHandle(hTargetProcess);

    if (ipcCount == 0) {
        ss << "  (No active ALPC ports or Named Pipe handles found for this PID)\n";
    }
    ss << "--------------------------------------------------------------------\n";

    return ss.str();
}

#endif
