// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PEBINSPECTOR_H
#define PEBINSPECTOR_H

#include "common.h"
#include <winternl.h>
#include <vector>

typedef NTSTATUS(WINAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

class PebInspector {
public:
    static std::string ExtractCommandLine(HANDLE hProcess) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return "";

        auto NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return "";

        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength = 0;

        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
        );

        if (status != 0 || !pbi.PebBaseAddress) return "";

        PEB peb;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            return "";
        }

        RTL_USER_PROCESS_PARAMETERS upp;
        if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
            return "";
        }

        std::vector<WCHAR> cmdLineBuffer(upp.CommandLine.Length / sizeof(WCHAR) + 1, 0);
        if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, cmdLineBuffer.data(), upp.CommandLine.Length, &bytesRead)) {
            return "";
        }

        std::wstring wCmdLine(cmdLineBuffer.data());
        return WStringToString(wCmdLine);
    }

    static std::string FormatPebReport(HANDLE hProcess) {
        std::string cmdLine = ExtractCommandLine(hProcess);
        std::ostringstream ss;
        ss << "[PEB-INSPECT] Process Environment Block Inspection:\r\n";
        ss << "  -> Extracted Command Line: " << (cmdLine.empty() ? "<Access Denied / Empty>" : cmdLine) << "\r\n";
        return ss.str();
    }
};

#endif
