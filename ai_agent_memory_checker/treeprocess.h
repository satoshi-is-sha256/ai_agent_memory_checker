// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TREEPROCESS_H
#define TREEPROCESS_H

#include "common.h"

struct ProcessInfo {
    DWORD processID;
    DWORD parentProcessID;
    std::string imageName;
};

inline std::vector<ProcessInfo> GetProcessTree(const std::string &target) {
    std::vector<ProcessInfo> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string exeName = WStringToString(pe32.szExeFile);
            if (exeName == target) {
                processes.push_back({ pe32.th32ProcessID, pe32.th32ParentProcessID, exeName });
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return processes;
}

inline DWORD FindMainChatGPTProcess(const std::vector<ProcessInfo> &allProcs) {
    if (allProcs.empty()) return 0;

    for (const auto &proc : allProcs) {
        bool isParent = false;
        for (const auto &other : allProcs) {
            if (other.parentProcessID == proc.processID) {
                isParent = true;
                break;
            }
        }

        if (isParent) {
            return proc.processID;
        }
    }

    DWORD minPid = allProcs[0].processID;
    for (const auto &proc : allProcs) {
        if (proc.processID < minPid) minPid = proc.processID;
    }
    return minPid;
}

#endif