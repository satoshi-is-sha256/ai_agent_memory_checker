// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROCESSTREE_H
#define PROCESSTREE_H

#include "common.h"
#include <tlhelp32.h>
#include <map>

struct ProcessNode {
    DWORD pid;
    DWORD ppid;
    std::wstring processName;
    std::vector<DWORD> children;
};

inline std::map<DWORD, ProcessNode> BuildProcessTree() {
    std::map<DWORD, ProcessNode> tree;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return tree;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            ProcessNode node;
            node.pid = pe32.th32ProcessID;
            node.ppid = pe32.th32ParentProcessID;
            node.processName = pe32.szExeFile;
            tree[node.pid] = node;
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    for (auto& pair : tree) {
        DWORD ppid = pair.second.ppid;
        if (tree.find(ppid) != tree.end()) {
            tree[ppid].children.push_back(pair.first);
        }
    }
    return tree;
}

#endif