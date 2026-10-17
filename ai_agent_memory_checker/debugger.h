// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DEBUGGER_H
#define DEBUGGER_H

#include "common.h"

inline bool CheckStandardDebugger(HANDLE hProcess) {
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent))
        return (isDebuggerPresent == TRUE) ? true : false;

    return false;
}

inline bool CheckDebugPort(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pfnNtQueryInformationProcess NtQueryInformationProcess = reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) return false;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)7, // ProcessDebugPort
        &debugPort,
        sizeof(debugPort),
        nullptr
    );

    return (NT_SUCCESS(status) && debugPort != 0);
}

inline bool CheckDebugObject(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pfnNtQueryInformationProcess NtQueryInformationProcess = reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) return false;

    HANDLE hDebugObject = nullptr;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1E, // ProcessDebugObjectHandle
        &hDebugObject,
        sizeof(hDebugObject),
        nullptr
    );

    return (NT_SUCCESS(status) && hDebugObject != nullptr);
}

#endif
