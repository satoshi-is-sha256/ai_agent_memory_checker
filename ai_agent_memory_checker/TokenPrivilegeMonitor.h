// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKENPRVILEGEMONITOR_H
#define TOKENPRVILEGEMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef BOOL(WINAPI *pfnOpenProcessToken)(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
    );

typedef BOOL(WINAPI *pfnAdjustTokenPrivileges)(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD ReturnLength
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CTokenPrivilegeMonitor {
public:
    static pfnOpenProcessToken Original_OpenProcessToken;
    static pfnAdjustTokenPrivileges Original_AdjustTokenPrivileges;

    static BOOL WINAPI Hooked_OpenProcessToken(
        HANDLE ProcessHandle,
        DWORD DesiredAccess,
        PHANDLE TokenHandle
    ) {
        std::ostringstream ss;
        ss << "[TOKEN-AUDIT] OpenProcessToken Intercepted!\r\n";
        ss << "  -> Target Process Handle: 0x" << std::hex << (uintptr_t)ProcessHandle << std::dec << "\r\n";
        ss << "  -> Desired Token Access: 0x" << std::hex << DesiredAccess << std::dec << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("OpenProcessToken", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    }

    static BOOL WINAPI Hooked_AdjustTokenPrivileges(
        HANDLE TokenHandle,
        BOOL DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD ReturnLength
    ) {
        std::ostringstream ss;
        ss << "[TOKEN-AUDIT] AdjustTokenPrivileges Intercepted (Privilege Escalation Attempt)!\r\n";
        if (NewState) {
            ss << "  -> Target Privilege Count: " << NewState->PrivilegeCount << "\r\n";
        }
        ss << "  -> Disable All Privileges: " << (DisableAllPrivileges ? "TRUE" : "FALSE") << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("PrivilegeEscalationAttempt", ss.str(), ThreatCorrelator::ThreatLevel::High);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    }

    static void InitializeTokenPrivilegeHooks() {
        HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvapi32) {
            hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        }
        if (!hAdvapi32) return;

        Original_OpenProcessToken = (pfnOpenProcessToken)GetProcAddress(hAdvapi32, "OpenProcessToken");
        Original_AdjustTokenPrivileges = (pfnAdjustTokenPrivileges)GetProcAddress(hAdvapi32, "AdjustTokenPrivileges");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_OpenProcessToken) {
            DetourAttach(&(PVOID&)Original_OpenProcessToken, Hooked_OpenProcessToken);
        }
        if (Original_AdjustTokenPrivileges) {
            DetourAttach(&(PVOID&)Original_AdjustTokenPrivileges, Hooked_AdjustTokenPrivileges);
        }

        DetourTransactionCommit();
    }

    static void UninitializeTokenPrivilegeHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_OpenProcessToken) {
            DetourDetach(&(PVOID&)Original_OpenProcessToken, Hooked_OpenProcessToken);
        }
        if (Original_AdjustTokenPrivileges) {
            DetourDetach(&(PVOID&)Original_AdjustTokenPrivileges, Hooked_AdjustTokenPrivileges);
        }

        DetourTransactionCommit();
    }
};

#endif