// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef REGISTRYPERSISTENCETRACKER_H
#define REGISTRYPERSISTENCETRACKER_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"

typedef LSTATUS(WINAPI *pfnRegSetValueExW)(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE* lpData,
    DWORD cbData
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CRegistryPersistence {
public:
    static pfnRegSetValueExW Original_RegSetValueExW;

    static LSTATUS WINAPI Hooked_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData) {
        std::wstring valueName = lpValueName ? lpValueName : L"(Default)";
    
        std::wstring dataStr = L"";
        if (dwType == REG_SZ && lpData && cbData > 0) {
            dataStr = std::wstring((LPCWSTR)lpData, cbData / sizeof(WCHAR));
        }

        std::ostringstream ss;
        ss << "[PERSISTENCE-WATCH] Registry Value Set Detected!\r\n";
        ss << "  -> Value Name: " << WStringToString(valueName) << "\r\n";
        if (!dataStr.empty()) {
            if (dataStr.length() > 100) dataStr = dataStr.substr(0, 100) + L"...";
            ss << "  -> Payload Data: " << WStringToString(dataStr) << "\r\n";
        }

        TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Alert, ss.str());
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }

    static void InitializePersistenceHooks() {
        HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvapi32) return;

        Original_RegSetValueExW = (pfnRegSetValueExW)GetProcAddress(hAdvapi32, "RegSetValueExW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_RegSetValueExW) {
            DetourAttach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }

        DetourTransactionCommit();
    }

    static void UninitializePersistenceHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_RegSetValueExW) {
            DetourDetach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }
        DetourTransactionCommit();
    }
};

#endif