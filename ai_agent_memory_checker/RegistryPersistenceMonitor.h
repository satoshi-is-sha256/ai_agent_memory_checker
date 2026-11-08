// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef REGISTRYPERSISTENCEMONITOR_H
#define REGISTRYPERSISTENCEMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef LONG(WINAPI *pfnRegSetValueExW)(
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
class CRegistryPersistenceMonitor {
public:
    static pfnRegSetValueExW Original_RegSetValueExW;

    static LONG WINAPI Hooked_RegSetValueExW(
        HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        const BYTE* lpData,
        DWORD cbData
    ) {
        std::wstring valueNameStr = lpValueName ? lpValueName : L"<Default>";
        std::string utf8ValueName = WStringToString(valueNameStr);

        std::ostringstream ss;
        ss << "[REGISTRY-PERSISTENCE] Registry Write / Autorun Intercepted!\r\n";
        ss << "  -> Target Value Name: " << utf8ValueName << "\r\n";
        ss << "  -> Payload Data Size: " << cbData << " bytes\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("RegistryPersistence", ss.str(), ThreatCorrelator::ThreatLevel::High);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }

    static void InitializeRegistryPersistenceHooks() {
        HMODULE hAdvApi32 = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvApi32) {
            hAdvApi32 = LoadLibraryW(L"advapi32.dll");
        }
        if (!hAdvApi32) return;

        Original_RegSetValueExW = (pfnRegSetValueExW)GetProcAddress(hAdvApi32, "RegSetValueExW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_RegSetValueExW) {
            DetourAttach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeRegistryPersistenceHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_RegSetValueExW) {
            DetourDetach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }
        DetourTransactionCommit();
    }
};

#endif
