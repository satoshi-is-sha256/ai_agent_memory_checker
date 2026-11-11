// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef REGISTRYRWMONITOR_H
#define REGISTRYRWMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef LSTATUS(WINAPI *pfnRegCreateKeyExW)(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
    );

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
class CRegistryRWMonitor {
public:
    static pfnRegCreateKeyExW Original_RegCreateKeyExW;
    static pfnRegSetValueExW Original_RegSetValueExW;

    static LSTATUS WINAPI Hooked_RegCreateKeyExW(
        HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD Reserved,
        LPWSTR lpClass,
        DWORD dwOptions,
        REGSAM samDesired,
        const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY phkResult,
        LPDWORD lpdwDisposition
    ) {
        std::wstring subKeyStr = lpSubKey ? lpSubKey : L"";
        std::string utf8SubKey = WStringToString(subKeyStr);

        if (utf8SubKey.find("Run") != std::string::npos ||
            utf8SubKey.find("RunOnce") != std::string::npos ||
            utf8SubKey.find("Image File Execution Options") != std::string::npos) {

            std::ostringstream ss;
            ss << "[REGISTRY-PERSISTENCE] Persistence Key Access / Creation Detected!\r\n";
            ss << "  -> Target SubKey: " << utf8SubKey << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("RegistryPersistenceKey", ss.str(), ThreatCorrelator::ThreatLevel::High);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    }

    static LSTATUS WINAPI Hooked_RegSetValueExW(
        HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        const BYTE* lpData,
        DWORD cbData
    ) {
        std::wstring valNameStr = lpValueName ? lpValueName : L"(Default)";
        std::string utf8ValName = WStringToString(valNameStr);

        std::string dataSnippet = "";
        if (lpData && cbData > 0 && dwType == REG_SZ) {
            std::wstring dataW((wchar_t*)lpData, min(cbData / 2, 100));
            dataSnippet = WStringToString(dataW);
        }

        std::ostringstream ss;
        ss << "[REGISTRY-AUDIT] Registry Value Write Intercepted!\r\n";
        ss << "  -> Value Name: " << utf8ValName << "\r\n";
        ss << "  -> Data Payload Size: " << cbData << " bytes\r\n";
        if (!dataSnippet.empty()) {
            ss << "  -> Data Value: " << dataSnippet << "\r\n";
        }

        ThreatCorrelator::GetInstance().IngestEvent("RegistryValueWrite", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }

    static void InitializeRegistryPersistenceHooks() {
        HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvapi32) {
            hAdvapi32 = LoadLibraryW(L"advapi32.dll");
        }
        if (!hAdvapi32) return;

        Original_RegCreateKeyExW = (pfnRegCreateKeyExW)GetProcAddress(hAdvapi32, "RegCreateKeyExW");
        Original_RegSetValueExW = (pfnRegSetValueExW)GetProcAddress(hAdvapi32, "RegSetValueExW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_RegCreateKeyExW) {
            DetourAttach(&(PVOID&)Original_RegCreateKeyExW, Hooked_RegCreateKeyExW);
        }
        if (Original_RegSetValueExW) {
            DetourAttach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeRegistryPersistenceHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_RegCreateKeyExW) {
            DetourDetach(&(PVOID&)Original_RegCreateKeyExW, Hooked_RegCreateKeyExW);
        }
        if (Original_RegSetValueExW) {
            DetourDetach(&(PVOID&)Original_RegSetValueExW, Hooked_RegSetValueExW);
        }

        DetourTransactionCommit();
    }
};

#endif
