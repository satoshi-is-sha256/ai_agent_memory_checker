// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DPAPIMONITOR_H
#define DPAPIMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <wincrypt.h>
#include "detours.h"

#pragma comment(lib, "crypt32.lib")

typedef BOOL (WINAPI *pfnCryptUnprotectData)(
    DATA_BLOB* pDataIn,
    LPWSTR* ppszDataDescr,
    DATA_BLOB* pOptionalEntropy,
    PVOID pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB* pDataOut
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCryptoPapiMonitor {
public:
    static pfnCryptUnprotectData Original_CryptUnprotectData;

    static BOOL WINAPI Hooked_CryptUnprotectData(
        DATA_BLOB* pDataIn,
        LPWSTR* ppszDataDescr,
        DATA_BLOB* pOptionalEntropy,
        PVOID pvReserved,
        CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
        DWORD dwFlags,
        DATA_BLOB* pDataOut
    ) {
        std::wstring descr = L"No Description";
        if (ppszDataDescr && *ppszDataDescr) {
            descr = *ppszDataDescr;
        }

        std::string utf8Descr = WStringToString(descr);

        std::ostringstream ss;
        ss << "[DPAPI-WATCH] Sensitive Credential Decryption Intercepted!\r\n";
        ss << "  -> Data Description: " << utf8Descr << "\r\n";
        ss << "  -> Encrypted Size (Bytes): " << (pDataIn ? pDataIn->cbData : 0) << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("DPAPI", ss.str(), ThreatCorrelator::ThreatLevel::High);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_CryptUnprotectData(
            pDataIn,
            ppszDataDescr,
            pOptionalEntropy,
            pvReserved,
            pPromptStruct,
            dwFlags,
            pDataOut
        );
    }

    static void InitializeDpapiHooks() {
        HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
        if (!hCrypt32) return;

        Original_CryptUnprotectData = (pfnCryptUnprotectData)GetProcAddress(hCrypt32, "CryptUnprotectData");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CryptUnprotectData) {
            DetourAttach(&(PVOID&)Original_CryptUnprotectData, Hooked_CryptUnprotectData);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDpapiHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_CryptUnprotectData) {
            DetourDetach(&(PVOID&)Original_CryptUnprotectData, Hooked_CryptUnprotectData);
        }
        DetourTransactionCommit();
    }
};

#endif
