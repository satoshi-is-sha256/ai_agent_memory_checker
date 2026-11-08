// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HTTPTRAFFICINSPECTOR_H
#define HTTPTRAFFICINSPECTOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <wininet.h>
#include "detours.h"

#pragma comment(lib, "wininet.lib")

typedef BOOL(WINAPI *pfnHttpSendRequestW)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CHttpTrafficInspector {
public:
    static pfnHttpSendRequestW Original_HttpSendRequestW;

    static BOOL WINAPI Hooked_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
        if (lpOptional && dwOptionalLength > 0) {
            std::string payload(static_cast<char*>(lpOptional), dwOptionalLength);

            std::ostringstream ss;
            ss << "[HTTP-INSPECTOR] Outbound API Payload Intercepted!\r\n";
            ss << "  -> Payload Size: " << dwOptionalLength << " bytes\r\n";
            ss << "  -> Data Snippet: " << payload.substr(0, 200) << (payload.size() > 200 ? "..." : "") << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("HttpInspection", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }

    static void InitializeHttpTrafficHooks() {
        HMODULE hWinInet = GetModuleHandleW(L"wininet.dll");
        if (!hWinInet) {
            hWinInet = LoadLibraryW(L"wininet.dll");
        }
        if (!hWinInet) return;

        Original_HttpSendRequestW = (pfnHttpSendRequestW)GetProcAddress(hWinInet, "HttpSendRequestW");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_HttpSendRequestW) {
            DetourAttach(&(PVOID&)Original_HttpSendRequestW, Hooked_HttpSendRequestW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeHttpTrafficHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_HttpSendRequestW) {
            DetourDetach(&(PVOID&)Original_HttpSendRequestW, Hooked_HttpSendRequestW);
        }

        DetourTransactionCommit();
    }
};

#endif
