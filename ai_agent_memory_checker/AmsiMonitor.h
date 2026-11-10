// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef AMSIMONITOR_H
#define AMSIMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HRESULT(WINAPI *pfnAmsiScanBuffer)(
    PVOID amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    PVOID amsiSession,
    DWORD* result
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CAmsiMonitor {
public:
    static pfnAmsiScanBuffer Original_AmsiScanBuffer;

    static HRESULT WINAPI Hooked_AmsiScanBuffer(
        PVOID amsiContext,
        PVOID buffer,
        ULONG length,
        LPCWSTR contentName,
        PVOID amsiSession,
        DWORD* result
    ) {
        if (buffer && length > 0) {
            std::string scriptSnippet;
            if (length > 2 && ((WCHAR*)buffer)[0] != 0) {
                std::wstring wstr((WCHAR*)buffer, min(length / 2, 200));
                scriptSnippet = WStringToString(wstr);
            }
            else {
                char *cstr = (char *)buffer;
                scriptSnippet = std::string(cstr, min(length, 200));
            }

            std::wstring wContentName = contentName ? contentName : L"UnknownScript";
            std::string utf8ContentName = WStringToString(wContentName);

            std::ostringstream ss;
            ss << "[AMSI-AUDIT] Dynamic Script / Payload Scan Intercepted!\r\n";
            ss << "  -> Content Name / Context: " << utf8ContentName << "\r\n";
            ss << "  -> Payload Size: " << length << " bytes\r\n";
            ss << "  -> Snippet: " << scriptSnippet << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("AmsiScan", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);
    }

    static void InitializeAmsiHooks() {
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (!hAmsi) {
            hAmsi = LoadLibraryW(L"amsi.dll");
        }
        if (!hAmsi) return;

        Original_AmsiScanBuffer = (pfnAmsiScanBuffer)GetProcAddress(hAmsi, "AmsiScanBuffer");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_AmsiScanBuffer) {
            DetourAttach(&(PVOID&)Original_AmsiScanBuffer, Hooked_AmsiScanBuffer);
        }

        DetourTransactionCommit();
    }

    static void UninitializeAmsiHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_AmsiScanBuffer) {
            DetourDetach(&(PVOID&)Original_AmsiScanBuffer, Hooked_AmsiScanBuffer);
        }

        DetourTransactionCommit();
    }
};

#endif
