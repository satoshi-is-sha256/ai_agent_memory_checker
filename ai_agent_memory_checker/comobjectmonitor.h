// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COMOBJECTMONITOR_H
#define COMOBJECTMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <objbase.h>
#include <iomanip>
#include "detours.h"

#pragma comment(lib, "ole32.lib")

typedef HRESULT(STDAPICALLTYPE *pfnCoCreateInstance)(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID* ppv
    );

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CComObjectMonitor {
private:
    static std::string ClsidToString(REFCLSID rclsid) {
        LPOLESTR lpszGuid = nullptr;
        if (SUCCEEDED(StringFromCLSID(rclsid, &lpszGuid))) {
            std::wstring ws(lpszGuid);
            CoTaskMemFree(lpszGuid);
            return WStringToString(ws);
        }
        return "{UNKNOWN-CLSID}";
    }

public:
    static pfnCoCreateInstance Original_CoCreateInstance;

    static HRESULT STDAPICALLTYPE Hooked_CoCreateInstance(
        REFCLSID rclsid,
        LPUNKNOWN pUnkOuter,
        DWORD dwClsContext,
        REFIID riid,
        LPVOID *ppv
    ) {
        std::string clsidStr = ClsidToString(rclsid);

        std::ostringstream ss;
        ss << "[COM-WATCH] COM Object Activation Intercepted!\r\n";
        ss << "  -> Target CLSID: " << clsidStr << "\r\n";
        ss << "  -> Context Flag: 0x" << std::hex << dwClsContext << std::dec << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("COM", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();

        return Original_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    }

    static void InitializeComHooks() {
        HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
        if (!hOle32) {
            hOle32 = LoadLibraryW(L"ole32.dll");
        }
        if (!hOle32) return;

        Original_CoCreateInstance = (pfnCoCreateInstance)GetProcAddress(hOle32, "CoCreateInstance");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CoCreateInstance) {
            DetourAttach(&(PVOID&)Original_CoCreateInstance, Hooked_CoCreateInstance);
        }

        DetourTransactionCommit();
    }

    static void UninitializeComHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_CoCreateInstance) {
            DetourDetach(&(PVOID&)Original_CoCreateInstance, Hooked_CoCreateInstance);
        }
        DetourTransactionCommit();
    }
};

#endif
