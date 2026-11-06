// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DNSRESOLUTIONMONITOR_H
#define DNSRESOLUTIONMONITOR_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "detours.h"

#pragma comment(lib, "ws2_32.lib")

typedef int(WINAPI *pfnGetaddrinfo)(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult
);

class CDnsResolution {
public:
    static pfnGetaddrinfo Original_getaddrinfo;

    static int WINAPI Hooked_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult) {
        if (pNodeName) {
            std::string hostName(pNodeName);

            if (hostName != "localhost" && hostName.find("127.0.0.1") == std::string::npos) {
                std::ostringstream ss;
                ss << "[DNS-WATCH] External Domain Resolution Intercepted!\r\n";
                ss << "  -> Target Hostname: " << hostName << "\r\n";

                TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Network, ss.str());
                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    static void InitializeDnsHooks() {
        HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
        if (!hWs2_32) return;

        Original_getaddrinfo = (pfnGetaddrinfo)GetProcAddress(hWs2_32, "getaddrinfo");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_getaddrinfo) {
            DetourAttach(&(PVOID&)Original_getaddrinfo, Hooked_getaddrinfo);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDnsHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_getaddrinfo) {
            DetourDetach(&(PVOID&)Original_getaddrinfo, Hooked_getaddrinfo);
        }
        DetourTransactionCommit();
    }

};

#endif