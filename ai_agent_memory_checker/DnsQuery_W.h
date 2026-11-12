// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DNSQUERY_W_H
#define DNSQUERY_W_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <winsock2.h>
#include <windns.h>
#include "detours.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

typedef int (WSAAPI *pfnGetAddrInfoW)(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW* ppResult
);

typedef DNS_STATUS (WINAPI *pfnDnsQuery_W)(
    PCWSTR pszName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD* ppQueryResults,
    PVOID* pReserved
);

class CDnsQueryAudit {
public:
    static pfnGetAddrInfoW Original_GetAddrInfoW;
    static pfnDnsQuery_W Original_DnsQuery_W;

    static int WSAAPI Hooked_GetAddrInfoW(
        PCWSTR pNodeName,
        PCWSTR pServiceName,
        const ADDRINFOW* pHints,
        PADDRINFOW* ppResult
    ) {
        if (pNodeName) {
            std::wstring node(pNodeName);
            std::string utf8Node = WStringToString(node);

            std::ostringstream ss;
            ss << "[DNS-AUDIT] DNS Resolution Request (getaddrinfo): " << utf8Node << "\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("DnsQueryLookup", ss.str(), ThreatCorrelator::ThreatLevel::Low);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    static DNS_STATUS WINAPI Hooked_DnsQuery_W(
        PCWSTR pszName,
        WORD wType,
        DWORD Options,
        PVOID pExtra,
        PDNS_RECORD* ppQueryResults,
        PVOID* pReserved
    ) {
        if (pszName) {
            std::wstring name(pszName);
            std::string utf8Name = WStringToString(name);

            std::ostringstream ss;
            ss << "[DNS-AUDIT] Native DNS Query (DnsQuery_W): " << utf8Name << " (Type: " << wType << ")\r\n";

            ThreatCorrelator::GetInstance().IngestEvent("NativeDnsQuery", ss.str(), ThreatCorrelator::ThreatLevel::Low);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    static void InitializeDnsQueryAuditHooks() {
        HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
        if (!hWs2_32) hWs2_32 = LoadLibraryW(L"ws2_32.dll");

        HMODULE hDnsapi = GetModuleHandleW(L"dnsapi.dll");
        if (!hDnsapi) hDnsapi = LoadLibraryW(L"dnsapi.dll");

        if (hWs2_32) {
            Original_GetAddrInfoW = (pfnGetAddrInfoW)GetProcAddress(hWs2_32, "GetAddrInfoW");
        }
        if (hDnsapi) {
            Original_DnsQuery_W = (pfnDnsQuery_W)GetProcAddress(hDnsapi, "DnsQuery_W");
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetAddrInfoW) {
            DetourAttach(&(PVOID&)Original_GetAddrInfoW, Hooked_GetAddrInfoW);
        }
        if (Original_DnsQuery_W) {
            DetourAttach(&(PVOID&)Original_DnsQuery_W, Hooked_DnsQuery_W);
        }

        DetourTransactionCommit();
    }

    static void UninitializeDnsQueryAuditHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_GetAddrInfoW) {
            DetourDetach(&(PVOID&)Original_GetAddrInfoW, Hooked_GetAddrInfoW);
        }
        if (Original_DnsQuery_W) {
            DetourDetach(&(PVOID&)Original_DnsQuery_W, Hooked_DnsQuery_W);
        }

        DetourTransactionCommit();
    }
};

#endif
