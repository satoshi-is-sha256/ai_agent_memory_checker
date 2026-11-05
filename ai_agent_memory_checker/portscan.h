// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PORTSCAN_H
#define PORTSCAN_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"
#include "detours.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

typedef int(WINAPI *pfnBind)(
    SOCKET s,
    const sockaddr *name,
    int namelen
);

typedef int(WINAPI *pfnConnect)(
    SOCKET s,
    const sockaddr *name,
    int namelen
);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CPortScan {
public:
    static pfnBind Original_bind;
    static pfnConnect Original_connect;

    static int WINAPI Hooked_bind(SOCKET s, const sockaddr *name, int namelen) {
        if (name && name->sa_family == AF_INET) {
            const sockaddr_in *addr = reinterpret_cast<const sockaddr_in *>(name);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr));
            u_short port = ntohs(addr->sin_port);

            std::ostringstream ss;
            ss << "[LOOPBACK-BIND] Local Server/Listener Spun Up -> " << ipStr << ":" << port << "\r\n";

            TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Network, ss.str());
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_bind(s, name, namelen);
    }

    static int WINAPI Hooked_connect(SOCKET s, const sockaddr *name, int namelen) {
        if (name && name->sa_family == AF_INET) {
            const sockaddr_in *addr = reinterpret_cast<const sockaddr_in *>(name);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr));
            u_short port = ntohs(addr->sin_port);

            if (std::string(ipStr) == "127.0.0.1" || std::string(ipStr) == "::1") {
                std::ostringstream ss;
                ss << "[LOOPBACK-CONNECT] Internal Loopback Outbound -> " << ipStr << ":" << port << "\r\n";

                TimelineCorrelator::GetInstance().PushEvent(GetCurrentProcessId(), "AgentHost", TimelineCorrelator::TimelineCategory::Network, ss.str());
                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return Original_connect(s, name, namelen);
    }

    static void InitializeLoopbackHooks() {
        HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
        if (!hWs2_32) return;

        Original_bind = (pfnBind)GetProcAddress(hWs2_32, "bind");
        Original_connect = (pfnConnect)GetProcAddress(hWs2_32, "connect");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_bind) {
            DetourAttach(&(PVOID&)Original_bind, Hooked_bind);
        }
        if (Original_connect) {
            DetourAttach(&(PVOID&)Original_connect, Hooked_connect);
        }

        DetourTransactionCommit();
    }

    static void UninitializeLoopbackHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_bind) {
            DetourDetach(&(PVOID&)Original_bind, Hooked_bind);
        }
        if (Original_connect) {
            DetourDetach(&(PVOID&)Original_connect, Hooked_connect);
        }
        DetourTransactionCommit();
    }
};

#endif
