// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOCALLLMAUDIT_H
#define LOCALLLMAUDIT_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "detours.h"
#include <stdio.h>
#include <unordered_set>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

typedef int (WSAAPI *PFN_CONNECT)(SOCKET s, const sockaddr *name, int namelen);
typedef int (WSAAPI *PFN_SEND)(SOCKET s, const char* buf, int len, int flags);

class CLocalLlmAudit {
private:
    static std::unordered_set<SOCKET> g_AiSockets;
    static std::mutex g_SocketMutex;
    static const std::unordered_set<USHORT> kAiSidecarPorts;

public:
    static PFN_CONNECT Real_connect;
    static PFN_SEND Real_send;

    static bool IsLocalAiSidecarAddress(const sockaddr* addr) {
        if (addr == nullptr) return false;

        USHORT port = 0;
        bool isLoopback = false;

        if (addr->sa_family == AF_INET) {
            const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(addr);
            port = ntohs(sin->sin_port);
            // 127.0.0.1
            if ((ntohl(sin->sin_addr.s_addr) & 0xFF000000) == 0x7F000000) {
                isLoopback = true;
            }
        } else if (addr->sa_family == AF_INET6) {
            const sockaddr_in6* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            port = ntohs(sin6->sin6_port);
            // ::1 IPv6 loopback
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
                isLoopback = true;
            }
        }

        if (isLoopback && kAiSidecarPorts.find(port) != kAiSidecarPorts.end()) {
            return true;
        }
        return false;
    }

    static void InspectLlmPayload(const char* data, int len) {
        if (data == nullptr || len <= 0) return;

        std::ostringstream ss;
        ss << "[LocalLLM Audit] Intercepted Local AI Request Payload (" << len << " bytes)\r\n";
        ThreatCorrelator::GetInstance().IngestEvent("[LocalLLM Audit] Intercepted Local AI", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();
    }

    static int WSAAPI Hooked_connect(SOCKET s, const sockaddr* name, int namelen) {
        if (IsLocalAiSidecarAddress(name)) {
            std::lock_guard<std::mutex> lock(g_SocketMutex);
            g_AiSockets.insert(s);

            std::ostringstream ss;
            ss << "[LocalLLM Audit] Connected to Local AI Sidecar Socket: " << s << "\r\n";
            ThreatCorrelator::GetInstance().IngestEvent("[LocalLLM Audit] Connected to Local AI", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
            g_NtAlpcCreatePortLogs += ss.str();
        }
        return Real_connect(s, name, namelen);
    }

    static int WSAAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
        bool isAiSocket = false;
        {
            std::lock_guard<std::mutex> lock(g_SocketMutex);
            if (g_AiSockets.find(s) != g_AiSockets.end()) {
                isAiSocket = true;
            }
        }

        if (isAiSocket) {
            InspectLlmPayload(buf, len);
        }

        return Real_send(s, buf, len, flags);
    }

    static bool InitializeLocalLlmAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)Real_connect, Hooked_connect);
        DetourAttach(&(PVOID&)Real_send, Hooked_send);

        Real_connect = connect;
        Real_send = send;

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }

    static bool UninitializeLocalLlmAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)Real_connect, Hooked_connect);
        DetourDetach(&(PVOID&)Real_send, Hooked_send);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }
};

#endif
