// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"
#include "alpc.h"
#include "detours.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

typedef int (WSAAPI *pfnConnect)(SOCKET s, const struct sockaddr* name, int namelen);
typedef BOOL(WINAPI *pfnHttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);


class CNetwork {
public:
    static pfnConnect Original_connect;
    static pfnHttpSendRequestW Original_HttpSendRequestW;

    static int WSAAPI Hooked_connect(SOCKET s, const struct sockaddr *name, int namelen) {
        if (name && name->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)name;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ipStr, sizeof(ipStr));
            int port = ntohs(addr->sin_port);

            std::ostringstream ss;
            ss << "[NETWORK-TCP] Outbound Connection -> Destination IP: " << ipStr << ":" << port << "\r\n";
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_connect(s, name, namelen);
    }

    static BOOL WINAPI Hooked_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
        if (lpOptional && dwOptionalLength > 0 && dwOptionalLength < 8192) {
            std::string payload((const char*)lpOptional, dwOptionalLength);

            if (payload.find("prompt") != std::string::npos ||
                payload.find("messages") != std::string::npos ||
                payload.find("content") != std::string::npos) {

                std::ostringstream ss;
                ss << "[NETWORK-HTTP-LEAK] AI Payload Outbound via WinINet!\r\n";
                ss << "  -> Payload Size: " << dwOptionalLength << " bytes\r\n";
                ss << "  -> Snippet: " << payload.substr(0, 300) << "\r\n";

                g_NtAlpcCreatePortLogs += ss.str();
            }
        }

        return Original_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }

    static void InitializeNetworkHooks() {
        HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
        HMODULE hWininet = GetModuleHandleW(L"wininet.dll");

        if (hWs2_32) {
            Original_connect = (pfnConnect)GetProcAddress(hWs2_32, "connect");
        }
        if (hWininet) {
            Original_HttpSendRequestW = (pfnHttpSendRequestW)GetProcAddress(hWininet, "HttpSendRequestW");
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_connect) {
            DetourAttach(&(PVOID&)Original_connect, Hooked_connect);
        }
        if (Original_HttpSendRequestW) {
            DetourAttach(&(PVOID&)Original_HttpSendRequestW, Hooked_HttpSendRequestW);
        }

        DetourTransactionCommit();
    }

    static void UninitializeNetworkHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (Original_connect) {
            DetourDetach(&(PVOID&)Original_connect, Hooked_connect);
        }
        if (Original_HttpSendRequestW) {
            DetourDetach(&(PVOID&)Original_HttpSendRequestW, Hooked_HttpSendRequestW);
        }
        DetourTransactionCommit();
    }
};

#endif