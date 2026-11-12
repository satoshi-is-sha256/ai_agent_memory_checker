// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTOPATHAUDIT_H
#define CRYPTOPATHAUDIT_H

#include "common.h"
#include "alpc.h"
#include <winsock2.h>
#include <wininet.h>
#include "detours.h"
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

typedef int (WSAAPI *PFN_SEND)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI *PFN_WSASEND)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef BOOL(WINAPI *PFN_HTTPSENDREQUESTW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class CCryptoPathAudit {
public: 
    static PFN_SEND Real_send;
    static PFN_WSASEND Real_WSASend;
    static PFN_HTTPSENDREQUESTW Real_HttpSendRequestW;

    static void InspectPlaintextData(const unsigned char* data, size_t size, const wchar_t* sourceAPI) {
        if (size == 0 || data == nullptr) return;

        std::ostringstream ss;
        ss << "[CryptoAudit] API: " << WStringToString(sourceAPI) << " Size: " << size << "\r\n";
        g_NtAlpcCreatePortLogs += ss.str();
    }

    static int WSAAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
        if (len > 0 && buf != nullptr) {
            InspectPlaintextData(reinterpret_cast<const unsigned char*>(buf), static_cast<size_t>(len), L"send");
        }
        return Real_send(s, buf, len, flags);
    }

    static int WSAAPI Hooked_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
        if (lpBuffers != nullptr) {
            for (DWORD i = 0; i < dwBufferCount; i++) {
                if (lpBuffers[i].buf != nullptr && lpBuffers[i].len > 0) {
                    InspectPlaintextData(reinterpret_cast<const unsigned char*>(lpBuffers[i].buf), lpBuffers[i].len, L"WSASend");
                }
            }
        }
        return Real_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    }

    static BOOL WINAPI Hooked_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
        if (lpOptional != nullptr && dwOptionalLength > 0) {
            InspectPlaintextData(reinterpret_cast<const unsigned char*>(lpOptional), static_cast<size_t>(dwOptionalLength), L"HttpSendRequestW");
        }
        return Real_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }

    static bool InitializeCryptoPathAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        Real_send = send;
        Real_WSASend = WSASend;
        Real_HttpSendRequestW = HttpSendRequestW;

        DetourAttach(&(PVOID&)Real_send, Hooked_send);
        DetourAttach(&(PVOID&)Real_WSASend, Hooked_WSASend);
        DetourAttach(&(PVOID&)Real_HttpSendRequestW, Hooked_HttpSendRequestW);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }

    static bool UninitializeCryptoPathAudit() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)Real_send, Hooked_send);
        DetourDetach(&(PVOID&)Real_WSASend, Hooked_WSASend);
        DetourDetach(&(PVOID&)Real_HttpSendRequestW, Hooked_HttpSendRequestW);

        LONG error = DetourTransactionCommit();
        return (error == NO_ERROR);
    }
};

#endif
