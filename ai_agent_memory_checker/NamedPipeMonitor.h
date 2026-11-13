// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAMEDPIPEMONITOR_H
#define NAMEDPIPEMONITOR_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include "detours.h"

typedef HANDLE(WINAPI *pfnCreateNamedPipeW)(
    LPCWSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );

typedef BOOL(WINAPI *pfnConnectNamedPipe)(
    HANDLE hNamedPipe,
    LPOVERLAPPED lpOverlapped
    );

typedef BOOL(WINAPI *PFN_WRITEFILE)(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped
    );

class CNamedPipeMonitor {
public:
    static pfnCreateNamedPipeW Original_CreateNamedPipeW;
    static pfnConnectNamedPipe Original_ConnectNamedPipe;
    static PFN_WRITEFILE Real_WriteFile;

    static HANDLE WINAPI Hooked_CreateNamedPipeW(
        LPCWSTR lpName,
        DWORD dwOpenMode,
        DWORD dwPipeMode,
        DWORD nMaxInstances,
        DWORD nOutBufferSize,
        DWORD nInBufferSize,
        DWORD nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ) {
        std::wstring pipeName(lpName ? lpName : L"");
        std::string utf8PipeName = WStringToString(pipeName);

        std::ostringstream ss;
        ss << "[NAMED-PIPE] Named Pipe Creation Intercepted!\r\n";
        ss << "  -> Pipe Name: " << utf8PipeName << "\r\n";
        ss << "  -> Open Mode: 0x" << std::hex << dwOpenMode << std::dec << "\r\n";

        ThreatCorrelator::GetInstance().IngestEvent("NamedPipe", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();

        if (IsElectronOrMojoPipe(lpName)) {
            std::ostringstream ss2;
            ss2 << "[MojoIPC Audit] Target IPC Pipe Created: " << utf8PipeName << "\r\n";
            ThreatCorrelator::GetInstance().IngestEvent("MojoIPC Audit Pipe Created", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
            g_NtAlpcCreatePortLogs += ss.str();
        }

        return Original_CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    }

    static BOOL WINAPI Hooked_ConnectNamedPipe(
        HANDLE hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ) {
        std::ostringstream ss;
        ss << "[NAMED-PIPE] Client Connection Established on Pipe Handle: 0x" << std::hex << (uintptr_t)hNamedPipe << std::dec << "\r\n";

        g_NtAlpcCreatePortLogs += ss.str();

        return Original_ConnectNamedPipe(hNamedPipe, lpOverlapped);
    }

    static BOOL WINAPI Hooked_WriteFile(
        HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped
    ) {
        if (hFile != INVALID_HANDLE_VALUE && lpBuffer != nullptr && nNumberOfBytesToWrite > 0) {
            InspectIpcPayload(reinterpret_cast<const unsigned char*>(lpBuffer), static_cast<size_t>(nNumberOfBytesToWrite), L"OUTBOUND (Write)");
        }

        return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    static bool IsElectronOrMojoPipe(LPCWSTR pipeName) {
        if (pipeName == nullptr) return false;
        if (wcsstr(pipeName, L"mojo") != nullptr ||
            wcsstr(pipeName, L"electron") != nullptr ||
            wcsstr(pipeName, L"chrome") != nullptr) {
            return true;
        }
        return false;
    }

    static void InspectIpcPayload(const unsigned char *data, size_t size, const wchar_t *direction) {
        if (size == 0 || data == nullptr) return;

        std::ostringstream ss;
        ss << "[MojoIPC Audit] Direction: " << WStringToString(std::wstring(direction)) << " Payload Size: " << size << "\r\n";
        ThreatCorrelator::GetInstance().IngestEvent("MojoIPC Audit Payload", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
        g_NtAlpcCreatePortLogs += ss.str();
    }

    static void InitializeNamedPipeHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        Original_CreateNamedPipeW = (pfnCreateNamedPipeW)GetProcAddress(hKernel32, "CreateNamedPipeW");
        Original_ConnectNamedPipe = (pfnConnectNamedPipe)GetProcAddress(hKernel32, "ConnectNamedPipe");
        Real_WriteFile = WriteFile;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CreateNamedPipeW) {
            DetourAttach(&(PVOID&)Original_CreateNamedPipeW, Hooked_CreateNamedPipeW);
        }
        if (Original_ConnectNamedPipe) {
            DetourAttach(&(PVOID&)Original_ConnectNamedPipe, Hooked_ConnectNamedPipe);
        }

        DetourTransactionCommit();
    }

    static void UninitializeNamedPipeHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (Original_CreateNamedPipeW) {
            DetourDetach(&(PVOID&)Original_CreateNamedPipeW, Hooked_CreateNamedPipeW);
        }
        if (Original_ConnectNamedPipe) {
            DetourDetach(&(PVOID&)Original_ConnectNamedPipe, Hooked_ConnectNamedPipe);
        }

        DetourTransactionCommit();
    }
};

#endif
