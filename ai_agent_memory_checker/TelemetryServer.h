// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TELEMETRYSERVER_H
#define TELEMETRYSERVER_H

#include "common.h"
#include <WinError.h>
#include <thread>
#include <atomic>

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// Singleton
class CTelemetryServer {
private:
    CTelemetryServer(const std::wstring &pipeName = L"\\\\.\\pipe\\AIAgentForensicsPipe") : m_pipeName(pipeName), m_isRunning(false), m_hPipe(INVALID_HANDLE_VALUE) {}

    std::wstring m_pipeName;
    std::atomic<bool> m_isRunning;
    std::thread m_serverThread;
    HANDLE m_hPipe;

    void ServerLoop() {
        while (m_isRunning) {
            m_hPipe = CreateNamedPipeW(
                m_pipeName.c_str(),
                PIPE_ACCESS_OUTBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                nullptr
            );

            if (m_hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                continue;
            }

            if (ConnectNamedPipe(m_hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_CONNECTION_ACTIVE)) {
                BroadcastEvent(g_NtAlpcCreatePortLogs);
            }

            DisconnectNamedPipe(m_hPipe);
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE;
        }
    }

public:

    ~CTelemetryServer() {
        Stop();
    }

    static CTelemetryServer &GetInstance() {
        static CTelemetryServer cs;
        return cs;
    }

    bool Start() {
        m_isRunning = true;
        m_serverThread = std::thread(&CTelemetryServer::ServerLoop, this);
        return true;
    }

    void Stop() {
        m_isRunning = false;
        if (m_hPipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(m_hPipe, nullptr);
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE;
        }
        if (m_serverThread.joinable()) {
            m_serverThread.join();
        }
    }

    bool BroadcastEvent(const std::string &jsonEventPayload) {
        if (m_hPipe == INVALID_HANDLE_VALUE) return false;

        DWORD bytesWritten = 0;
        BOOL success = WriteFile(
            m_hPipe,
            jsonEventPayload.data(),
            (DWORD)jsonEventPayload.size(),
            &bytesWritten,
            nullptr
        );

        return success == TRUE;
    }
};

#endif
