// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETWSESSIONMONITOR_H
#define ETWSESSIONMONITOR_H

#include "common.h"
#include "alpc.h"
#include <evntrace.h>
#include <evntcons.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "tdh.lib")

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// Singleton
class CEtwSessionMonitor {
private:
    TRACEHANDLE m_sessionHandle;
    TRACEHANDLE m_traceHandle;
    std::atomic<bool> m_isListening;
    std::thread m_consumerThread;
    std::wstring m_sessionName;

    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
        if (pEvent) {
            DWORD pid = pEvent->EventHeader.ProcessId;
            USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

            std::ostringstream ss;
            ss << "[ETW-EVENT] PID: " << pid << ", EventID: " << eventId << std::endl;
            g_NtAlpcCreatePortLogs += ss.str();
        }
    }

    CEtwSessionMonitor(const std::wstring &sessionName = L"AIAgentEtwSession") : m_sessionHandle(0), m_traceHandle(0), m_isListening(false), m_sessionName(sessionName) {}

    void ConsumerLoop() {
        ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
    }

public:
    static CEtwSessionMonitor &GetInstance() {
        static CEtwSessionMonitor esm;
        return esm;
    }

    ~CEtwSessionMonitor() {
        Stop();
    }

    bool Start() {
        m_isListening = true;
        m_consumerThread = std::thread(&CEtwSessionMonitor::ConsumerLoop, this);
        return true;
    }

    void Stop() {
        if (m_isListening) {
            m_isListening = false;
            if (m_traceHandle) {
                CloseTrace(m_traceHandle);
                m_traceHandle = 0;
            }
            if (m_consumerThread.joinable()) {
                m_consumerThread.join();
            }
        }
    }
};

#endif
