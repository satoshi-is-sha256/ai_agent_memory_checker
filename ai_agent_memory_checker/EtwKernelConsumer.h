// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ETWKERNELCONSUMER_H
#define ETWKERNELCONSUMER_H

#include "common.h"
#include "alpc.h"
#include "threatcorrelator.h"
#include <evntrace.h>
#include <evntcons.h>
#include <thread>
#include <atomic>

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// require: administrator
class EtwKernelConsumer {
private:
    TRACEHANDLE m_sessionHandle;
    TRACEHANDLE m_traceHandle;
    std::atomic<bool> m_isCollecting;
    std::thread m_consumerThread;

    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent, GUID ProcessTraceGuid) {
        if (pEvent->EventHeader.ProviderId == ProcessTraceGuid) {
            std::ostringstream ss;
            ss << "[ETW-KERNEL] Low-level process lifecycle event intercepted.\r\n";
            ThreatCorrelator::GetInstance().IngestEvent("EtwKernel", ss.str(), ThreatCorrelator::ThreatLevel::Medium);
            g_NtAlpcCreatePortLogs += ss.str();
        }
    }

    void ConsumerLoop(PROCESSTRACE_HANDLE traceHandle) {
        ProcessTrace(&traceHandle, 1, NULL, NULL);
    }

public:
    EtwKernelConsumer() : m_sessionHandle(0), m_traceHandle(0), m_isCollecting(false) {}

    ~EtwKernelConsumer() {
        StopCollection();
    }

    bool StartCollection() {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        EVENT_TRACE_PROPERTIES *pSessionProperties = (EVENT_TRACE_PROPERTIES *)malloc(bufferSize);
        if (!pSessionProperties) return false;

        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = bufferSize;
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->Wnode.ClientContext = 1;
        pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
        pSessionProperties->BufferSize = 64;
        pSessionProperties->MinimumBuffers = 2;
        pSessionProperties->MaximumBuffers = 10;
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD;

        TRACEHANDLE sessionHandle = 0;
        ULONG status = StartTraceW(&sessionHandle, KERNEL_LOGGER_NAMEW, pSessionProperties);
        free(pSessionProperties);

        if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
            return false;
        }

        m_sessionHandle = sessionHandle;
        m_isCollecting = true;
        return true;
    }

    void StopCollection() {
        if (m_isCollecting) {
            m_isCollecting = false;

            ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
            EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
            if (pSessionProperties) {
                ZeroMemory(pSessionProperties, bufferSize);
                pSessionProperties->Wnode.BufferSize = bufferSize;
                ControlTraceW(m_sessionHandle, KERNEL_LOGGER_NAMEW, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
                free(pSessionProperties);
            }
            if (m_traceHandle) {
                CloseTrace(m_traceHandle);
                m_traceHandle = 0;
            }

            m_sessionHandle = 0;
        }
    }

    std::string GetStatusReport() {
        std::ostringstream ss;
        ss << "[ETW-CONSUMER] Kernel-level ETW Trace Status:\r\n";
        ss << "  -> Collection Status: " << (m_isCollecting ? "ACTIVE (Subscribing to OS Kernel)" : "STOPPED") << "\r\n";
        ss << "  -> Target Events: Process, Thread, Image Load (Driver/DLL)\r\n";
        return ss.str();
    }
};

#endif