// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THREATCORRELATOR_H
#define THREATCORRELATOR_H

#include "common.h"
#include "alpc.h"
#include "timelinecorrelator.h"

//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
// Singleton
class ThreatCorrelator {
public:
    enum class ThreatLevel {
        Low,
        Medium,
        High,
        Critical
    };

    struct ForensicEvent {
        std::string timestamp;
        std::string category; // "Registry", "Clipboard", "Network", "Injection", etc.
        std::string details;
        ThreatLevel baseThreat;
        ForensicEvent() { baseThreat = ThreatLevel::Low; }
    };

    void IngestEvent(const std::string& category, const std::string &details, ThreatLevel level) {
        ForensicEvent ev;
        ev.timestamp = GetCurrentTimestamp();
        ev.category = category;
        ev.details = details;
        ev.baseThreat = level;

        m_eventStream.push_back(ev);
        EvaluateBehavioralPattern();
    }

    void EvaluateBehavioralPattern() {
        int clipboardReads = 0;
        int externalNetworkConn = 0;

        for (const auto& ev : m_eventStream) {
            if (ev.category == "Clipboard") clipboardReads++;
            if (ev.category == "Network") externalNetworkConn++;
        }

        if (clipboardReads > 0 && externalNetworkConn > 0) {
            // High-risk correlation detected!
            g_NtAlpcCreatePortLogs += std::string("[CORRELATOR-ALERT] Potential Data Exfiltration Chain Detected!\n");
        }
    }

    size_t GetTotalEventsCount() const {
        return m_eventStream.size();
    }

    static ThreatCorrelator &GetInstance() {
        static ThreatCorrelator tcr;
        return tcr;
    }

private:
    ThreatCorrelator() {}

    std::vector<ForensicEvent> m_eventStream;

    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream ss;
        struct tm buf;
        localtime_s(&buf, &in_time_t);
        ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

#endif