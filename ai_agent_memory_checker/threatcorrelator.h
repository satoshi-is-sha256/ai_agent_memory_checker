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

    std::string ThreatLevelToString(ThreatLevel level) {
        if(level == ThreatLevel::Low)
            return "Low";
        else if (level == ThreatLevel::Medium)
            return "Medium";
        else if (level == ThreatLevel::High)
            return "High";
        else
            return "Critical";
    }

    struct ThreatAlert {
        std::string timestamp;
        std::string category;
        ThreatLevel level;
        std::string details;
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

    std::string GenerateCorrelationReport() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::ostringstream ss;

        ss << "=== THREAT CORRELATION & AUDIT SUMMARY ===\r\n";
        ss << "Cumulative Risk Score: " << m_cumulativeScore << "\r\n";
        ss << "Total Intercepted Alerts: " << m_alerts.size() << "\r\n";
        ss << "Threat Status: " << (m_cumulativeScore > 50 ? "[CRITICAL ALERT] Active Attack Kill-Chain Detected!" : "[STABLE] Normal Monitoring") << "\r\n\r\n";

        ss << "--- Detailed Alert Timeline ---\r\n";
        for (const auto& alert : m_alerts) {
            ss << "[" << alert.timestamp << "] [" << alert.category << "] "
               << "Severity: " << ThreatLevelToString(alert.level) << "\r\n"
               << "  -> " << alert.details << "\r\n";
        }

        return ss.str();
    }

    size_t GetTotalEventsCount() const {
        return m_eventStream.size();
    }

    static ThreatCorrelator &GetInstance() {
        static ThreatCorrelator tcr;
        return tcr;
    }

private:
    ThreatCorrelator() : m_cumulativeScore(0) {}

    std::vector<ForensicEvent> m_eventStream;

    std::vector<ThreatAlert> m_alerts;
    std::mutex m_mutex;
    int m_cumulativeScore;

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