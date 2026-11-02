// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TIMELINECORRELATOR_H
#define TIMELINECORRELATOR_H

#include "common.h"
#include <mutex>
#include <algorithm>

// Singleton
class TimelineCorrelator {
public:
    enum class TimelineCategory {
        ALPC,
        SharedMemory,
        NamedPipe,
        FileIO,
        Network,
        Alert
    };

    struct TimelineEvent {
        int64_t timestampMs;
        DWORD pid;
        std::string processName;
        TimelineCategory category;
        std::string details;

        bool operator<(const TimelineEvent &other) const {
            return timestampMs < other.timestampMs;
        }
    };

private:
    TimelineCorrelator() {}

    std::vector<TimelineEvent> m_events;
    std::mutex m_mutex;
    size_t m_maxCapacity = 10000;

    int64_t GetCurrentTimestampMs() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }

    std::string CategoryToString(TimelineCategory cat) {
        switch (cat) {
        case TimelineCategory::ALPC:         return "[ALPC]";
        case TimelineCategory::SharedMemory: return "[SHARED-MEM]";
        case TimelineCategory::NamedPipe:    return "[PIPE]";
        case TimelineCategory::FileIO:       return "[FILE-IO]";
        case TimelineCategory::Network:      return "[NETWORK]";
        case TimelineCategory::Alert:        return "[ALERT]";
        default:                             return "[UNKNOWN]";
        }
    }

public:
    static TimelineCorrelator &GetInstance() {
        static TimelineCorrelator timeline;
        return timeline;
    }

    void PushEvent(DWORD pid, const std::string &processName, TimelineCategory category, const std::string &details) {
        std::lock_guard<std::mutex> lock(m_mutex);

        TimelineEvent ev;
        ev.timestampMs = GetCurrentTimestampMs();
        ev.pid = pid;
        ev.processName = processName;
        ev.category = category;
        ev.details = details;

        m_events.push_back(ev);
        if (m_events.size() > m_maxCapacity) {
            m_events.erase(m_events.begin());
        }
    }

    std::vector<TimelineEvent> GetSortedTimeline() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<TimelineEvent> sortedEvents = m_events;
        std::sort(sortedEvents.begin(), sortedEvents.end());
        return sortedEvents;
    }

    std::string FormatEventToString(const TimelineEvent &ev) {
        auto timeT = (time_t)(ev.timestampMs / 1000);
        int ms = (int)(ev.timestampMs % 1000);
        std::tm tm{};
        localtime_s(&tm, &timeT);

        std::ostringstream ss;
        ss  << std::put_time(&tm, "%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms
            << " | PID:" << ev.pid << " (" << ev.processName << ") "
            << CategoryToString(ev.category) << " " << ev.details;
        return ss.str();
    }
};

#endif