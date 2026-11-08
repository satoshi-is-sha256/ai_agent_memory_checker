// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RESOURCEMONITOR_H
#define RESOURCEMONITOR_H

#include "common.h"
#include <psapi.h>
#include <chrono>

struct ProcessMetrics {
    SIZE_T workingSetSize;
    SIZE_T privateUsage;
    double cpuUsagePercent;
    DWORD activeThreads;
};

class ResourceMonitor {
private:
    ULARGE_INTEGER m_lastSystemCpuTime;
    ULARGE_INTEGER m_lastProcessCpuTime;
    std::chrono::steady_clock::time_point m_lastCheckTime;

    ULARGE_INTEGER FileTimeToInt64(const FILETIME &ft) {
        ULARGE_INTEGER res;
        res.LowPart = ft.dwLowDateTime;
        res.HighPart = ft.dwHighDateTime;
        return res;
    }

public:
    ResourceMonitor() {
        m_lastCheckTime = std::chrono::steady_clock::now();

        FILETIME creation, exit, kernel, user;
        if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
            m_lastProcessCpuTime.QuadPart = FileTimeToInt64(kernel).QuadPart + FileTimeToInt64(user).QuadPart;
        }
    }

    ProcessMetrics MeasureMetrics(HANDLE hProcess = GetCurrentProcess()) {
        ProcessMetrics metrics = { 0, 0, 0.0, 0 };

        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            metrics.workingSetSize = pmc.WorkingSetSize;
            metrics.privateUsage = pmc.PrivateUsage;
        }

        return metrics;
    }

    std::string FormatMetricsReport(HANDLE hProcess = GetCurrentProcess()) {
        ProcessMetrics metrics = MeasureMetrics(hProcess);

        std::ostringstream ss;
        ss << "[RESOURCE-MONITOR] Real-time Process Resource Metrics:\r\n";
        ss << "  -> Working Set Size: " << (metrics.workingSetSize / 1024 / 1024) << " MB\r\n";
        ss << "  -> Private Memory Usage: " << (metrics.privateUsage / 1024 / 1024) << " MB\r\n";

        return ss.str();
    }
};

#endif