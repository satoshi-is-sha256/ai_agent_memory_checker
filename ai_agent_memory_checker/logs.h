// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOGS_H
#define LOGS_H

#include "common.h"
#include <mutex>

// Singleton
class LogQueueManager {
private:
    LogQueueManager() {}
    std::vector<std::string> logQueue;
    std::mutex queueMutex;

public:
    static LogQueueManager &GetInstanceLeft() {
        static LogQueueManager LogQueue;
        return LogQueue;
    }

    static LogQueueManager &GetInstanceRight() {
        static LogQueueManager LogQueue;
        return LogQueue;
    }

    void PushLog(const std::string &log) {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push_back(log);
    }

    bool FlushLogs(std::vector<std::string> &outLogs) {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (logQueue.empty()) return false;

        outLogs = std::move(logQueue);
        logQueue.clear();
        return true;
    }

    void Reset() {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.clear();
    }
};

#endif