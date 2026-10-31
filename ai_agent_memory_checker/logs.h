// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOGS_H
#define LOGS_H

#include "common.h"
#include <mutex>
#include <fstream>

extern std::string g_NtAlpcCreatePortLogs; // main.cpp

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

class SignatureEngine {
public:
    enum class LogCategory {
        ALPC,
        SharedMemory,
        NamedPipe,
        FileIO,
        Alert
    };

    struct StatisticsTracker {
        std::atomic<uint64_t> alpcCount{ 0 };
        std::atomic<uint64_t> sharedMemCount{ 0 };
        std::atomic<uint64_t> pipeCount{ 0 };
        std::atomic<uint64_t> fileIOCount{ 0 };
        std::atomic<uint64_t> alertCount{ 0 };
    };
    static StatisticsTracker g_Stats;

    static bool ScanAndAlert(const std::string &data, LogCategory category, DWORD pid, std::string &outMatchedRule) {
        static const std::regex apiPattern("(sk-[a-zA-Z0-9]{20,}|ant_api_[a-zA-Z0-9]{20,})");
        static const std::regex keywordPattern("(prompt|messages|confidential|password|api_key)", std::regex_constants::icase);

        std::smatch match;
        if (std::regex_search(data, match, apiPattern)) {
            outMatchedRule = "API_KEY_LEAK: " + match[0].str();
            g_Stats.alertCount++;
            return true;
        }
        if (std::regex_search(data, match, keywordPattern)) {
            outMatchedRule = "KEYWORD_MATCH: " + match[0].str();
            return true;
        }

        return false;
    }
};

// Singleton
//
// The logs hooked here are output from the log strings defined in alpc.h (g_NtAlpcCreatePortLogs).
//
class ForensicArchiver : public SignatureEngine {
private:
    ForensicArchiver() {
        CreateDirectoryA(m_outputDir.c_str(), nullptr);
    }

    std::mutex m_fileMutex;
    std::string m_outputDir = "C:\\ForensicsDumps\\";

public:
    static ForensicArchiver &GetInstance() {
        static ForensicArchiver g_Archiver;
        return g_Archiver;
    }

    void SaveDump(DWORD pid, const std::string& processName, LogCategory category, const std::string &content) {
        std::lock_guard<std::mutex> lock(m_fileMutex);

        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << m_outputDir << "PID_" << pid << "_" << processName << "_";

        std::tm bt{};
        localtime_s(&bt, &in_time_t);
        ss << std::put_time(&bt, "%Y%m%d_%H%M%S") << ".log";

        std::ofstream file(ss.str(), std::ios::app);
        if (file.is_open()) {
            file << "=== FORENSIC DUMP ===" << "\n";
            file << "PID: " << pid << " | Process: " << processName << "\n";
            file << "Category: " << static_cast<int>(category) << "\n";
            file << "Timestamp: " << std::put_time(&bt, "%Y-%m-%d %H:%M:%S") << "\n";
            file << "---------------------------------------" << "\n";
            file << content << "\n\n";
            file.close();
        }
    }

    void ProcessCapturedPayload(DWORD pid, const std::string &processName, LogCategory category, const std::string &payload) {
        switch (category) {
        case LogCategory::ALPC:         g_Stats.alpcCount++; break;
        case LogCategory::SharedMemory: g_Stats.sharedMemCount++; break;
        case LogCategory::NamedPipe:    g_Stats.pipeCount++; break;
        case LogCategory::FileIO:       g_Stats.fileIOCount++; break;
        default: break;
        }

        std::string matchedRule;
        bool isAlert = SignatureEngine::ScanAndAlert(payload, category, pid, matchedRule);
        if (isAlert) {
            std::string alertMsg = "[ALERT!] Rule matched: " + matchedRule + " [PID: " + std::to_string(pid) + "]\r\n";
            g_NtAlpcCreatePortLogs += alertMsg;
        }

        ForensicArchiver::GetInstance().SaveDump(pid, processName, category, payload);
        g_NtAlpcCreatePortLogs += std::string("[SAVED] FORENSIC DUMP ----- \n\n");
    }
};

#endif