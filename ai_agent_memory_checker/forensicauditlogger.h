// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FORENSICAUDITLOGGER_H
#define FORENSICAUDITLOGGER_H

#include "common.h"
#include <fstream>
#include <iomanip>

// Singleton
class ForensicAuditLogger {
private:
    ForensicAuditLogger(const std::string &filePath) : m_logFilePath(filePath) {}

    std::string m_logFilePath;

    std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        tm tobj;
        localtime_s(&tobj, &in_time_t);
        ss << std::put_time(&tobj, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

public:
    static ForensicAuditLogger &GetInstance(const std::string &filePath) {
        static ForensicAuditLogger fal(filePath);
        return fal;
    }

    struct AuditEventRecord {
        std::string timestamp;
        std::string category;
        std::string severity;
        std::string details;
    };

    bool LogEvent(const std::string& category, const std::string& severity, const std::string &details) {
        std::ofstream file(m_logFilePath, std::ios::app);
        if (!file.is_open()) return false;

        std::string timeStr = GetCurrentTimestamp();

        file << "{\n";
        file << "  \"timestamp\": \"" << timeStr << "\",\n";
        file << "  \"category\": \"" << category << "\",\n";
        file << "  \"severity\": \"" << severity << "\",\n";
        file << "  \"details\": \"" << details << "\"\n";
        file << "},\n";

        file.close();
        return true;
    }

    std::string GetLogPath() const {
        return m_logFilePath;
    }
};

#endif
