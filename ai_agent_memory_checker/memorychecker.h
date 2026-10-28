// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MEMORYCHECKER_H
#define MEMORYCHECKER_H

#include "common.h"
#include "promptInspector.h"
#include <unordered_map>
#include <algorithm>

// Singleton
class MemoryAccessStatsTracker {
private:
    MemoryAccessStatsTracker() { Reset(); }

    std::unordered_map<uintptr_t, uint64_t> addressHitCounts;
    uint64_t totalSendBytes = 0;
    uint64_t totalReceiveBytes = 0;
    uint64_t totalSendCount = 0;
    uint64_t totalReceiveCount = 0;

public:
    static MemoryAccessStatsTracker &GetInstance() {
        static MemoryAccessStatsTracker StatsTracker;
        return StatsTracker;
    }

    void Reset() {
        addressHitCounts.clear();
        totalSendBytes = 0;
        totalReceiveBytes = 0;
        totalSendCount = 0;
        totalReceiveCount = 0;
    }

    void RecordAccess(uintptr_t sourceAddress, size_t dataSize, bool isSend) {
        addressHitCounts[sourceAddress]++;

        if (isSend) {
            totalSendBytes += dataSize;
            totalSendCount++;
        } else {
            totalReceiveBytes += dataSize;
            totalReceiveCount++;
        }
    }

    std::string PrintSummaryReport() {
        std::ostringstream ss;
        ss << "\n[=== ALPC Memory Hotspot & Traffic Statistics ===]\n";
        ss << "  [SEND] Packets: " << totalSendCount << " | Total Bytes: " << totalSendBytes << " B\n";
        ss << "  [RECV] Packets: " << totalReceiveCount << " | Total Bytes: " << totalReceiveBytes << " B\n";
        ss << "  Top Hotspot Pointer Addresses (Source Buffers):\n";

        std::vector<std::pair<uintptr_t, uint64_t>> sortedHits(addressHitCounts.begin(), addressHitCounts.end());
        std::sort(sortedHits.begin(), sortedHits.end(), [](const auto &a, const auto &b) {
            return a.second > b.second;
        });

        int rank = 1;
        for (const auto& pair : sortedHits) {
            if (rank > 5) break;
            std::cout << "    #" << rank++ << " -> Addr: 0x" << std::hex << pair.first 
                      << std::dec << " | Hits: " << pair.second << " times\n";
        }
        ss << "==================================================\n\n";

        return ss.str();
    }
};

inline std::string AnalyzeAndHighlightPayload(const unsigned char *buffer, size_t size, uintptr_t sourceAddress, bool isSend) {
    MemoryAccessStatsTracker &StatsTracker = MemoryAccessStatsTracker::GetInstance();
    if (!buffer || size == 0) return std::string("[ALPC-ERROR]");

    std::string payloadStr(reinterpret_cast<const char*>(buffer), size);
    StatsTracker.RecordAccess(sourceAddress, size, isSend);

    bool isJson = (size > 2 && ((payloadStr.front() == '{' && payloadStr.back() == '}') || 
                                (payloadStr.front() == '[' && payloadStr.back() == ']')));
    bool hasMojoSig = (payloadStr.find("mojo") != std::string::npos || payloadStr.find("IPC") != std::string::npos);

    std::ostringstream ss;
    if (isSend) {
        ss << "WARN --- [ALPC-SEND] ";
    } else {
        ss << "[ALPC-RECV] ";
    }

    ss << "[SrcAddr: 0x" << std::hex << sourceAddress << std::dec << " | Size: " << size << "B] ";

    if (isJson) {

        ss << "[TAG: JSON-PAYLOAD]\n";
        std::string snippet = payloadStr.substr(0, 250);
        ss << "  -> " << snippet << (payloadStr.length() > 250 ? "..." : "") << "\n";

    } else if (hasMojoSig) {

        ss << "[TAG: MOJO-SIGNATURE]\n";
        ss << "  -> " << payloadStr.substr(0, 150) << "\n";

    } else {

        ss << "[TAG: RAW-BUFFER]\n";
        ss << "  -> Hex: ";
        for (size_t i = 0; i < (size < 32 ? size : 32); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        }
        ss << std::dec << "\n";
    }

    std::string aiInspectionResult = InspectAiModelPayload(payloadStr);
    if (!aiInspectionResult.empty()) {
        ss << aiInspectionResult;
    }

    return ss.str();
}

#endif
