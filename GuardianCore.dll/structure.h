// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <Windows.h>

#define GUARDIAN_PIPE_NAME L"\\\\.\\pipe\\AIAgentMemoryCheckerPipe"

enum class AlertType {
    MemoryRead,
    ProcessOpen,
    CommonMapView,
    DuplicateObject
};

struct GuardianAlertEvent {
    AlertType type;
    DWORD sourcePid;
    DWORD targetPid;
    ULONG_PTR baseAddress;
    SIZE_T bufferSize;
    DWORD desiredAccess;
    BYTE buf[512];

    GuardianAlertEvent() {
        type = AlertType::MemoryRead;
        sourcePid = 0;
        targetPid = 0;
        baseAddress = 0;
        bufferSize = 0;
        desiredAccess = 0;
        memset(buf, 0, sizeof(buf));
    }
};

inline std::string ToHexString(const unsigned char *buf, size_t size) {
    std::ostringstream ss;
    for (size_t i = 0; i < size; ++i) {
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]) << " ";
    }

    return ss.str();
}

inline std::string FormatMemoryPeek_512bytes(const void *buffer, size_t bytesRead) {
    try {
        constexpr size_t rMax = 512;

        if (!buffer || bytesRead == 0) return "";

        const size_t peekSize = (bytesRead < rMax) ? bytesRead : rMax;
        BYTE safeBuffer[rMax] = { 0 };

        std::memcpy(safeBuffer, buffer, peekSize);
        std::ostringstream ss;
        for (size_t i = 0; i < peekSize; ++i) {
            ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                << static_cast<int>(safeBuffer[i]) << " ";
        }

        for (size_t i = peekSize; i < rMax; ++i) ss << "   ";
        ss << "| ";
        for (size_t i = 0; i < peekSize; ++i) {
            char ch = static_cast<char>(safeBuffer[i]);
            ss << (std::isprint(static_cast<unsigned char>(ch)) ? ch : '.');
        }

        return ss.str();
    }
    catch (const std::string&) {
        return "[Access Exception]";
    }
}

#endif