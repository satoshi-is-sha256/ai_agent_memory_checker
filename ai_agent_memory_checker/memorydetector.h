// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MEMORYDETECTOR_H
#define MEMORYDETECTOR_H

#include "common.h"
#include <regex>

inline bool IsTargetWatched(DWORD targetPid, DWORD specifiedTargetPid, const std::string &targetName, const std::string &targetNameFilter) {
    if (specifiedTargetPid != 0 && targetPid == specifiedTargetPid) {
        return true;
    }

    if (!targetNameFilter.empty()) {
        if (targetName.find(targetNameFilter) != std::string::npos) {
            return true;
        }
    }

    if (specifiedTargetPid == 0 && targetNameFilter.empty()) {
        return true;
    }

    return false;
}

#endif