

#ifndef MEMORYDETECTOR_H
#define MEMORYDETECTOR_H

#include <Windows.h>
#include <string>

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
