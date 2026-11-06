// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MEMORYSCANNER_H
#define MEMORYSCANNER_H

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

struct MemoryScanHit {
    uintptr_t address;
    size_t size;
    std::string matchedPattern;
};

class MemoryScanner {
public:

    static std::vector<MemoryScanHit> ScanProcessMemory(HANDLE hProcess, const std::vector<std::string> &patterns) {
        std::vector<MemoryScanHit> hits;
        uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                    for (const auto& pattern : patterns) {
                        if (pattern.empty()) continue;

                        for (size_t i = 0; i <= bytesRead - pattern.size(); ++i) {
                            if (memcmp(buffer.data() + i, pattern.data(), pattern.size()) == 0) {
                                MemoryScanHit hit;
                                hit.address = (uintptr_t)mbi.BaseAddress + i;
                                hit.size = pattern.size();
                                hit.matchedPattern = pattern;
                                hits.push_back(hit);
                            }
                        }
                    }
                }
            }

            address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (address < (uintptr_t)mbi.BaseAddress) break;
        }

        return hits;
    }

    static std::string FormatScanResults(const std::vector<MemoryScanHit> &hits) {
        std::ostringstream ss;
        ss << "[MEMORY-SCAN] Heap & Virtual Memory Inspection Results:\r\n";
        for (const auto& hit : hits) {
            ss << "  -> Found Pattern: \"" << hit.matchedPattern 
               << "\" at Address: 0x" << std::hex << hit.address << std::dec << "\r\n";
        }
        return ss.str();
    }
};

#endif
