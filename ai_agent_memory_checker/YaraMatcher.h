// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YARAMATCHER_H
#define YARAMATCHER_H

#include "common.h"
#include <regex>
#include <sstream>

struct YaraMatchResult {
    std::string ruleName;
    uintptr_t matchedAddress;
    size_t matchLength;
    std::string matchedSnippet;
};

class YaraMatcher {
private:
    struct YaraRule {
        std::string name;
        std::string pattern;
        bool isRegex;
    };

    std::vector<YaraRule> m_rules;

public:
    void AddRule(const std::string& name, const std::string& pattern, bool isRegex = false) {
        m_rules.push_back({ name, pattern, isRegex });
    }

    std::vector<YaraMatchResult> ScanBuffer(const BYTE* buffer, size_t bufferSize, uintptr_t baseAddress = 0) {
        std::vector<YaraMatchResult> results;
        if (!buffer || bufferSize == 0) return results;

        std::string dataStr(reinterpret_cast<const char*>(buffer), bufferSize);

        for (const auto& rule : m_rules) {
            try {
                if (rule.isRegex) {
                    std::regex rx(rule.pattern);
                    auto words_begin = std::sregex_iterator(dataStr.begin(), dataStr.end(), rx);
                    auto words_end = std::sregex_iterator();

                    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                        std::smatch match = *i;
                        YaraMatchResult res;
                        res.ruleName = rule.name;
                        res.matchedAddress = baseAddress + match.position();
                        res.matchLength = match.length();
                        res.matchedSnippet = match.str();
                        results.push_back(res);
                    }
                }
                else {
                    size_t pos = dataStr.find(rule.pattern);
                    while (pos != std::string::npos) {
                        YaraMatchResult res;
                        res.ruleName = rule.name;
                        res.matchedAddress = baseAddress + pos;
                        res.matchLength = rule.pattern.size();
                        res.matchedSnippet = rule.pattern;
                        results.push_back(res);

                        pos = dataStr.find(rule.pattern, pos + 1);
                    }
                }
            }
            catch (...) {
                return results;
            }
        }

        return results;
    }

    static std::string FormatMatchResults(const std::vector<YaraMatchResult>& results) {
        std::ostringstream ss;
        ss << "[YARA-MATCH] Signature Inspection Results:\r\n";
        if (results.empty()) {
            ss << "  -> No signature matches detected.\r\n";
        }
        else {
            for (const auto &res : results) {
                ss << "  -> Rule Matched: [" << res.ruleName << "]"
                   << " at Address: 0x" << std::hex << res.matchedAddress << std::dec
                   << " (Snippet: \"" << res.matchedSnippet << "\")\r\n";
            }
        }
        return ss.str();
    }
};

#endif
