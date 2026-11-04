// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MOJOPAYLOADPARSER_H
#define MOJOPAYLOADPARSER_H

#include "common.h"

class MojoPayloadParser {
public:
    struct ParsedMessage {
        bool hasJson = false;
        std::string extractedJson;
        std::vector<std::string> keywordsFound;
    };

    static ParsedMessage Parse(const LPVOID buffer, DWORD size) {
        ParsedMessage result;
        if (!buffer || size == 0 || size > 65536) return result;

        const char *rawData = static_cast<const char *>(buffer);
        std::string content(rawData, size);

        const std::vector<std::string> targetKeywords = {
            "prompt", "messages", "content", "role", "system", 
            "codex", "auth", "token", "model", "tools"
        };

        for (const auto &kw : targetKeywords) {
            if (content.find(kw) != std::string::npos) {
                result.keywordsFound.push_back(kw);
            }
        }

        size_t jsonStart = content.find('{');
        size_t jsonEnd = content.rfind('}');

        if (jsonStart != std::string::npos && jsonEnd != std::string::npos && jsonEnd > jsonStart) {
            std::string potentialJson = content.substr(jsonStart, (jsonEnd - jsonStart) + 1);

            if (potentialJson.length() > 5 && potentialJson.length() < 4096) {
                result.hasJson = true;
                result.extractedJson = potentialJson;
            }
        }

        return result;
    }

    static std::string FormatParsedResult(const ParsedMessage &parsed) {
        std::ostringstream ss;
        if (parsed.hasJson) {
            ss << "\n    [MOJO-PAYLOAD] -> Extracted JSON Payload:\n";
            ss << "      " << parsed.extractedJson << "\n";
        }
        if (!parsed.keywordsFound.empty()) {
            ss << "    [MOJO-KEYWORDS] -> Detected Keys: ";
            for (size_t i = 0; i < parsed.keywordsFound.size(); ++i) {
                ss << parsed.keywordsFound[i] << (i + 1 < parsed.keywordsFound.size() ? ", " : "");
            }
            ss << "\n";
        }
        return ss.str();
    }
};

#endif
