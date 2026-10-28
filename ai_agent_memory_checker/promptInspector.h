// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROMPTINSPECTOR
#define PROMPTINSPECTOR

#include "common.h"

inline std::string InspectAiModelPayload(const std::string &payloadStr) {
    std::ostringstream aiLog;

    bool hasMessages = (payloadStr.find("\"messages\"") != std::string::npos || payloadStr.find("messages") != std::string::npos);
    bool hasPrompt   = (payloadStr.find("\"prompt\"") != std::string::npos || payloadStr.find("prompt") != std::string::npos);
    bool hasModel    = (payloadStr.find("\"model\"") != std::string::npos || payloadStr.find("model") != std::string::npos);
    bool hasContent  = (payloadStr.find("\"content\"") != std::string::npos);

    if (hasMessages || hasPrompt || hasModel || hasContent) {
        aiLog << "\r\n  [AI-INSPECTION DETECTED] ----------------------------------\r\n";

        if (hasModel) {
            aiLog << "    -> [Model Config / Target Detected]\r\n";
        }
        if (hasMessages || hasPrompt) {
            aiLog << "    -> [Prompt / Context Stream Flow]\r\n";
        }

        std::string preview = payloadStr.length() > 400 ? payloadStr.substr(0, 400) + "..." : payloadStr;
        aiLog << "    -> Payload Snippet: " << preview << "\r\n";
        aiLog << "  -----------------------------------------------------------\r\n";
    }

    return aiLog.str();
}

#endif