// Copyright (c) 2026 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROMPTINSPECTOR
#define PROMPTINSPECTOR

#include "common.h"
#pragma warning(disable: 4566)

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

// Singleton
class AiPromptShield {
private:
    AiPromptShield() {
        InitializeSignatures();
    }

    std::vector<std::string> m_injectionSignatures;

    void InitializeSignatures() {
        m_injectionSignatures.push_back("ignore previous instructions");
        m_injectionSignatures.push_back("system override");
        m_injectionSignatures.push_back("disregard all prior rules");
        m_injectionSignatures.push_back("reveal system prompt");
        m_injectionSignatures.push_back("you are now DAN");
    }

public:
    static AiPromptShield &GetInstance() {
        static AiPromptShield aps;
        return aps;
    }

    struct InspectionResult {
        bool isMalicious;
        std::string detectedSignature;
        std::string riskDetails;
    };

    static char tolower(char c) {
        return (char)std::tolower(c);
    }

    InspectionResult InspectPrompt(const std::string &promptText) {
        InspectionResult result{false, "", ""};

        std::string lowerText = promptText;
        std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), AiPromptShield::tolower);

        for (const auto& sig : m_injectionSignatures) {
            if (lowerText.find(sig) != std::string::npos) {
                result.isMalicious = true;
                result.detectedSignature = sig;

                std::ostringstream ss;
                ss << "[AI-PROMPT-SHIELD] Prompt Injection / Jailbreak Attempt Detected!\r\n"
                   << "  -> Matched Signature: \"" << sig << "\"\r\n"
                   << "  -> Prompt Snippet: " << promptText.substr(0, 150) << (promptText.size() > 150 ? "..." : "") << "\r\n";
                result.riskDetails = ss.str();
                break;
            }
        }

        if (!result.isMalicious) {
            if (promptText.find("\u200B") != std::string::npos || promptText.find("\u200C") != std::string::npos) { // #pragma warning(disable: 4566)
                result.isMalicious = true;
                result.detectedSignature = "Hidden Zero-Width Injection";
                result.riskDetails = "[AI-PROMPT-SHIELD] Zero-width control characters detected in prompt payload.\r\n";
            }
        }

        return result;
    }
};

#endif