#include "signature_detection.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdint>

static inline std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

bool SignatureDetector::load_signatures(const std::string &path) {
    rules.clear();
    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string tag = trim(line.substr(0, pos));
        std::string pat = trim(line.substr(pos + 1));

        if (!tag.empty() && !pat.empty()) {
            rules.push_back({tag, pat});
        }
    }
    return true;
}

std::string SignatureDetector::to_lower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

std::vector<SigMatch> SignatureDetector::match_payload(const char* data, uint32_t len) {
    std::vector<SigMatch> found;
    if (len == 0) return found;

    std::string payload(data, data + len);
    std::string lower_payload = to_lower(payload);

    for (const auto &rule : rules) {
        std::string patt = to_lower(rule.pattern);
        if (lower_payload.find(patt) != std::string::npos) {
            found.push_back(rule);
        }
    }
    return found;
}
