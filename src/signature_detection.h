#ifndef SIGNATURE_DETECTION_H
#define SIGNATURE_DETECTION_H

#include <string>
#include <vector>
#include <cstdint>

struct SigMatch {
    std::string tag;     // e.g. SQLI, XSS, CMD
    std::string pattern; // the actual malicious substring
};

class SignatureDetector {
public:
    SignatureDetector() = default;

    bool load_signatures(const std::string &path);

    std::vector<SigMatch> match_payload(const char* data, uint32_t len);

private:
    std::vector<SigMatch> rules;

    static std::string to_lower(const std::string &s);
};

#endif // SIGNATURE_DETECTION_H
