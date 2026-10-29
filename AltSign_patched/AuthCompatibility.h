#pragma once

#include <cpprest/http_client.h>
#include <cstdlib>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>

class AnisetteData;

namespace altauth {
inline bool enabled()
{
    const char* mode = std::getenv("ALTSERVER_AUTH_MODE");
    if (!mode || !*mode || std::string(mode) == "legacy") return false;
    if (std::string(mode) == "official-2026") return true;
    throw std::runtime_error("Unknown ALTSERVER_AUTH_MODE");
}

inline void headerValue(const std::string& value)
{
    if (value.empty() || value.size() > 2048)
        throw std::runtime_error("Missing or oversized authentication metadata");
    for (unsigned char ch : value)
        if (ch < 32 || ch == 127)
            throw std::runtime_error("Invalid authentication metadata");
}

// Values come from the provider AND the isolated identity's provisioning record.
// Do not infer a User-Agent from a client-info string or silently rewrite either.
inline void identity(const std::string& client, const std::string& agent,
                     const std::string& provisionedClient, const std::string& provisionedAgent)
{
    headerValue(client);
    headerValue(agent);
    if (client != provisionedClient || agent != provisionedAgent)
        throw std::runtime_error("Anisette provisioning and authentication identity mismatch");
    const char* configured = std::getenv("ALTSERVER_GSA_USER_AGENT");
    if (configured && *configured && agent != configured)
        throw std::runtime_error("Configured User-Agent differs from Anisette provider");
}

enum class Factor { none, trusted, alreadySent, sms };
inline Factor factor(const std::string& au, long hsc)
{
    if (au.empty() && hsc == 409) return Factor::alreadySent;
    if (au == "trustedDeviceSecondaryAuth") return Factor::trusted;
    if (au == "secondaryAuth") return Factor::sms;
    if (!au.empty()) throw std::runtime_error("Unsupported Apple secondary authentication method");
    if (hsc != 0 && hsc != 200) throw std::runtime_error("Unexpected Apple authentication status");
    return Factor::none;
}

inline std::string appleError(long code)
{
    switch (code) {
    case -80045: return "Apple rejected authentication (-80045). Check the Anisette provider and matching identity; no automatic retry.";
    case -80046: return "Apple rejected authentication (-80046). Verify the updated Classic client and provider; no automatic retry.";
    case -23782: return "Apple rejected the client identity (-23782). Use a separately provisioned compatible provider identity; no automatic rewrite.";
    case -21669: return "Incorrect verification code (-21669).";
    default: return "Apple authentication failed (" + std::to_string(code) + ").";
    }
}

inline void httpStatus(unsigned status)
{
    if (status >= 200 && status < 300) return;
    throw std::runtime_error("Apple authentication HTTP " + std::to_string(status) +
        (status == 503 ? ". Possible service, rate-limit or client-identity rejection; no automatic login retry." : "."));
}

struct Context {
    bool modern = false;
    unsigned resyncs = 0;
    unsigned factors = 0;
    std::shared_ptr<AnisetteData> current;
    std::function<std::shared_ptr<AnisetteData>()> refresh;
    std::function<std::shared_ptr<AnisetteData>(const std::string&)> resync;
    std::set<std::string> usedPasswords;
    std::map<std::string, std::string> cookies;
    // Dependency injection for offline protocol tests. Production never sets this.
    std::function<pplx::task<web::http::http_response>(web::http::http_request)> transport;

    void consume(const std::string& password) {
        if (password.empty() || !usedPasswords.insert(password).second)
            throw std::runtime_error("Anisette provider returned a reused one-time password");
    }
    void beginResync(const std::string& sim) {
        if (sim.empty() || sim.size() > 65536 || resyncs++ != 0 || !resync)
            throw std::runtime_error("Anisette resync unavailable or repeated (hsc 434)");
    }
    void beginFactor() {
        if (factors++ != 0)
            throw std::runtime_error("Apple requested repeated two-factor authentication; stopped");
    }
};
} // namespace altauth
