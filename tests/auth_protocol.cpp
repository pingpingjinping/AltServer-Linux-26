// Offline tests call the compiled production request, parser and 2FA methods.
// transport is always injected; no Apple account or external HTTP is used.
#include "AppleAPI.hpp"
#include "AnisetteData.h"
#include <iostream>
#include <stdexcept>

using namespace web::http;
using namespace altauth;
static void check(bool ok) { if (!ok) throw std::runtime_error("Protocol assertion failed"); }
template<class F> static void fails(F action, const std::string& expected = "") {
    try { action(); } catch (const std::exception& e) {
        auto error = dynamic_cast<const Error*>(&e);
        const auto message = error ? error->localizedDescription() : std::string(e.what());
        check(message.find("PRIVATE-ACCOUNT") == std::string::npos);
        check(expected.empty() || message.find(expected) != std::string::npos); return;
    }
    throw std::runtime_error("Expected protocol failure");
}
static auto data(const std::string& otp) {
    timeval date{}; date.tv_sec = std::time(nullptr);
    auto result = std::make_shared<AnisetteData>("synthetic-machine", otp, "synthetic-local", 1,
        "synthetic-device", "2", "<PC> <Windows;6.2> <com.apple.AuthKit/1>", date, "en_US@calendar=gregorian", "GMT");
    result->authenticationUserAgent = "synthetic-provider-agent";
    return result;
}
static std::string body(http_request request) {
    // plist media types have no text charset; inspect bytes like production.
    auto bytes = request.extract_vector().get();
    return std::string(bytes.begin(), bytes.end());
}
static http_response response(const std::string& status, unsigned http = 200) {
    http_response result(http);
    result.set_body("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Response</key><dict><key>Status</key><dict>" + status + "</dict></dict></dict></plist>");
    return result;
}
static auto context() {
    auto result = std::make_shared<Context>(); result->modern = true;
    result->current = data("otp-0");
    auto counter = std::make_shared<int>(0);
    result->refresh = [counter] { return data("otp-" + std::to_string(++*counter)); };
    return result;
}
struct AuthProtocolTests {
    static auto send(const std::shared_ptr<Context>& c, const std::string& op = "init") {
        auto cpd = plist_new_dict();
        plist_dict_set_item(cpd, "bootstrap", plist_new_bool(true));
        std::map<std::string, plist_t> params{{"cpd",cpd},{"o", plist_new_string(op.c_str())},
            {"u", plist_new_string("synthetic@example.invalid")}, {"A2k", plist_new_data("synthetic-public-key",20)}};
        return AppleAPI::getInstance()->SendAuthenticationRequest(params, c->current, c);
    }
    static auto factor(const std::shared_ptr<Context>& c, Factor type,
                       std::function<pplx::task<std::optional<std::string>>()> prompt) {
        return AppleAPI::getInstance()->RequestModernTwoFactorCode("synthetic-dsid", "synthetic-token", type, prompt, c);
    }
    static void run() {
        unsetenv("ALTSERVER_AUTH_MODE"); check(!enabled());
        setenv("ALTSERVER_AUTH_MODE", "official-2026", 1); check(enabled());
        setenv("ALTSERVER_AUTH_MODE", "typo", 1); fails([] { enabled(); });
        unsetenv("ALTSERVER_AUTH_MODE"); unsetenv("ALTSERVER_GSA_USER_AGENT");
        identity("client", "agent", "client", "agent");
        fails([] { identity("client", "agent", "other", "agent"); });
        fails([] { identity("client", "agent\r\nprivate", "client", "agent\r\nprivate"); });
        setenv("ALTSERVER_GSA_USER_AGENT", "different", 1);
        fails([] { identity("client", "agent", "client", "agent"); }); unsetenv("ALTSERVER_GSA_USER_AGENT");
        check(altauth::factor("",409) == Factor::alreadySent);
        check(altauth::factor("trustedDeviceSecondaryAuth",200) == Factor::trusted);
        check(altauth::factor("secondaryAuth",200) == Factor::sms);
        check(altauth::factor("",200) == Factor::none);
        fails([] { altauth::factor("unrecognized",200); });

        auto legacy = context(); legacy->modern = false;
        legacy->transport = [](http_request req) {
            check(req.headers()["User-Agent"] == "AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)");
            auto xml = body(req); plist_t root = nullptr;
            plist_from_xml(xml.data(),xml.size(),&root);
            auto cpd = plist_dict_get_item(plist_dict_get_item(root,"Request"),"cpd");
            check(plist_get_node_type(plist_dict_get_item(cpd,"bootstrap")) == PLIST_BOOLEAN);
            plist_free(root); return pplx::task_from_result(response("<key>ec</key><integer>0</integer>"));
        };
        plist_free(send(legacy).get()); check(legacy->usedPasswords.empty());

        // Actual wire headers and CPD after a provider refresh, including resync.
        auto c = context(); int requests = 0; std::string publicKey;
        c->resync = [](const std::string& sim) { check(sim == "synthetic-sim"); return data("resynced-otp"); };
        c->transport = [&](http_request req) {
            ++requests;
            check(req.headers()["User-Agent"] == c->current->authenticationUserAgent);
            check(req.headers()["X-MMe-Client-Info"] == c->current->deviceDescription());
            auto xml = body(req);
            plist_t root = nullptr; plist_from_xml(xml.data(), xml.size(), &root);
            auto r = plist_dict_get_item(root,"Request");
            auto cpd = plist_dict_get_item(r,"cpd"); check(plist_dict_get_size(cpd) == 9);
            auto n = plist_dict_get_item(cpd,"bootstrap"); check(plist_get_node_type(n) == PLIST_STRING);
            char* otp = nullptr; plist_get_string_val(plist_dict_get_item(cpd,"X-Apple-I-MD"), &otp);
            check(std::string(otp) == c->current->oneTimePassword()); free(otp);
            char* key = nullptr; uint64_t size = 0; plist_get_data_val(plist_dict_get_item(r,"A2k"), &key, &size);
            if (requests == 1) publicKey.assign(key,size); else check(publicKey == std::string(key,size));
            free(key); plist_free(root);
            return pplx::task_from_result(response(requests == 1
                ? "<key>hsc</key><integer>434</integer><key>ec</key><integer>-29004</integer><key>X-Apple-I-MD-DATA</key><string>synthetic-sim</string>"
                : "<key>ec</key><integer>0</integer><key>hsc</key><integer>200</integer>"));
        };
        plist_free(send(c).get()); check(requests == 2 && c->resyncs == 1);
        plist_free(send(c,"complete").get()); check(requests == 3 && c->current->oneTimePassword() == "otp-1");
        plist_free(send(c,"apptokens").get()); check(requests == 4 && c->current->oneTimePassword() == "otp-2");

        // Bounded/unsupported/malformed resync, HTTP and Apple errors.
        for (auto status : {"<key>hsc</key><integer>434</integer>",
             "<key>hsc</key><integer>434</integer><key>X-Apple-I-MD-DATA</key><string>sim</string>"}) {
            auto f = context(); f->transport = [=](http_request) { return pplx::task_from_result(response(status)); };
            fails([&] { send(f).get(); });
        }
        auto repeated = context(); repeated->resync = [](const std::string&) { return data("new-resync"); };
        repeated->transport = [](http_request) { return pplx::task_from_result(response("<key>hsc</key><integer>434</integer><key>X-Apple-I-MD-DATA</key><string>sim</string>")); };
        fails([&] { send(repeated).get(); },"repeated");
        for (int code : {-80045,-80046,-23782,-21669,-22411}) {
            auto f = context(); f->transport = [=](http_request) { return pplx::task_from_result(response("<key>ec</key><integer>"+std::to_string(code)+"</integer><key>em</key><string>PRIVATE-ACCOUNT</string>")); };
            fails([&] { send(f).get(); },std::to_string(code));
        }
        for (unsigned status : {302,403,409,434,503}) {
            auto f = context(); int calls = 0;
            f->transport = [&](http_request) { ++calls; http_response r(status); r.set_body("<html>PRIVATE-ACCOUNT</html>"); return pplx::task_from_result(r); };
            fails([&] { send(f).get(); }, "HTTP " + std::to_string(status)); check(calls == 1);
        }
        auto malformed = context(); malformed->transport = [](http_request) {
            http_response r(200); r.set_body("<html>PRIVATE-ACCOUNT</html>"); return pplx::task_from_result(r);
        };
        fails([&] { send(malformed).get(); });
        auto binary = context(); binary->resync = [](const std::string& sim) { check(sim == "c2lt"); return data("binary-resync"); };
        binary->transport = [binary](http_request) { return pplx::task_from_result(response(binary->resyncs == 0
            ? "<key>hsc</key><integer>434</integer><key>X-Apple-I-MD-DATA</key><data>c2lt</data>"
            : "<key>ec</key><integer>0</integer>")); };
        plist_free(send(binary).get()); check(binary->resyncs == 1);
        auto later = context(); later->transport = [](http_request) {
            return pplx::task_from_result(response("<key>hsc</key><integer>434</integer>"));
        };
        fails([&] { send(later,"complete").get(); });

        auto reused = context(); reused->refresh = [] { return data("otp-0"); };
        reused->transport = [](http_request) { return pplx::task_from_result(response("")); };
        plist_free(send(reused).get()); fails([&] { send(reused,"complete").get(); },"reused");
        auto changed = context(); changed->refresh = [] { auto d=data("next"); d->authenticationUserAgent="wrong"; return d; };
        fails([&] { send(changed,"complete").get(); },"identity changed");

        // hsc 409 never requests another trusted-device code; typed-code refresh
        // occurs only after the prompt, and SMS validates via the PE response header.
        for (auto type : {Factor::alreadySent,Factor::trusted,Factor::sms}) {
            auto f = context(); int calls = 0; bool prompted = false;
            f->transport = [&](http_request req) {
                ++calls; check(req.headers()["User-Agent"] == f->current->authenticationUserAgent);
                bool validate = req.request_uri().to_string().find("validate") != std::string::npos || req.request_uri().to_string().find("securitycode") != std::string::npos;
                check(validate == prompted);
                if (validate && type != Factor::sms) check(req.headers()["security-code"] == "123456");
                if (validate && type == Factor::sms) check(body(req).find("securityCode.code") != std::string::npos);
                http_response r(200);
                r.headers().add("Set-Cookie","test=synthetic-cookie; Secure");
                if (type == Factor::sms && validate) r.headers().add("X-Apple-PE-Token","synthetic-pe");
                else r.set_body("<plist><dict><key>ec</key><integer>0</integer></dict></plist>");
                return pplx::task_from_result(r);
            };
            auto prompt = [&] { prompted=true; return pplx::task_from_result(std::optional<std::string>("123456")); };
            check(factor(f,type,prompt).get()); check(calls == (type == Factor::alreadySent ? 1 : 2));
            check(!f->cookies.empty() && context()->cookies.empty());
        }
        for (auto type : {Factor::alreadySent,Factor::sms}) {
            auto rejected = context();
            rejected->transport = [type](http_request) {
                http_response r(200);
                if (type != Factor::sms) r.set_body("<plist><dict><key>ec</key><integer>-21669</integer><key>em</key><string>PRIVATE-ACCOUNT</string></dict></plist>");
                return pplx::task_from_result(r);
            };
            fails([&] { factor(rejected,type,[] { return pplx::task_from_result(std::optional<std::string>("123456")); }).get(); },"-21669");
        }

        auto cancelled = context(); cancelled->transport = [](http_request) -> pplx::task<http_response> { throw std::runtime_error("Should not send"); };
        fails([&] { factor(cancelled,Factor::alreadySent,[] { return pplx::task_from_result(std::optional<std::string>()); }).get(); });
        Context bounded; bounded.beginFactor(); fails([&] { bounded.beginFactor(); });
    }
};
int main() {
    try { AuthProtocolTests::run(); std::cout << "Compiled authentication protocol tests passed (offline)\n"; return 0; }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
