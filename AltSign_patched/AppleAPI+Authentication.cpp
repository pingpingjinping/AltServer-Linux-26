//  Heavily based on sample code provided by Kabir Oberai (https://github.com/kabiroberai)

#include "AppleAPI.hpp"

#include "AnisetteData.h"

// Core Crypto
extern "C" {
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccpad.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstddef>
#include <algorithm>
#include <cctype>
#include <tuple>
}

#include <ostream>
#include <cstdlib>

using namespace std;
using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

extern std::string make_uuid();

extern std::string StringFromWideString(std::string wideString);
extern std::string WideStringFromString(std::string string);

extern bool decompress(const uint8_t* input, size_t input_size, std::vector<uint8_t>& output);

#define odslog(msg) { std::stringstream ss; ss << msg << std::endl; OutputDebugStringA(ss.str().c_str()); }

static std::string ALTAuthKitUserAgent()
{
    const char* configured = std::getenv("ALTSERVER_GSA_USER_AGENT");
    return configured && *configured
        ? configured
        : "AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)";
}

static std::shared_ptr<AnisetteData> ALTUseFreshData(
    std::shared_ptr<altauth::Context> context, std::shared_ptr<AnisetteData> fresh)
{
    auto old = context->current;
    if (!fresh || !old || fresh->authenticationUserAgent.empty() ||
        fresh->deviceDescription() != old->deviceDescription() ||
        fresh->authenticationUserAgent != old->authenticationUserAgent ||
        fresh->deviceUniqueIdentifier() != old->deviceUniqueIdentifier() ||
        fresh->localUserID() != old->localUserID() || fresh->machineID() != old->machineID())
        throw std::runtime_error("Anisette identity changed during authentication");
    context->current = fresh;
    return fresh;
}

static std::shared_ptr<AnisetteData> ALTRefreshData(std::shared_ptr<altauth::Context> context)
{
    if (!context->refresh) throw std::runtime_error("Fresh Anisette handler unavailable");
    return ALTUseFreshData(context, context->refresh());
}

static plist_t ALTModernClientDictionary(std::shared_ptr<AnisetteData> data)
{
    auto cpd = plist_new_dict();
    for (const auto& pair : std::map<std::string, std::string>{
        {"bootstrap", "true"}, {"icscrec", "true"}, {"pbe", "false"},
        {"prkgen", "true"}, {"svct", "iCloud"}, {"loc", "en_US"},
        {"X-Apple-I-MD", data->oneTimePassword()}, {"X-Apple-I-MD-M", data->machineID()},
        {"X-Mme-Device-Id", data->deviceUniqueIdentifier()}})
        plist_dict_set_item(cpd, pair.first.c_str(), plist_new_string(pair.second.c_str()));
    return cpd;
}

static long ALTStatusInteger(plist_t dictionary, const char* key)
{
    auto node = dictionary ? plist_dict_get_item(dictionary, key) : nullptr;
    if (!node) return 0;
    if (plist_get_node_type(node) == PLIST_UINT) {
        uint64_t value = 0; plist_get_uint_val(node, &value); return (int64_t)value;
    }
    if (plist_get_node_type(node) == PLIST_STRING) {
        char* value = nullptr; plist_get_string_val(node, &value);
        std::string text = value ? value : ""; free(value);
        size_t end = 0;
        try { long result = std::stol(text, &end); if (end == text.size()) return result; } catch (...) {}
    }
    throw std::runtime_error("Invalid Apple authentication status value");
}

static std::string ALTStatusString(plist_t dictionary, const char* key)
{
    auto node = dictionary ? plist_dict_get_item(dictionary, key) : nullptr;
    if (!node) return "";
    char* value = nullptr;
    if (plist_get_node_type(node) != PLIST_STRING) throw APIError(APIErrorCode::InvalidResponse);
    plist_get_string_val(node, &value);
    std::string result = value ? value : ""; free(value); return result;
}

//struct ccrng_state* ccDRBGGetRngState(void);

static const char ALTHexCharacters[] = "0123456789abcdef";

struct ccrng_state* RNG = NULL;

// -----------------------------------------------------------------------------
// GrandSlam logical HTTP session (cpprestsdk transport)
// -----------------------------------------------------------------------------
// Keep a fresh cpprestsdk http_client/connection for each Apple request (this
// avoids the SRP #2 HTTP 429 we observed), but preserve cookies across SRP,
// trusted-device 2FA, validate, and apptokens. This recreates the relevant
// logical-session behavior of NSURLSession without reusing its TCP connection.
// Cookie values are authentication material, so diagnostics log counts only.
static std::map<std::string, std::string> ALTGrandSlamCookieJar;

static void ALTResetGrandSlamCookies()
{
    ALTGrandSlamCookieJar.clear();
    odslog("GrandSlam logical session: cookie jar reset");
}

static void ALTStoreGrandSlamCookies(const http_response& response, std::shared_ptr<altauth::Context> context = nullptr)
{
    if (!response.headers().has(U("Set-Cookie"))) return;
    
    
    auto it = response.headers().find(U("Set-Cookie"));
if (it == response.headers().end()) return;
std::string raw = StringFromWideString(it->second);
    
    
    auto semi = raw.find(';');
    std::string pair = (semi == std::string::npos) ? raw : raw.substr(0, semi);
    auto eq = pair.find('=');
    if (eq == std::string::npos || eq == 0)
    {
        odslog("GrandSlam logical session: Set-Cookie present but not parseable");
        return;
    }
    auto& jar = context && context->modern ? context->cookies : ALTGrandSlamCookieJar;
    jar[pair.substr(0, eq)] = pair.substr(eq + 1);
    odslog("GrandSlam logical session: cookie stored; jar size=" << jar.size());
}

static void ALTApplyGrandSlamCookies(http_request& request, std::shared_ptr<altauth::Context> context = nullptr)
{
    auto& jar = context && context->modern ? context->cookies : ALTGrandSlamCookieJar;
    if (jar.empty())
    {
        odslog("GrandSlam logical session: outgoing cookies=0");
        return;
    }
    std::string value;
    for (const auto& cookie : jar)
    {
        if (!value.empty()) value += "; ";
        value += cookie.first + "=" + cookie.second;
    }
    if (request.headers().has(U("Cookie"))) request.headers().remove(U("Cookie"));
    request.headers().add(U("Cookie"), WideStringFromString(value));
    odslog("GrandSlam logical session: outgoing cookies=" << jar.size());
}


static void ALTLogRequestHeaders(
    const char* label,
    const web::http::http_request& request)
{
    odslog("=== " << label << " REQUEST ===");
    odslog("Method: " << StringFromWideString(request.method()));
    odslog("URI: " << StringFromWideString(request.request_uri().to_string()));

    for (const auto& h : request.headers())
    {
        odslog(StringFromWideString(h.first)
               << ": "
               << "[redacted]");
    }

    odslog("=== END " << label << " REQUEST ===");
}

std::vector<unsigned char> DataFromBytes(const char* bytes, size_t count)
{
	std::vector<unsigned char> data;
	data.reserve(count);
	for (int i = 0; i < count; i++)
	{
		data.push_back(bytes[i]);
	}

	return data;
}

void ALTDigestUpdateString(const struct ccdigest_info* di_info, struct ccdigest_ctx* di_ctx, std::string string)
{
	ccdigest_update(di_info, di_ctx, string.length(), string.c_str());
}

void ALTDigestUpdateData(const struct ccdigest_info* di_info, struct ccdigest_ctx* di_ctx, std::vector<unsigned char>& data)
{
	uint32_t data_len = (uint32_t)data.size(); // 4 bytes for length
	ccdigest_update(di_info, di_ctx, sizeof(data_len), &data_len);
	ccdigest_update(di_info, di_ctx, data_len, data.data());
}

std::optional<std::vector<unsigned char>> ALTPBKDF2SRP(const struct ccdigest_info* di_info, bool isS2k, std::string password, std::vector<unsigned char>& salt, int iterations)
{
	const struct ccdigest_info* password_di_info = ccsha256_di();
	char* digest_raw = (char*)malloc(password_di_info->output_size);
	const char* passwordUTF8 = password.c_str();
	ccdigest(password_di_info, strlen(passwordUTF8), passwordUTF8, digest_raw);

	size_t final_digest_len = password_di_info->output_size * (isS2k ? 1 : 2);
	char* digest = (char*)malloc(final_digest_len);

	if (isS2k)
	{
		memcpy(digest, digest_raw, final_digest_len);
	}
	else
	{
		for (size_t i = 0; i < password_di_info->output_size; i++)
		{
			char byte = digest_raw[i];
			digest[i * 2 + 0] = ALTHexCharacters[(byte >> 4) & 0x0F];
			digest[i * 2 + 1] = ALTHexCharacters[(byte >> 0) & 0x0F];
		}
	}

	char *outputBytes = (char*)malloc(di_info->output_size);

	if (ccpbkdf2_hmac(di_info, final_digest_len, digest, salt.size(), salt.data(), iterations, di_info->output_size, outputBytes) != 0)
	{
		return std::nullopt;
	}

	auto data = DataFromBytes(outputBytes, di_info->output_size);
	return std::make_optional(data);
}

std::vector<unsigned char> ALTCreateSessionKey(ccsrp_ctx_t srp_ctx, const char* key_name)
{
        const struct ccdigest_info* di_info = ccsha256_di();

        // GrandSlam uses the modulus-sized SRP premaster secret S as
        // the HMAC key, rather than CoreCrypto's hashed session key K.
        cc_unit* premaster = ccsrp_get_premaster_secret(srp_ctx);

        if (premaster == NULL)
        {
                odslog("ERROR: SRP premaster secret is unavailable.");
                return {};
        }

        // Edits Sept 2026. trimmed S
        size_t key_len =
        ccn_write_uint_size(ccsrp_ctx_n(srp_ctx), premaster);
			std::vector<unsigned char> session_key(key_len);

			ccn_write_uint(
				ccsrp_ctx_n(srp_ctx),premaster,key_len,session_key.data()
				);

        odslog("GrandSlam trimmed premaster key length: " << key_len);
			
			
			// Diagnostic: reproduce CoreCrypto's padded representation of S
size_t padded_s_len = ccsrp_ctx_sizeof_n(srp_ctx);
std::vector<unsigned char> padded_s(padded_s_len, 0);

ccn_write_uint_padded(
    ccsrp_ctx_n(srp_ctx),
    premaster,
    padded_s_len,
    padded_s.data()
);

unsigned char padded_s_hash[SHA256_DIGEST_LENGTH];
SHA256(
    padded_s.data(),
    padded_s.size(),
    padded_s_hash
);

size_t internal_k_len = 0;
const void* internal_k =
    ccsrp_get_session_key(srp_ctx, &internal_k_len);

bool padded_s_matches_internal_k =
    internal_k != nullptr &&
    internal_k_len == SHA256_DIGEST_LENGTH &&
    memcmp(
        padded_s_hash,
        internal_k,
        SHA256_DIGEST_LENGTH
    ) == 0;

odslog(
    "Padded S SHA256 vs CoreCrypto internal K: "
    << (padded_s_matches_internal_k ? "MATCH" : "MISMATCH")
);
			
			
        size_t length = strlen(key_name);
        size_t hmac_len = di_info->output_size;

        std::vector<unsigned char> hmac_bytes(hmac_len);

        cchmac(
                di_info,
                key_len,
                session_key.data(),
                length,
                key_name,
                hmac_bytes.data()
        );
			// Diagnostic: compare CoreCrypto HMAC-SHA256 against OpenSSL 
			unsigned char openssl_hmac[EVP_MAX_MD_SIZE]; 
			unsigned int openssl_hmac_len = 0;

			HMAC(
    			EVP_sha256(),
    			session_key.data(),
    			static_cast<int>(key_len),
    			reinterpret_cast<const unsigned char*>(key_name),
    			length,
    			openssl_hmac,
    			&openssl_hmac_len
				);

			bool hmac_match =
    			(openssl_hmac_len == hmac_len) &&
    			(memcmp(openssl_hmac, hmac_bytes.data(), hmac_len) == 0);

			odslog("HMAC cross-check [" << key_name << "]: "<< (hmac_match ?"MATCH" : "MISMATCH"));
			odslog("AltSign sizeof(ccsrp_ctx): " << sizeof(struct ccsrp_ctx));
			odslog("AltSign offsetof(ccn): " << offsetof(struct ccsrp_ctx, ccn));
			
        return hmac_bytes;
}
std::optional<std::vector<unsigned char>> ALTDecryptDataGCM(std::vector<unsigned char>& sk, std::vector<unsigned char>& encryptedData)
{
	const struct ccmode_gcm* decrypt_mode = ccaes_gcm_decrypt_mode();

	ccgcm_ctx* gcm_ctx = (ccgcm_ctx*)malloc(decrypt_mode->size);
	decrypt_mode->init(decrypt_mode, gcm_ctx, sk.size(), sk.data());

	if (encryptedData.size() < 35)
	{
		odslog("ERROR: Encrypted token too short.");
		return std::nullopt;
	}

	if (cc_cmp_safe(3, encryptedData.data(), "XYZ"))
	{
		odslog("ERROR: Encrypted token wrong version!");
		return std::nullopt;
	}

	decrypt_mode->set_iv(gcm_ctx, 16, encryptedData.data() + 3);
	decrypt_mode->gmac(gcm_ctx, 3, encryptedData.data());

	size_t decrypted_len = encryptedData.size() - 35;

	char* decryptedBytes = (char*)malloc(decrypted_len);

	decrypt_mode->gcm(gcm_ctx, decrypted_len, encryptedData.data() + 16 + 3, decryptedBytes);

	char tag[16];
	decrypt_mode->finalize(gcm_ctx, 16, tag);

	if (cc_cmp_safe(16, encryptedData.data() + decrypted_len + 19, tag))
	{
		odslog("ERROR: Invalid tag version.");
		return std::nullopt;
	}

	auto decryptedData = DataFromBytes((const char*)decryptedBytes, decrypted_len);
	return decryptedData;
}

// check decrypt job with OpenSSL AES 
std::optional<std::vector<unsigned char>> ALTDecryptDataCBC(
    ccsrp_ctx_t srp_ctx,
    std::vector<unsigned char>& spd)
{
    auto extraDataKey = ALTCreateSessionKey(srp_ctx, "extra data key:");
    auto extraDataIV  = ALTCreateSessionKey(srp_ctx, "extra data iv:");

    /*
     * Existing CoreCrypto AES-CBC decrypt
     */
    char* decryptedBytes = (char*)malloc(spd.size());

    const struct ccmode_cbc* decrypt_mode = ccaes_cbc_decrypt_mode();

    cccbc_iv* iv = (cccbc_iv*)malloc(decrypt_mode->block_size);

    if (extraDataIV.data())
    {
        memcpy(iv, extraDataIV.data(), decrypt_mode->block_size);
    }
    else
    {
        memset(iv, 0, decrypt_mode->block_size);
    }

    cccbc_ctx* ctx_buf = (cccbc_ctx*)malloc(decrypt_mode->size);

    decrypt_mode->init(
        decrypt_mode,
        ctx_buf,
        extraDataKey.size(),
        extraDataKey.data()
    );

    size_t length = ccpad_pkcs7_decrypt(
        decrypt_mode,
        ctx_buf,
        iv,
        spd.size(),
        spd.data(),
        decryptedBytes
    );

    /*
     * Diagnostic: decrypt the SAME ciphertext with OpenSSL AES-256-CBC.
     */
    EVP_CIPHER_CTX* ossl_ctx = EVP_CIPHER_CTX_new();

    std::vector<unsigned char> ossl_plaintext(spd.size() + EVP_MAX_BLOCK_LENGTH);

    int ossl_len1 = 0;
    int ossl_len2 = 0;

    int ossl_ok = EVP_DecryptInit_ex(
        ossl_ctx,
        EVP_aes_256_cbc(),
        NULL,
        extraDataKey.data(),
        extraDataIV.data()
    );

    if (ossl_ok == 1)
    {
        ossl_ok = EVP_DecryptUpdate(
            ossl_ctx,
            ossl_plaintext.data(),
            &ossl_len1,
            spd.data(),
            static_cast<int>(spd.size())
        );
    }

    if (ossl_ok == 1)
    {
        ossl_ok = EVP_DecryptFinal_ex(
            ossl_ctx,
            ossl_plaintext.data() + ossl_len1,
            &ossl_len2
        );
    }

    EVP_CIPHER_CTX_free(ossl_ctx);

    if (ossl_ok == 1)
    {
        size_t ossl_total =
            static_cast<size_t>(ossl_len1 + ossl_len2);

        bool aes_match =
            (ossl_total == length) &&
            (memcmp(
                ossl_plaintext.data(),
                decryptedBytes,
                length
            ) == 0);

        odslog(
            "AES-CBC cross-check: "
            << (aes_match ? "MATCH" : "MISMATCH")
            << " (CoreCrypto=" << length
            << " bytes, OpenSSL=" << ossl_total << " bytes)"
        );

        // Safe diagnostic: only identify whether OpenSSL output
        // begins like a plist, don't print decrypted account data.
        bool looks_like_plist =
    			((ossl_total >= 5) &&
     			memcmp(ossl_plaintext.data(), "<?xml", 5) == 0) ||
    			((ossl_total >= 6) &&
     			memcmp(ossl_plaintext.data(), "bplist", 6) == 0);

        odslog(
            "OpenSSL decrypted SPD looks like plist: "
            << (looks_like_plist ? "YES" : "NO")
        );
    }
    else
    {
        odslog("OpenSSL AES-CBC decrypt/padding: FAILED");
    }

    /*
     * Continue using the original CoreCrypto result.
     */
    if (length > spd.size())
    {
        return std::nullopt;
    }

    auto decryptedData =
        DataFromBytes((const char*)decryptedBytes, length);

    return decryptedData;
}


std::vector<unsigned char> ALTCreateAppTokensChecksum(const std::vector<unsigned char>& sk, std::string adsid, std::vector<std::string> apps)


{
	const struct ccdigest_info* di_info = ccsha256_di();
	size_t hmac_size = cchmac_di_size(di_info);
	struct cchmac_ctx* hmac_ctx = (struct cchmac_ctx*)malloc(hmac_size);
	cchmac_init(di_info, hmac_ctx, sk.size(), sk.data());

	const char* key = "apptokens";
	cchmac_update(di_info, hmac_ctx, strlen(key), key);

	const char* adsidUTF8 = adsid.c_str();
	cchmac_update(di_info, hmac_ctx, strlen(adsidUTF8), adsidUTF8);

	for (auto app : apps)
	{
		cchmac_update(di_info, hmac_ctx, app.size(), app.c_str());
	}

	char* checksumBytes = (char*)malloc(di_info->output_size);
	cchmac_final(di_info, hmac_ctx, (unsigned char *)checksumBytes);

	auto checksum = DataFromBytes(checksumBytes, di_info->output_size);
	return checksum;
}

pplx::task<std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>>> AppleAPI::Authenticate(
	std::string appleID,
	std::string password,
	std::shared_ptr<AnisetteData> anisetteData,
	std::optional<std::function <pplx::task<std::optional<std::string>>(void)>> verificationHandler,
    std::shared_ptr<altauth::Context> context)
{
    if (!context) context = std::make_shared<altauth::Context>();
    context->current = anisetteData;
    if (context->modern) {
        altauth::headerValue(context->current->deviceDescription());
        altauth::headerValue(context->current->authenticationUserAgent);
        std::transform(appleID.begin(), appleID.end(), appleID.begin(),
            [](unsigned char c) { return std::tolower(c); });
    }
    if (!context->modern || context->factors == 0) ALTResetGrandSlamCookies(); // new login = new logical Apple HTTP session

	if (RNG == nullptr)
	{
		RNG = ccrng(NULL);
	}

	auto adsidValue = std::make_shared<std::string>("");
	auto sessionValue = std::make_shared<AppleAPISession>();

	time_t time;
	struct tm* tm;
	char dateString[64];

	time = context->current->date().tv_sec;
	//tm = gmtime(&time);
	//strftime(dateString, sizeof dateString, "%Y-%m-%dT%H:%M:%SZ", tm);
	tm = gmtime(&time);
	strftime(dateString, sizeof dateString, "%FT%TZ", tm);
	
	
	std::map<std::string, plist_t> clientDictionary = {
		{ "bootstrap", plist_new_bool(true) },
		{ "icscrec", plist_new_bool(true) },
		{ "loc", plist_new_string(context->current->locale().c_str()) },
		{ "pbe", plist_new_bool(false) },
		{ "prkgen", plist_new_bool(true) },
		{ "svct", plist_new_string("iCloud") },
		{ "X-Apple-I-Client-Time", plist_new_string(dateString) },
		{ "X-Apple-Locale", plist_new_string(context->current->locale().c_str()) },
		{ "X-Apple-I-TimeZone", plist_new_string(context->current->timeZone().c_str()) },
		{ "X-Apple-I-MD", plist_new_string(context->current->oneTimePassword().c_str()) },
		{ "X-Apple-I-MD-LU", plist_new_string(context->current->localUserID().c_str()) },
		{ "X-Apple-I-MD-M", plist_new_string(context->current->machineID().c_str()) },
		{ "X-Apple-I-MD-RINFO", plist_new_uint(context->current->routingInfo()) },
		{ "X-Mme-Device-Id", plist_new_string(context->current->deviceUniqueIdentifier().c_str()) },
		{ "X-Apple-I-SRL-NO", plist_new_string(context->current->deviceSerialNumber().c_str()) }
	};

	/* Begin CoreCrypto Logic */
	ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();

	const struct ccdigest_info* di_info = ccsha256_di();
	struct ccdigest_ctx* di_ctx = (struct ccdigest_ctx*)malloc(ccdigest_di_size(di_info));
	ccdigest_init(di_info, di_ctx);

	const struct ccdigest_info* srp_di = ccsha256_di();
	ccsrp_ctx_t srp_ctx = (ccsrp_ctx_t)malloc(ccsrp_sizeof_srp(di_info, gp));
	ccsrp_ctx_init(srp_ctx, srp_di, gp);

	HDR(srp_ctx)->blinding_rng = ccrng(NULL);
	HDR(srp_ctx)->flags.noUsernameInX = true;

	std::vector<std::string> ps = { "s2k", "s2k_fo" };
	ALTDigestUpdateString(di_info, di_ctx, ps[0]);
	ALTDigestUpdateString(di_info, di_ctx, ",");
	ALTDigestUpdateString(di_info, di_ctx, ps[1]);

	size_t A_size = ccsrp_exchange_size(srp_ctx);
	char* A_bytes = (char*)malloc(A_size);
	ccsrp_client_start_authentication(srp_ctx, ccrng(NULL), A_bytes);

	auto A_data = DataFromBytes(A_bytes, A_size);

	ALTDigestUpdateString(di_info, di_ctx, "|");

	auto psPlist = plist_new_array();
	for (auto value : ps)
	{
		plist_array_append_item(psPlist, plist_new_string(value.c_str()));
	}	

	auto cpd = plist_new_dict();
	for (auto pair : clientDictionary)
	{
		plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
	}

	std::map<std::string, plist_t> parameters = {
		{ "A2k", plist_new_data((const char *)A_bytes, A_size) },
		{ "ps", psPlist },
		{ "cpd", cpd },
		{ "u", plist_new_string(appleID.c_str()) },
		{ "o", plist_new_string("init") }
	};

	auto task = this->SendAuthenticationRequest(parameters, context->current, context)
		.then([=](plist_t plist) {

		size_t M_size = ccsrp_get_session_key_length(srp_ctx);
		char* M_bytes = (char*)malloc(M_size);

		auto spNode = plist_dict_get_item(plist, "sp");
		if (spNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* sp = nullptr;
		plist_get_string_val(spNode, &sp);

		bool isS2K = (std::string(sp) == "s2k");

		ALTDigestUpdateString(di_info, di_ctx, "|");

		if (sp)
		{
			ALTDigestUpdateString(di_info, di_ctx, sp);
		}

		auto cNode = plist_dict_get_item(plist, "c");
		auto saltNode = plist_dict_get_item(plist, "s");
		auto iterationsNode = plist_dict_get_item(plist, "i");
		auto bNode = plist_dict_get_item(plist, "B");

		if (cNode == nullptr || saltNode == nullptr || iterationsNode == nullptr || bNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* c = nullptr;
		plist_get_string_val(cNode, &c);

		char* saltBytes = nullptr;
		uint64_t saltSize = 0;
		plist_get_data_val(saltNode, &saltBytes, &saltSize);

		uint64_t iterations = 0;
		plist_get_uint_val(iterationsNode, &iterations);

		char* B_bytes = nullptr;
		uint64_t B_size = 0;
		plist_get_data_val(bNode, &B_bytes, &B_size);

		auto salt = DataFromBytes((const char*)saltBytes, saltSize);
		auto B_data = DataFromBytes((const char*)B_bytes, B_size);

		auto passwordKey = ALTPBKDF2SRP(di_info, isS2K, password, salt, iterations);
		if (passwordKey == ::nullopt)
		{
			throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
		}

		int result = ccsrp_client_process_challenge(srp_ctx, appleID.c_str(), passwordKey->size(), passwordKey->data(),
			salt.size(), salt.data(), B_data.data(), M_bytes);
		if (result != 0)
		{
			throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
		}

		time_t time;
		struct tm* tm;
		char dateString[64];

		time = context->current->date().tv_sec;
		//tm = gmtime(&time);
		//strftime(dateString, sizeof dateString, "%Y-%m-%dT%H:%M:%SZ", tm);
		tm = gmtime(&time);
		strftime(dateString, sizeof dateString, "%FT%TZ", tm);
		
		
		std::map<std::string, plist_t> clientDictionary = {
		{ "bootstrap", plist_new_bool(true) },
		{ "icscrec", plist_new_bool(true) },
		{ "loc", plist_new_string(context->current->locale().c_str()) },
		{ "pbe", plist_new_bool(false) },
		{ "prkgen", plist_new_bool(true) },
		{ "svct", plist_new_string("iCloud") },
		{ "X-Apple-I-Client-Time", plist_new_string(dateString) },
		{ "X-Apple-Locale", plist_new_string(context->current->locale().c_str()) },
		{ "X-Apple-I-TimeZone", plist_new_string(context->current->timeZone().c_str()) },
		{ "X-Apple-I-MD", plist_new_string(context->current->oneTimePassword().c_str()) },
		{ "X-Apple-I-MD-LU", plist_new_string(context->current->localUserID().c_str()) },
		{ "X-Apple-I-MD-M", plist_new_string(context->current->machineID().c_str()) },
		{ "X-Apple-I-MD-RINFO", plist_new_uint(context->current->routingInfo()) },
		{ "X-Mme-Device-Id", plist_new_string(context->current->deviceUniqueIdentifier().c_str()) },
		{ "X-Apple-I-SRL-NO", plist_new_string(context->current->deviceSerialNumber().c_str()) }
		};

		auto cpd = plist_new_dict();
		for (auto pair : clientDictionary)
		{
			plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
		}

		std::map<std::string, plist_t> parameters = {
			{ "c", plist_new_string(c) },
			{ "M1", plist_new_data((const char*)M_bytes, M_size) },
			{ "cpd", cpd },
			{ "u", plist_new_string(appleID.c_str()) },
			{ "o", plist_new_string("complete") }
		};

		return this->SendAuthenticationRequest(parameters, context->current, context);
			}).then([=](plist_t plist) {

				auto M2_node = plist_dict_get_item(plist, "M2");
				if (M2_node == nullptr)
				{
					odslog("ERROR: M2 data not found!");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* M2_bytes = nullptr;
				uint64_t M2_size = 0;
				plist_get_data_val(M2_node, &M2_bytes, &M2_size);

				if (!ccsrp_client_verify_session(srp_ctx, (const uint8_t*)M2_bytes)){
        			odslog("Apple M2 vs CoreCrypto expected M2: MISMATCH");
        			throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
					}

odslog("Apple M2 vs CoreCrypto expected M2: MATCH");

				ALTDigestUpdateString(di_info, di_ctx, "|");

				std::vector<unsigned char> spd;
				auto spdNode = plist_dict_get_item(plist, "spd");
				if (spdNode != nullptr)
				{
					char* spdBytes = nullptr;
					uint64_t spdSize = 0;
					plist_get_data_val(spdNode, &spdBytes, &spdSize);

					spd = DataFromBytes(spdBytes, spdSize);
					ALTDigestUpdateData(di_info, di_ctx, spd);
				}

				ALTDigestUpdateString(di_info, di_ctx, "|");

				auto scNode = plist_dict_get_item(plist, "sc");
				if (scNode != nullptr)
				{
					char* scBytes = nullptr;
					uint64_t scSize = 0;
					plist_get_data_val(scNode, &scBytes, &scSize);

					auto sc = DataFromBytes(scBytes, scSize);
					ALTDigestUpdateData(di_info, di_ctx, sc);
				}

				ALTDigestUpdateString(di_info, di_ctx, "|");

				auto npNode = plist_dict_get_item(plist, "np");
				if (npNode == nullptr)
				{
					odslog("ERROR: Missing np dictionary.");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* npBytes = nullptr;
				uint64_t npSize = 0;
				plist_get_data_val(npNode, &npBytes, &npSize);

				auto np = DataFromBytes(npBytes, npSize);
				ALTDigestUpdateData(di_info, di_ctx, np);

				size_t digest_len = di_info->output_size;
				if (np.size() != digest_len)
				{
					odslog("ERROR: Neg proto hash is too short.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}

				unsigned char* digest = (unsigned char*)malloc(digest_len);
				di_info->final(di_info, di_ctx, digest);

				auto hmacKey = ALTCreateSessionKey(srp_ctx, "HMAC key:");
				unsigned char* hmac_out = (unsigned char*)malloc(digest_len);
				cchmac(di_info, hmacKey.size(), hmacKey.data(), digest_len, digest, hmac_out);

				//odslog("HMAC_OUT:");
				for (int i = 0; i < digest_len; i++)
				{
					char str[8];
					char byte = ((char*)hmac_out)[i];
					_itoa(byte, str, 10);

					//odslog("Byte:" << str);
				}

				//odslog("NP:");
				for (int i = 0; i < digest_len; i++)
				{
					char str[8];
					char byte = ((char*)npBytes)[i];
					_itoa(byte, str, 10);

					//odslog("Byte:" << str);
				}

				/*
				if (cc_cmp_safe(digest_len, hmac_out, np.data()))
				{
					odslog("ERROR: Invalid neg prot hmac.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}*/

				auto decryptedData = ALTDecryptDataCBC(srp_ctx, spd);
				if (decryptedData == ::nullopt)
				{
					odslog("ERROR: Could not decrypt login response.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}

				//odslog("Data: " << decryptedData->data());

				plist_t decryptedPlist = nullptr;
				plist_from_xml((const char *)decryptedData->data(), (int)decryptedData->size(), &decryptedPlist);

				if (decryptedPlist == nullptr)
				{
					odslog("ERROR: Could not parse decrypted login response plist!");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				auto adsidNode = plist_dict_get_item(decryptedPlist, "adsid");
				auto idmsTokenNode = plist_dict_get_item(decryptedPlist, "GsIdmsToken");

				if (adsidNode == nullptr || idmsTokenNode == nullptr)
				{
					odslog("ERROR: adsid and /or idmsToken is nil.");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* adsid = nullptr;
				plist_get_string_val(adsidNode, &adsid);

				char* idmsToken = nullptr;
				plist_get_string_val(idmsTokenNode, &idmsToken);

				
				
				auto statusDictionary = plist_dict_get_item(plist, "Status");
if (statusDictionary == nullptr)
{
    throw APIError(APIErrorCode::InvalidResponse);
}

bool isTwoFactorEnabled = false;

auto authTypeNode = plist_dict_get_item(statusDictionary, "au");
				
				
				
				if (authTypeNode != nullptr)
				{
					char* authType = nullptr;
					plist_get_string_val(authTypeNode, &authType);
					// Do not log provider-supplied authentication strings.

					if (std::string(authType) == "trustedDeviceSecondaryAuth" ||
    std::string(authType) == "secondaryAuth")
{
    isTwoFactorEnabled = true;
}
				}

                if (context->modern) {
                    auto factor = altauth::factor(ALTStatusString(statusDictionary, "au"),
                                                  ALTStatusInteger(statusDictionary, "hsc"));
                    if (factor != altauth::Factor::none) {
                        if (!verificationHandler) throw APIError(APIErrorCode::RequiresTwoFactorAuthentication);
                        context->beginFactor();
                        return this->RequestModernTwoFactorCode(adsid, idmsToken, factor,
                            *verificationHandler, context).then([=](bool success) {
                            if (!success) throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
                            auto fresh = ALTRefreshData(context);
                            return this->Authenticate(appleID, password, fresh, verificationHandler, context);
                        });
                    }
                    isTwoFactorEnabled = false;
                }

                // IMPORTANT (Sep 2026): extract and preserve the token material from
                // THIS successful SRP exchange before deciding whether 2FA is needed.
                // xhzq233/altsign-cli performs trusted-device validation and then uses
                // these same sk/c/adsid/GsIdmsToken values for `apptokens`.  It does
                // NOT start a second SRP exchange after the verification code succeeds.
                auto skNode = plist_dict_get_item(decryptedPlist, "sk");
                auto cNode = plist_dict_get_item(decryptedPlist, "c");

                if (skNode == nullptr || cNode == nullptr)
                {
                    odslog("ERROR: No sk and/or c data in decrypted SPD.");
                    throw APIError(APIErrorCode::InvalidResponse);
                }

                char* skBytes = nullptr;
                uint64_t skSize = 0;
                plist_get_data_val(skNode, &skBytes, &skSize);

                char* cBytes = nullptr;
                uint64_t cSize = 0;
                plist_get_data_val(cNode, &cBytes, &cSize);

                odslog("APPTOKENS SPD structural check:"
                       << " sk_type=" << plist_get_node_type(skNode)
                       << " sk_len=" << skSize
                       << " c_type=" << plist_get_node_type(cNode)
                       << " c_len=" << cSize);

                // Copy everything that must survive the asynchronous 2FA callbacks.
                // Never capture the plist-owned char* buffers themselves across tasks.
                auto sk = DataFromBytes((const char*)skBytes, skSize);
                auto requestC = DataFromBytes((const char*)cBytes, cSize);
                std::string preservedAdsid(adsid);
                std::string preservedIdmsToken(idmsToken);

                // Build and send the app-token request from the ORIGINAL SRP state.
                // This helper is deliberately local to this authentication transaction.
                auto fetchOriginalSessionToken = [=]() {
                    auto appsNode = plist_new_array();
                    plist_array_append_item(appsNode, plist_new_string("com.apple.gs.xcode.auth"));

                    auto checksum = ALTCreateAppTokensChecksum(
                        sk,
                        preservedAdsid,
                        { "com.apple.gs.xcode.auth" });

                    odslog("APPTOKENS request uses preserved first-SRP state:"
                           << " checksum_len=" << checksum.size()
                           << " adsid_len=" << preservedAdsid.length()
                           << " token_len=" << preservedIdmsToken.length());

                    std::map<std::string, plist_t> clientDictionary = {
                        { "bootstrap", plist_new_string("true") },
                        { "icscrec", plist_new_string("true") },
                        { "loc", plist_new_string("en_US") },
                        { "pbe", plist_new_string("false") },
                        { "prkgen", plist_new_string("true") },
                        { "svct", plist_new_string("iCloud") },
                        { "X-Mme-Device-Id", plist_new_string(context->current->deviceUniqueIdentifier().c_str()) },
                        { "X-Apple-I-MD", plist_new_string(context->current->oneTimePassword().c_str()) },
                        { "X-Apple-I-MD-M", plist_new_string(context->current->machineID().c_str()) }
                    };

                    auto cpd = plist_new_dict();
                    for (auto pair : clientDictionary)
                    {
                        plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
                    }

                    std::map<std::string, plist_t> parameters = {
                        { "u", plist_new_string(preservedAdsid.c_str()) },
                        { "app", appsNode },
                        { "c", plist_new_data((const char*)requestC.data(), requestC.size()) },
                        { "t", plist_new_string(preservedIdmsToken.c_str()) },
                        { "checksum", plist_new_data((const char*)checksum.data(), checksum.size()) },
                        { "cpd", cpd },
                        { "o", plist_new_string("apptokens") }
                    };

                    *adsidValue = preservedAdsid;
                    return this->FetchAuthToken(parameters, sk, context->current, context)
                        .then([=](std::string token) {
                            auto session = std::make_shared<AppleAPISession>(
                                *adsidValue, token, context->current);
                            *sessionValue = *session;
                            return this->FetchAccount(session);
                        })
                        .then([=](std::shared_ptr<Account> account)
                            -> std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>> {
                            return std::make_pair(account, sessionValue);
                        });
                };

                if (isTwoFactorEnabled)
                {
                    odslog("Requires two factor...");

                    if (!verificationHandler.has_value())
                    {
                        throw APIError(APIErrorCode::RequiresTwoFactorAuthentication);
                    }

                    return this->RequestTwoFactorCode(
                            preservedAdsid,
                            preservedIdmsToken,
                            anisetteData,
                            *verificationHandler)
                        .then([=](bool success) {
                            if (!success)
                            {
                                throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
                            }

                            
                            // SideSign 2026 behavior:
// After successful 2FA, restart authentication.
// The next SRP exchange should now see the account as 2FA-authorized.
odslog("2FA validated; restarting authentication as SideSign does.");

return this->Authenticate(
    appleID,
    password,
    anisetteData,
    verificationHandler);
                            
                            
                            
                        });
                }

                // No secondary authentication was requested: use the same path directly.
                return fetchOriginalSessionToken();

			});

	return task;
}

pplx::task<std::string> AppleAPI::FetchAuthToken(std::map<std::string, plist_t> requestParameters, std::vector<unsigned char> sk, std::shared_ptr<AnisetteData> anisetteData, std::shared_ptr<altauth::Context> context)
{
	auto apps = requestParameters["app"];
	auto appNode = plist_array_get_item(apps, 0);

	char* appName = nullptr;
	plist_get_string_val(appNode, &appName);

	std::string app(appName);

	return this->SendAuthenticationRequest(requestParameters, anisetteData, context)
	.then([=](plist_t plist) {
		odslog("FetchAuthToken: response received for " << app);
		auto encryptedTokenNode = plist_dict_get_item(plist, "et");
		if (encryptedTokenNode == nullptr)
		{
			odslog("FetchAuthToken: ERROR missing et");
			throw APIError(APIErrorCode::InvalidResponse);
		}

		odslog("FetchAuthToken: et present");
		char* encryptedTokenBytes = nullptr;
		uint64_t encryptedTokenSize = 0;
		plist_get_data_val(encryptedTokenNode, &encryptedTokenBytes, &encryptedTokenSize);

		auto sk_copy = sk;

		auto encryptedToken = DataFromBytes(encryptedTokenBytes, encryptedTokenSize);
		odslog("FetchAuthToken: attempting GCM decrypt");
		auto decryptedToken = ALTDecryptDataGCM(sk_copy, encryptedToken);

		if (decryptedToken == ::nullopt)
		{
			odslog("FetchAuthToken: ERROR GCM decrypt FAILED");
			odslog("ERROR: Failed to decrypt apptoken.");
			throw APIError(APIErrorCode::InvalidResponse);
		}
		odslog("FetchAuthToken: GCM decrypt SUCCESS");
		plist_t decryptedTokenPlist = nullptr;
		plist_from_xml((const char *)decryptedToken->data(), decryptedToken->size(), &decryptedTokenPlist);

		if (decryptedTokenPlist == nullptr)
		{
			odslog("ERROR: Could not parse decrypted apptoken plist.");
			throw APIError(APIErrorCode::InvalidResponse);
		}
		odslog("FetchAuthToken: decrypted plist parsed successfully");
		auto tokensNode = plist_dict_get_item(decryptedTokenPlist, "t");
		if (tokensNode == nullptr)
		{
			odslog("FetchAuthToken: ERROR missing t dictionary");
			throw APIError(APIErrorCode::InvalidResponse);
		}

		odslog("FetchAuthToken: t dictionary present");
		auto tokenDictionary = plist_dict_get_item(tokensNode, app.c_str());
		if (tokenDictionary == nullptr)
		{
			odslog("FetchAuthToken: ERROR missing dictionary for " << app);
			throw APIError(APIErrorCode::InvalidResponse);
		}
		odslog("FetchAuthToken: app dictionary present for " << app);
		auto tokenNode = plist_dict_get_item(tokenDictionary, "token");
		if (tokenNode == nullptr)
		{
			odslog("FetchAuthToken: ERROR missing token");
			throw APIError(APIErrorCode::InvalidResponse);
		}

		odslog("FetchAuthToken: token field present");
		char* token = nullptr;
		plist_get_string_val(tokenNode, &token);

		odslog("FetchAuthToken: SUCCESS got token for " << app);
		//odslog("Got token for " << app << "!\nValue : " << token);

		return std::string(token);
	});
}



// Official AltSign 1599a32/06c4bdd flow, adapted to cpprestsdk.
pplx::task<bool> AppleAPI::RequestModernTwoFactorCode(
    std::string dsid, std::string token, altauth::Factor factor,
    const std::function<pplx::task<std::optional<std::string>>()>& handler,
    std::shared_ptr<altauth::Context> context)
{
    const bool sms = factor == altauth::Factor::sms;
    auto send = [=](bool validate, const std::string& code) {
        // In particular, always refresh AFTER the user has typed a code.
        auto data = ALTRefreshData(context);
        context->consume(data->oneTimePassword());
        http_request request(sms ? methods::POST : methods::GET);
        request.set_request_uri(sms
            ? (validate ? U("/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put") : U("/auth/verify/phone/put?mode=sms"))
            : (validate ? U("/grandslam/GsService2/validate") : U("/auth/verify/trusteddevice")));
        const std::string identity = dsid + ":" + token;
        auto encoded = utility::conversions::to_base64(std::vector<unsigned char>(identity.begin(), identity.end()));
        request.headers().add(U("X-Apple-Identity-Token"), encoded);
        request.headers().add(U("User-Agent"), data->authenticationUserAgent);
        request.headers().add(U("X-MMe-Client-Info"), data->deviceDescription());
        request.headers().add(U("X-Apple-I-MD"), data->oneTimePassword());
        request.headers().add(U("X-Apple-I-MD-M"), data->machineID());
        request.headers().add(U("X-Apple-I-MD-LU"), data->localUserID());
        request.headers().add(U("X-Apple-I-MD-RINFO"), std::to_string(data->routingInfo()));
        request.headers().add(U("X-Mme-Device-Id"), data->deviceUniqueIdentifier());
        request.headers().add(U("X-Apple-App-Info"), U("com.apple.gs.xcode.auth"));
        request.headers().add(U("X-Xcode-Version"), U("27.0 (27A5218g)"));
        request.headers().add(U("Content-Type"), U("text/x-xml-plist"));
        request.headers().add(U("Accept"), U("text/x-xml-plist"));
        request.headers().add(U("Accept-Language"), U("en-us"));
        request.headers().add(U("Connection"), U("close"));
        char date[64]; time_t stamp = data->date().tv_sec; struct tm tm;
        gmtime_r(&stamp, &tm); strftime(date, sizeof(date), "%FT%TZ", &tm);
        request.headers().add(U("X-Apple-I-Client-Time"), date);
        auto locale = data->locale(); locale = locale.substr(0, locale.find('@'));
        request.headers().add(U("X-Apple-Locale"), locale);
        request.headers().add(U("X-Apple-I-TimeZone"), data->timeZone());
        request.headers().add(U("X-Apple-I-SRL-NO"), data->deviceSerialNumber());
        if (sms) {
            auto body = plist_new_dict();
            auto server = plist_new_dict();
            plist_dict_set_item(server, "phoneNumber.id", plist_new_string("1"));
            plist_dict_set_item(body, "serverInfo", server);
            plist_dict_set_item(server, "mode", plist_new_string("sms"));
            if (validate) plist_dict_set_item(body, "securityCode.code", plist_new_string(code.c_str()));
            char* xml = nullptr; uint32_t size = 0; plist_to_xml(body, &xml, &size);
            request.set_body(std::string(xml, size)); free(xml); plist_free(body);
        } else if (validate) request.headers().add(U("security-code"), code);
        ALTApplyGrandSlamCookies(request, context);
        http_client_config config;
        config.set_validate_certificates(true);
        config.set_max_redirects(0);
        config.set_timeout(std::chrono::seconds(30));
        auto client = std::make_shared<http_client>(U("https://gsa.apple.com"), config);
        auto task = context->transport ? context->transport(request) : client->request(request);
        return task.then([=](http_response response) {
            altauth::httpStatus(response.status_code());
            ALTStoreGrandSlamCookies(response, context);
            if (!validate) return pplx::task_from_result(true);
            if (sms) {
                if (response.status_code() != 200 || !response.headers().has(U("X-Apple-PE-Token")))
                    throw LocalizedError(-21669, altauth::appleError(-21669));
                return pplx::task_from_result(true);
            }
            return response.extract_vector().then([](std::vector<unsigned char> bytes) {
                if (bytes.size() > 1024 * 1024) throw APIError(APIErrorCode::InvalidResponse);
                plist_t body = nullptr; plist_from_xml((const char*)bytes.data(), bytes.size(), &body);
                auto owner = std::shared_ptr<void>(body, [](void* p) { if(p) plist_free((plist_t)p); });
                if (!body || plist_get_node_type(body) != PLIST_DICT || !plist_dict_get_item(body, "ec"))
                    throw APIError(APIErrorCode::InvalidResponse);
                auto code = ALTStatusInteger(body, "ec");
                if (code) throw LocalizedError(code, altauth::appleError(code));
                return true;
            });
        });
    };
    // hsc 409 with no au means Apple already sent a trusted-device code.
    auto start = factor == altauth::Factor::alreadySent
        ? pplx::task_from_result(true) : send(false, "");
    return start.then([=](bool) { return handler(); }).then([=](std::optional<std::string> code) {
        if (!code) throw APIError(APIErrorCode::RequiresTwoFactorAuthentication);
        if (code->size() != 6 || code->find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("Verification code must contain six digits");
        return send(true, *code);
    });
}

pplx::task<bool> AppleAPI::RequestTwoFactorCode(
    std::string dsid,
    std::string idmsToken,
    std::shared_ptr<AnisetteData> anisetteData,
    const std::function<pplx::task<std::optional<std::string>>(void)>& verificationHandler)
{
    // Sep 2026 SideSign-compatible secondaryAuth path:
    // secondaryAuth prefers SMS rather than blindly using trusteddevice.
    const std::string phoneID = "1";
    const std::string mode = "sms";

    time_t timestamp = anisetteData->date().tv_sec;
    struct tm* tm = gmtime(&timestamp);
    char dateString[64];
    strftime(dateString, sizeof(dateString), "%FT%TZ", tm);

    std::string identityToken = dsid + ":" + idmsToken;
    std::vector<unsigned char> identityTokenData(
        identityToken.begin(), identityToken.end());
    auto encodedIdentityToken =
        utility::conversions::to_base64(identityTokenData);

    std::map<utility::string_t, utility::string_t> headers = {
        {U("Accept"), U("application/x-buddyml")},
        {U("Accept-Language"), U("en-us")},
        {U("Content-Type"), U("application/x-plist")},
        {U("User-Agent"), WideStringFromString(ALTAuthKitUserAgent())},
        {U("X-Apple-App-Info"), U("com.apple.gs.xcode.auth")},
        {U("X-Xcode-Version"), U("27.0 (27A5218g)")},

        {U("X-Apple-Identity-Token"), encodedIdentityToken},
        {U("X-Apple-I-MD"),
            WideStringFromString(anisetteData->oneTimePassword())},
        {U("X-Apple-I-MD-M"),
            WideStringFromString(anisetteData->machineID())},
        {U("X-Apple-I-MD-LU"),
            WideStringFromString(anisetteData->localUserID())},
        {U("X-Apple-I-MD-RINFO"),
            WideStringFromString(
                std::to_string(anisetteData->routingInfo()))},
        {U("X-Apple-I-SRL-NO"),
            WideStringFromString(anisetteData->deviceSerialNumber())},

        {U("X-Mme-Device-Id"),
            WideStringFromString(
                anisetteData->deviceUniqueIdentifier())},
        {U("X-MMe-Client-Info"),
            WideStringFromString(anisetteData->deviceDescription())},

        {U("X-Apple-I-Client-Time"),
            WideStringFromString(dateString)},
        {U("X-Apple-Locale"),
            WideStringFromString(anisetteData->locale())},
        {U("X-Apple-I-TimeZone"),
            WideStringFromString(anisetteData->timeZone())},

        {U("Connection"), U("close")}
    };

    auto applyHeaders = [headers](http_request& request)
    {
        for (const auto& pair : headers)
        {
            if (request.headers().has(pair.first))
            {
                request.headers().remove(pair.first);
            }

            request.headers().add(pair.first, pair.second);
        }
    };

    // ------------------------------------------------------------
    // STEP 1: Ask Apple to send an SMS code.
    //
    // SideSign:
    // POST /auth/verify/phone/put?mode=sms
    //
    // When no trustedPhoneNumbers were returned by SRP, SideSign
    // falls back to phoneNumber.id = "1".
    // ------------------------------------------------------------

    http_request request(methods::POST);
    request.set_request_uri(
        U("/auth/verify/phone/put?mode=sms"));

    applyHeaders(request);

    plist_t serverInfo = plist_new_dict();
    plist_dict_set_item(
        serverInfo,
        "mode",
        plist_new_string(mode.c_str()));
    plist_dict_set_item(
        serverInfo,
        "phoneNumber.id",
        plist_new_string(phoneID.c_str()));

    plist_t bodyPlist = plist_new_dict();
    plist_dict_set_item(
        bodyPlist,
        "serverInfo",
        serverInfo);

    char* bodyXML = nullptr;
    uint32_t bodyLength = 0;
    plist_to_xml(bodyPlist, &bodyXML, &bodyLength);

    std::string body;
    if (bodyXML != nullptr)
    {
        body.assign(bodyXML, bodyLength);
        free(bodyXML);
    }

    plist_free(bodyPlist);

    request.set_body(body);

    odslog("=== SIDESIGN SMS 2FA INIT ===");
    odslog("phone ID fallback=" << phoneID);
    odslog("mode=" << mode);
    ALTLogRequestHeaders("SMS INIT", request);

    web::http::client::http_client_config config;
    config.set_validate_certificates(true);
    config.set_max_redirects(0);
    config.set_timeout(std::chrono::seconds(30));

    auto client =
        std::make_shared<web::http::client::http_client>(
            U("https://gsa.apple.com"), config);

    return client->request(request)

        .then([=](http_response response)
        {
            odslog("SMS init HTTP status="
                   << response.status_code());

            odslog("=== SMS INIT RESPONSE HEADER NAMES ===");
            for (const auto& h : response.headers())
            {
                odslog(StringFromWideString(h.first));
            }
            odslog("=== END SMS INIT RESPONSE HEADER NAMES ===");

            return response.extract_vector();
        })

      .then([=](std::vector<unsigned char> responseData)
{
    odslog("SMS init response bytes=" << responseData.size());

    std::string resolvedPhoneID = phoneID;   // fallback remains "1"
    std::string resolvedMode = mode;         // fallback remains "sms"

    plist_t responsePlist = nullptr;

    if (!responseData.empty())
    {
        plist_from_xml(
            reinterpret_cast<const char*>(responseData.data()),
            static_cast<uint32_t>(responseData.size()),
            &responsePlist);
    }

    if (responsePlist != nullptr)
    {
        odslog("SMS init response: plist parse SUCCESS");

        // SideSign phone responses may contain serverInfo.
        plist_t serverInfo =
            plist_dict_get_item(responsePlist, "serverInfo");

        if (serverInfo != nullptr &&
            plist_get_node_type(serverInfo) == PLIST_DICT)
        {
            plist_t phoneIDNode =
                plist_dict_get_item(serverInfo, "phoneNumber.id");

            if (phoneIDNode != nullptr)
            {
                if (plist_get_node_type(phoneIDNode) == PLIST_STRING)
                {
                    char* value = nullptr;
                    plist_get_string_val(phoneIDNode, &value);

                    if (value != nullptr)
                    {
                        resolvedPhoneID = value;
                        free(value);
                    }
                }
                else if (plist_get_node_type(phoneIDNode) == PLIST_UINT)
                {
                    uint64_t value = 0;
                    plist_get_uint_val(phoneIDNode, &value);
                    resolvedPhoneID = std::to_string(value);
                }
            }

            plist_t modeNode =
                plist_dict_get_item(serverInfo, "mode");

            if (modeNode != nullptr &&
                plist_get_node_type(modeNode) == PLIST_STRING)
            {
                char* value = nullptr;
                plist_get_string_val(modeNode, &value);

                if (value != nullptr)
                {
                    resolvedMode = value;
                    free(value);
                }
            }
        }

        plist_free(responsePlist);
    }
    
    
    else
{
    odslog("SMS init response: not a normal plist; trying XMLUI");

    std::string xml(
        reinterpret_cast<const char*>(responseData.data()),
        responseData.size());

    // Current SideSign parses:
    // <serverInfo ... phoneNumber.id="..." mode="..." ...>
    size_t serverInfoStart = xml.find("<serverInfo");

    if (serverInfoStart != std::string::npos)
    {
        size_t serverInfoEnd = xml.find('>', serverInfoStart);

        if (serverInfoEnd != std::string::npos)
        {
            std::string serverInfoTag =
                xml.substr(
                    serverInfoStart,
                    serverInfoEnd - serverInfoStart + 1);

            odslog("SMS init XMLUI: serverInfo tag found");

            // Extract phoneNumber.id
            const std::string phoneMarker =
                "phoneNumber.id=\"";

            size_t phoneStart =
                serverInfoTag.find(phoneMarker);

            if (phoneStart != std::string::npos)
            {
                phoneStart += phoneMarker.length();

                size_t phoneEnd =
                    serverInfoTag.find('"', phoneStart);

                if (phoneEnd != std::string::npos)
                {
                    resolvedPhoneID =
                        serverInfoTag.substr(
                            phoneStart,
                            phoneEnd - phoneStart);
                }
            }

            // Extract mode
            const std::string modeMarker =
                "mode=\"";

            size_t modeStart =
                serverInfoTag.find(modeMarker);

            if (modeStart != std::string::npos)
            {
                modeStart += modeMarker.length();

                size_t modeEnd =
                    serverInfoTag.find('"', modeStart);

                if (modeEnd != std::string::npos)
                {
                    resolvedMode =
                        serverInfoTag.substr(
                            modeStart,
                            modeEnd - modeStart);
                }
            }
        }
        else
        {
            odslog("SMS init XMLUI: malformed serverInfo tag");
        }
    }
    else
    {
        odslog("SMS init XMLUI: no serverInfo tag found");
    }
}

    odslog("SMS init phone selection resolved (redacted)");


    odslog("SMS challenge requested; waiting for code.");

    return verificationHandler()
        .then([=](std::optional<std::string> verificationCode)
        {
            return std::make_tuple(
                verificationCode,
                resolvedPhoneID,
                resolvedMode);
        });
})

       .then([=](std::tuple<
              std::optional<std::string>,
              std::string,
              std::string> result)
    -> pplx::task<http_response>
{
    auto verificationCode = std::get<0>(result);
    auto resolvedPhoneID = std::get<1>(result);
    auto resolvedMode = std::get<2>(result);

    if (!verificationCode.has_value())
    {
        throw APIError(
            APIErrorCode::RequiresTwoFactorAuthentication);
    }

            // ----------------------------------------------------
            // STEP 2: Submit the SMS code.
            //
            // SideSign:
            // POST /auth/verify/phone/securitycode
            //      ?referrer=/auth/verify/phone/put
            // ----------------------------------------------------

            http_request verifyRequest(methods::POST);

            verifyRequest.set_request_uri(
                U("/auth/verify/phone/securitycode")
                U("?referrer=/auth/verify/phone/put"));

            applyHeaders(verifyRequest);

            plist_t verifyServerInfo = plist_new_dict();

            plist_dict_set_item(
                verifyServerInfo,
                "mode",
                // plist_new_string(mode.c_str()));
                plist_new_string(resolvedMode.c_str()));

            plist_dict_set_item(
                verifyServerInfo,
                "phoneNumber.id",
                //plist_new_string(phoneID.c_str()));
                plist_new_string(resolvedPhoneID.c_str()));

            plist_t verifyBody = plist_new_dict();

            plist_dict_set_item(
                verifyBody,
                "securityCode.code",
                plist_new_string(
                    verificationCode->c_str()));

            plist_dict_set_item(
                verifyBody,
                "serverInfo",
                verifyServerInfo);

            char* verifyXML = nullptr;
            uint32_t verifyLength = 0;

            plist_to_xml(
                verifyBody,
                &verifyXML,
                &verifyLength);

            std::string verifyBodyString;

            if (verifyXML != nullptr)
            {
                verifyBodyString.assign(
                    verifyXML,
                    verifyLength);

                free(verifyXML);
            }

            plist_free(verifyBody);

            verifyRequest.set_body(verifyBodyString);

            ALTLogRequestHeaders(
                "SMS VALIDATE",
                verifyRequest);

            web::http::client::http_client_config verifyConfig;
            verifyConfig.set_validate_certificates(true);
            verifyConfig.set_max_redirects(0);
            verifyConfig.set_timeout(std::chrono::seconds(30));

            auto verifyClient =
                std::make_shared<
                    web::http::client::http_client>(
                        U("https://gsa.apple.com"),
                        verifyConfig);

            return verifyClient->request(verifyRequest);
        })

        .then([=](http_response response)
        {
            odslog("SMS validate HTTP status="
                   << response.status_code());

            bool hasPEToken = false;

            odslog(
                "=== SMS VALIDATE RESPONSE HEADER NAMES ===");

            for (const auto& h : response.headers())
            {
                std::string name =
                    StringFromWideString(h.first);

                odslog(name);

                std::string lower = name;
                std::transform(
                    lower.begin(),
                    lower.end(),
                    lower.begin(),
                    [](unsigned char c)
                    {
                        return std::tolower(c);
                    });

                if (lower == "x-apple-pe-token")
                {
                    hasPEToken = true;
                }
            }

            odslog(
                "=== END SMS VALIDATE RESPONSE HEADER NAMES ===");

            odslog("SMS validate X-Apple-PE-Token present="
                   << hasPEToken);

            if (response.status_code() != 200)
            {
                throw APIError(
                    APIErrorCode::AuthenticationHandshakeFailed);
            }

            return response.extract_vector()
                .then([=](std::vector<unsigned char> data)
                {
                    plist_t plist = nullptr;

                    if (!data.empty())
                    {
                        plist_from_xml(
                            reinterpret_cast<const char*>(
                                data.data()),
                            static_cast<uint32_t>(
                                data.size()),
                            &plist);
                    }

                    int64_t ec = 0;

                    if (plist != nullptr)
                    {
                        plist_t ecNode =
                            plist_dict_get_item(plist, "ec");

                        if (ecNode == nullptr)
                        {
                            plist_t status =
                                plist_dict_get_item(
                                    plist,
                                    "Status");

                            if (status != nullptr)
                            {
                                ecNode =
                                    plist_dict_get_item(
                                        status,
                                        "ec");
                            }
                        }

                        if (ecNode != nullptr)
                        {
                            uint64_t raw = 0;
                            plist_get_uint_val(
                                ecNode,
                                &raw);

                            ec =
                                static_cast<int64_t>(raw);
                        }

                        plist_free(plist);
                    }

                    odslog("SMS validate ec=" << ec);

                    // Current SideSign requires the PE token for
                    // successful phone/SMS verification.
                    if (ec != 0 || !hasPEToken)
                    {
                        odslog(
                            "SMS 2FA validation FAILED:"
                            << " ec=" << ec
                            << " PE-token="
                            << hasPEToken);

                        return false;
                    }

                    odslog(
                        "SMS 2FA validation SUCCESS");

                    return true;
                });
        });
}





pplx::task<std::shared_ptr<Account>> AppleAPI::FetchAccount(std::shared_ptr<AppleAPISession> session)
{
	std::map<std::string, std::string> parameters = {};
	auto task = this->SendRequest("viewDeveloper.action", parameters, session, nullptr)
		.then([=](plist_t plist)->std::shared_ptr<Account>
		{	
			auto account = this->ProcessResponse<shared_ptr<Account>>(plist, [](auto plist)
				{
					auto node = plist_dict_get_item(plist, "developer");
					if (node == nullptr)
					{
						throw APIError(APIErrorCode::InvalidResponse);
					}

					auto account = make_shared<Account>(node);
					return account;

				}, [=](auto resultCode) -> optional<APIError>
				{
					return nullopt;
				});

			return account;
		});

	return task;
}

pplx::task<plist_t> AppleAPI::SendAuthenticationRequest(
    std::map<std::string, plist_t> requestParameters,
    std::shared_ptr<AnisetteData> anisetteData,
    std::shared_ptr<altauth::Context> context)
{
    const bool modern = context && context->modern;
    auto requestDictionary = plist_new_dict();
    for (auto& parameter : requestParameters)
        plist_dict_set_item(requestDictionary, parameter.first.c_str(), parameter.second);
    auto owner = std::shared_ptr<void>(requestDictionary, [](void* p) { plist_free((plist_t)p); });
    const auto operation = ALTStatusString(requestDictionary, "o");
    if (modern) {
        if (operation != "init") ALTRefreshData(context);
        anisetteData = context->current;
        context->consume(anisetteData->oneTimePassword());
        plist_dict_set_item(requestDictionary, "cpd", ALTModernClientDictionary(anisetteData));
    }
    auto root = plist_new_dict();
    auto header = plist_new_dict();
    plist_dict_set_item(header, "Version", plist_new_string("1.0.1"));
    plist_dict_set_item(root, "Header", header);
    plist_dict_set_item(root, "Request", plist_copy(requestDictionary));
    char* xml = nullptr;
    uint32_t length = 0;
    plist_to_xml(root, &xml, &length);
    std::string body(xml, length);
    free(xml);
    plist_free(root);

    http_request request(methods::POST);
    request.set_request_uri(U("/grandslam/GsService2"));
    request.set_body(body);
    request.headers().add(U("Content-Type"), U("text/x-xml-plist"));
    request.headers().add(U("Accept"), U("text/x-xml-plist"));
    request.headers().add(U("User-Agent"), modern ? anisetteData->authenticationUserAgent : ALTAuthKitUserAgent());
    request.headers().add(U("X-MMe-Client-Info"), anisetteData->deviceDescription());
    request.headers().add(U("X-Xcode-Version"), U("27.0 (27A5218g)"));
    request.headers().add(U("X-Apple-App-Info"), U("com.apple.gs.xcode.auth"));
    request.headers().add(U("Connection"), U("close"));
    ALTApplyGrandSlamCookies(request, context);
    http_client_config config;
    config.set_validate_certificates(true);
    config.set_max_redirects(0);
    config.set_timeout(std::chrono::seconds(30));
    auto client = std::make_shared<http_client>(U("https://gsa.apple.com"), config);
    auto task = context && context->transport ? context->transport(request) : client->request(request);
    return task.then([=](http_response response) {
        // Classify HTTP errors before interpreting the body as a property list.
        altauth::httpStatus(response.status_code());
        ALTStoreGrandSlamCookies(response, context);
        return response.extract_vector();
    }).then([=](std::vector<unsigned char> bytes) -> pplx::task<plist_t> {
        (void)owner; // retain request nodes until the optional resync retry is built
        if (bytes.size() > 1024 * 1024) throw APIError(APIErrorCode::InvalidResponse);
        plist_t parsed = nullptr;
        plist_from_xml((const char*)bytes.data(), bytes.size(), &parsed);
        auto parsedOwner = std::shared_ptr<void>(parsed, [](void* p) { if (p) plist_free((plist_t)p); });
        auto dictionary = parsed ? plist_dict_get_item(parsed, "Response") : nullptr;
        auto status = dictionary ? plist_dict_get_item(dictionary, "Status") : nullptr;
        if (!status || plist_get_node_type(status) != PLIST_DICT)
            throw APIError(APIErrorCode::InvalidResponse);
        if (ALTStatusInteger(status, "hsc") == 434) {
            // Resync is valid only for init. Retry once, preserving its A2k/SRP context.
            if (!modern || operation != "init") throw APIError(APIErrorCode::InvalidAnisetteData);
            auto simNode = plist_dict_get_item(status, "X-Apple-I-MD-DATA");
            std::string sim;
            if (simNode && plist_get_node_type(simNode) == PLIST_STRING)
                sim = ALTStatusString(status, "X-Apple-I-MD-DATA");
            else if (simNode && plist_get_node_type(simNode) == PLIST_DATA) {
                char* raw = nullptr; uint64_t size = 0;
                plist_get_data_val(simNode, &raw, &size);
                if (size <= 49152) sim = utility::conversions::to_base64(DataFromBytes(raw, size));
                free(raw);
            }
            context->beginResync(sim);
            ALTUseFreshData(context, context->resync(sim));
            std::map<std::string, plist_t> retry;
            for (const auto& parameter : requestParameters)
                retry[parameter.first] = plist_copy(plist_dict_get_item(requestDictionary, parameter.first.c_str()));
            return this->SendAuthenticationRequest(retry, context->current, context);
        }
        const auto code = ALTStatusInteger(status, "ec");
        if (code == -29004) throw APIError(APIErrorCode::InvalidAnisetteData);
        if (code != 0) throw LocalizedError(code, altauth::appleError(code));
        return pplx::task_from_result(plist_copy(dictionary));
    });
}
