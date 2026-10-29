#include "AnisetteDataManager.h"
#include <sstream>
#include <filesystem>
#include "Error.hpp"
#include "ServerError.hpp"

#include <set>
#include <ctime>
#include <cstdlib>
#include <stdexcept>

#include "AnisetteData.h"
#include "AuthCompatibility.h"
#include "AltServerApp.h"

#define odslog(msg) { std::stringstream ss; ss << msg << std::endl; OutputDebugStringA(ss.str().c_str()); }

AnisetteDataManager* AnisetteDataManager::_instance = nullptr;

AnisetteDataManager* AnisetteDataManager::instance()
{
	if (_instance == 0)
	{
		_instance = new AnisetteDataManager();
	}

	return _instance;
}

AnisetteDataManager::AnisetteDataManager() : loadedDependencies(false)
{
}

AnisetteDataManager::~AnisetteDataManager()
{
}

bool AnisetteDataManager::LoadiCloudDependencies()
{
	return true;
}

bool AnisetteDataManager::LoadDependencies()
{
	return true;
}

#include <cpprest/json.h>

using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features

std::string GetAnisetteURL() {
	const char *server = getenv("ALTSERVER_ANISETTE_SERVER");
	if (server) {
		return server;
	}
	return U("https://armconverter.com/anisette/irGb3Quww8zrhgqnzmrx");
}

std::shared_ptr<AnisetteData> AnisetteDataManager::FetchAnisetteData(std::string sim)
{
	// auto client = web::http::client::http_client(U("https://armconverter.com"));
	// std::string wideURI = ("/anisette/irGb3Quww8zrhgqnzmrx");
	
	// auto encodedURI = web::uri::encode_uri(wideURI);
	// uri_builder builder(encodedURI);

	// http_request request(methods::GET);
	// request.set_request_uri(builder.to_string());

	const bool modern = altauth::enabled();
    const auto url = GetAnisetteURL();
    web::uri endpoint(url);
    if (modern && (endpoint.scheme() != "http" || endpoint.host() != "127.0.0.1" ||
                   !endpoint.user_info().empty() || !endpoint.query().empty() ||
                   !endpoint.fragment().empty() || endpoint.path() != "/"))
        throw std::runtime_error("official-2026 requires an explicit isolated loopback Anisette adapter URL ending in /");
    if (!sim.empty() && !modern)
        throw std::runtime_error("Anisette resync requires official-2026 mode");
    http_client_config config;
    config.set_validate_certificates(true);
    config.set_max_redirects(0);
    config.set_timeout(std::chrono::seconds(30));
    auto client = web::http::client::http_client(url, config);
    http_request request(sim.empty() ? methods::GET : methods::POST);
    if (!sim.empty()) {
        if (sim.size() > 65536) throw std::runtime_error("Oversized Anisette resync data");
        request.set_request_uri("resync");
        json::value body;
        body["sim"] = json::value::string(sim);
        request.set_body(body);
    }
	
	std::map<utility::string_t, utility::string_t> headers = {
		{"User-Agent", "Xcode"},
	};

	for (auto& pair : headers)
	{
		if (request.headers().has(pair.first))
		{
			request.headers().remove(pair.first);
		}

		request.headers().add(pair.first, pair.second);
	}

	std::shared_ptr<AnisetteData> anisetteData = NULL;

	auto task = client.request(request)
		.then([=](http_response response)
			{
				return response.content_ready();
			})
		.then([=](http_response response)
			{
				odslog("Received response status code: " << response.status_code());
				if (response.status_code() != status_codes::OK)
				{
					throw std::runtime_error("Anisette server returned HTTP " + std::to_string(response.status_code()));
				}
				return response.extract_json();
			})
		.then([&anisetteData, modern](pplx::task<json::value> previousTask)
			{
				odslog("parse anisette data ret");
				json::value jsonVal = previousTask.get();
				odslog("Anisette data received (values redacted)");
				std::vector<std::string> keys = {
					"X-Apple-I-MD-M",
					"X-Apple-I-MD",
					"X-Apple-I-MD-LU",
					"X-Apple-I-MD-RINFO",
					"X-Mme-Device-Id",
					"X-Apple-I-SRL-NO",
					"X-MMe-Client-Info",
					"X-Apple-I-Client-Time",
					"X-Apple-Locale",
					"X-Apple-I-TimeZone"
				};
				for (auto &key : keys) {
					if (!jsonVal.has_string_field(key) || jsonVal.at(key).as_string().empty())
					{
						throw std::runtime_error("Anisette response missing string field: " + key);
					}
				}

				struct tm tm = { 0 };
				const auto timestamp = jsonVal.at("X-Apple-I-Client-Time").as_string();
				const auto end = strptime(timestamp.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm);
				if (!end || *end != '\0')
				{
					throw std::runtime_error("Anisette response has an invalid UTC timestamp");
				}
				unsigned long ts = timegm(&tm);
				struct timeval tv = { 0 };
				tv.tv_sec = ts;
				tv.tv_usec = 0;

				odslog("Building anisetteData obj...");
				anisetteData = std::make_shared<AnisetteData>(
					jsonVal.at("X-Apple-I-MD-M").as_string(),
					jsonVal.at("X-Apple-I-MD").as_string(),
					jsonVal.at("X-Apple-I-MD-LU").as_string(),
					std::atoi(jsonVal.at("X-Apple-I-MD-RINFO").as_string().c_str()),
					jsonVal.at("X-Mme-Device-Id").as_string(),
					jsonVal.at("X-Apple-I-SRL-NO").as_string(),
					jsonVal.at("X-MMe-Client-Info").as_string(),
					tv,
					jsonVal.at("X-Apple-Locale").as_string(),
					jsonVal.at("X-Apple-I-TimeZone").as_string());
				
				if (modern) {
                    for (const auto& key : {"authenticationUserAgent", "provisionedClientInfo", "provisionedUserAgent"})
                        if (!jsonVal.has_string_field(key))
                            throw std::runtime_error("Anisette adapter lacks provisioning identity metadata");
                    for (const auto& key : keys) altauth::headerValue(jsonVal.at(key).as_string());
                    const auto agent = jsonVal.at("authenticationUserAgent").as_string();
                    altauth::identity(anisetteData->deviceDescription(), agent,
                        jsonVal.at("provisionedClientInfo").as_string(),
                        jsonVal.at("provisionedUserAgent").as_string());
                    if (std::abs(std::difftime(std::time(nullptr), tv.tv_sec)) > 120)
                        throw std::runtime_error("Anisette response is stale");
                    anisetteData->authenticationUserAgent = agent;
                }
			});
	
	task.get();

	if (!anisetteData)
	{
		throw std::runtime_error("Anisette response did not produce authentication data");
	}
	odslog("Anisette data ready (values redacted)");

	return anisetteData;
}

bool AnisetteDataManager::ReprovisionDevice(std::function<void(void)> provisionCallback)
{
#if !SPOOF_MAC
	provisionCallback();
	return true;
#else
	std::string adiDirectoryPath = "C:\\ProgramData\\Apple Computer\\iTunes\\adi";

	/* Start Provisioning */

	// Move iCloud's ADI files (so we don't mess with them).
	for (const auto& entry : fs::directory_iterator(adiDirectoryPath))
	{
		if (entry.path().extension() == ".pb")
		{
			fs::path backupPath = entry.path();
			backupPath += ".icloud";

			fs::rename(entry.path(), backupPath);
		}
	}

	// Copy existing AltServer .pb files into original location to reuse the MID.
	for (const auto& entry : fs::directory_iterator(adiDirectoryPath))
	{
		if (entry.path().extension() == ".altserver")
		{
			fs::path path = entry.path();
			path.replace_extension();

			fs::rename(entry.path(), path);
		}
	}

	auto cleanUp = [adiDirectoryPath]() {
		/* Finish Provisioning */

		// Backup AltServer ADI files.
		for (const auto& entry : fs::directory_iterator(adiDirectoryPath))
		{
			// Backup AltStore file
			if (entry.path().extension() == ".pb")
			{
				fs::path backupPath = entry.path();
				backupPath += ".altserver";

				fs::rename(entry.path(), backupPath);
			}
		}

		// Copy iCloud ADI files back to original location.
		for (const auto& entry : fs::directory_iterator(adiDirectoryPath))
		{
			if (entry.path().extension() == ".icloud")
			{
				// Move backup file to original location
				fs::path path = entry.path();
				path.replace_extension();

				fs::rename(entry.path(), path);

				odslog("Copying iCloud file from: " << entry.path().string() << " to: " << path.string());
			}
		}
	};

	// Calling CopyAnisetteData implicitly generates new anisette data,
	// using the new client info string we injected.
	ObjcObject* error = NULL;
	ObjcObject* anisetteDictionary = (ObjcObject*)CopyAnisetteData(NULL, 0x1, &error);

	try
	{
		if (anisetteDictionary == NULL)
		{
			odslog("Reprovision Error:" << ((ObjcObject*)error)->description());

			ObjcObject* localizedDescription = (ObjcObject*)((id(*)(id, SEL))objc_msgSend)(error, sel_registerName("localizedDescription"));
			if (localizedDescription)
			{
				int errorCode = ((int(*)(id, SEL))objc_msgSend)(error, sel_registerName("code"));
				throw LocalizedError(errorCode, localizedDescription->description());
			}
			else
			{
				throw ServerError(ServerErrorCode::InvalidAnisetteData);
			}
		}

		odslog("Reprovisioned Anisette:" << anisetteDictionary->description());

		AltServerApp::instance()->setReprovisionedDevice(true);

		// Call callback while machine is provisioned for AltServer.
		provisionCallback();
	}
	catch (std::exception &exception)
	{
		cleanUp();

		throw;
	}

	cleanUp();

	return true;
#endif
}

bool AnisetteDataManager::ResetProvisioning()
{
	std::string adiDirectoryPath = "C:\\ProgramData\\Apple Computer\\iTunes\\adi";

	// Remove existing AltServer .pb files so we can create new ones next time we provision this device.
	for (const auto& entry : fs::directory_iterator(adiDirectoryPath))
	{
		if (entry.path().extension() == ".altserver")
		{
			fs::remove(entry.path());
		}
	}

	return true;
}
