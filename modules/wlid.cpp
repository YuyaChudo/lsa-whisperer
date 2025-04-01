// Copyright (C) 2025 Evan McBroom
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "sspi.hpp"
#include <algorithm>
#include <clipp.h>
#include <codecvt>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <nlohmann/json.hpp>
#include <wininet.h>

auto ServiceError = "Please ensure that the \"Microsoft Account Sign-in Assistant\" service (e.g., wlidsvc) is installed and running.";

// clang-format off
/// <summary>
/// Start the WLID service by triggering one of the NetworkEndpoint
/// service triggers that are set for the LiveIdSvc RPC interface.
/// </summary>
void TriggerWlidService() {
    RpcTryExcept
        if (RpcBindingFromStringBindingW(RPC_WSTR(L"ncalrpc:"), &LiveIdSvcRpcImplicitHandle) == RPC_S_OK) {
            (void)RpcEpResolveBinding(LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec);
            (void)RpcBindingFree(&LiveIdSvcRpcImplicitHandle);
        }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    RpcEndExcept
}
// clang-format on

std::string UnprotectTbCacheValue(std::string input) {
    std::string output{ input };
    DWORD cbBinary{ 0 };
    if (CryptStringToBinaryA(input.data(), input.length(), CRYPT_STRING_BASE64, nullptr, &cbBinary, nullptr, nullptr) && cbBinary) {
        std::vector<char> buffer(cbBinary, '\0');
        (void)CryptStringToBinaryA(input.data(), input.length(), CRYPT_STRING_BASE64, reinterpret_cast<PBYTE>(buffer.data()), &cbBinary, nullptr, nullptr);
        DATA_BLOB inputBlob{ DWORD(buffer.size()), reinterpret_cast<PBYTE>(buffer.data()) };
        DATA_BLOB outputBlob;
        if (CryptUnprotectData(&inputBlob, nullptr, nullptr, nullptr, nullptr, 0, &outputBlob)) {
            if (std::all_of(buffer.cbegin(), buffer.cend(), [](char c) {
                    return __isascii(c);
                })) {
                output = std::string(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
            } else {
                if (CryptBinaryToStringA(outputBlob.pbData, outputBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cbBinary)) {
                    buffer.resize(cbBinary, '\0');
                    (void)CryptBinaryToStringA(outputBlob.pbData, outputBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer.data(), &cbBinary);
                    output = std::string(buffer.begin(), buffer.end());
                }
            }
            LocalFree(outputBlob.pbData);
        }
    }
    return output;
}

extern "C" {
int config(int, char**) {
    bool succeeded{ false };
    Rpc::Client rpcClient;
    if (!rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec)) {
        TriggerWlidService();
        rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec);
    }
    if (rpcClient.IsBound()) {
        LPWSTR deviceName{ nullptr };
        if (WLIDGetLocalDeviceName(&deviceName) == RPC_S_OK && deviceName) {
            BOOL isKiosk;
            auto prompt{ (WLIDIsKioskMode(&isKiosk) == RPC_S_OK && isKiosk) ? "Device: " : "Device (is kiosk): " };
            std::wcout << prompt << deviceName << std::endl;
            MIDL_user_free(deviceName);
        }
        LPWSTR serviceEnvironment{ nullptr };
        if (WLIDGetSvcEnvironment(&serviceEnvironment) == RPC_S_OK && serviceEnvironment) {
            std::wcout << L"Service environment: " << serviceEnvironment << std::endl;
            MIDL_user_free(serviceEnvironment);
        }
        LPWSTR inlineUrlContextData{ nullptr };
        if (WLIDGetSvcEnvironment(&serviceEnvironment) == RPC_S_OK && inlineUrlContextData) {
            std::wcout << L"Inline url context data: " << inlineUrlContextData << std::endl;
            MIDL_user_free(inlineUrlContextData);
        }
        std::wcout << std::endl
                   << L"Config strings:" << std::endl;
        std::vector<LPWSTR> configTypes{
            L"AccountDomain",
            L"AccountPolicy",
            L"ConnectAccountPolicy",
            L"CookieP3PHeader",
            L"DeviceDNSSuffix",
            L"InterruptResolutionDomain",
            L"PasswordReset",
            L"StrongAuthPolicy"
        };
        size_t promptWidth{ 0 };
        for (auto configType : configTypes) {
            auto configTypeLength{ std::wcslen(configType) };
            promptWidth = (configTypeLength > promptWidth) ? configTypeLength : promptWidth;
        }
        for (auto configType : configTypes) {
            auto configTypeArg{ std::wstring(L"cfg:") + configType };
            LPWSTR configValue{ nullptr };
            if (WLIDGetConfigString(configTypeArg.data(), &configValue) == RPC_S_OK && configValue) {
                std::wstring prompt{ configType };
                prompt.insert(prompt.size(), promptWidth - prompt.size(), L' ');
                prompt.insert(0, 4, L' ');
                prompt.append(L": ");
                std::wcout << prompt << configValue << std::endl;
                MIDL_user_free(configValue);
            }
        }
        std::wcout << std::endl
                   << L"Config DWORD values:" << std::endl;
        DWORD value{ 0 };
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_CONNECT_TIMEOUT, &value) == RPC_S_OK) {
            std::wcout << L"    CONNECT_TIMEOUT: " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_ENVIRONMENT, &value) == RPC_S_OK) {
            std::wcout << L"    ENVIRONMENT    : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_LCID, &value) == RPC_S_OK) {
            std::wcout << L"    LCID           : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_MSC_TIMEOUT, &value) == RPC_S_OK) {
            std::wcout << L"    MSC_TIMEOUT    : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_PROXY, &value) == RPC_S_OK) {
            std::wcout << L"    PROXY          : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_PROXY_PASSWORD, &value) == RPC_S_OK) {
            std::wcout << L"    PROXY_PASSWORD : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_PROXY_USERNAME, &value) == RPC_S_OK) {
            std::wcout << L"    PROXY_USERNAME : " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_RECEIVE_TIMEOUT, &value) == RPC_S_OK) {
            std::wcout << L"    RECEIVE_TIMEOUT: " << value << std::endl;
        }
        if (WLIDGetConfigDWORDValue(IDCRL::IDCRL_OPTION_SEND_TIMEOUT, &value) == RPC_S_OK) {
            std::wcout << L"    SEND_TIMEOUT   : " << value << std::endl;
        }
        succeeded = true;
    } else {
        std::cout << ServiceError << std::endl;
    }
    return (succeeded) ? 0 : -1;
}

int get_token(int argc, char** argv) {
    bool showHelp{ false };
    std::string user{ "" };
    std::string target{ "scope=service::substrate.office.com::MBI_SSL_SHORT&telemetry=MATS&uaid=ABCDEF12-3456-7890-AAAA-DEADB33F0000&clientid=0000000000000000" };
    std::string policy{ "TOKEN_BROKER" };
    std::string method{ "Silent" };
    bool xmlOutput{ false };
    // clang-format off
    auto args = (
        clipp::required("--user").doc("User to request the token for.") & clipp::value("email", user),
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
        clipp::option("--target").doc("Specify an alternative service target.") & clipp::value("target", target),
        clipp::option("--policy").doc("Specify an alternative service policy.") & clipp::value("policy", policy),
        clipp::option("--method").doc("Specify an alternative method to acquire the token.") & clipp::value("method", method),
        clipp::option("--xml").set(xmlOutput).doc("Encode output as xml.")
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (!user.size() || showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return (!user.size()) ? -1 : 0;
    }
    bool succeeded{ false };
    Rpc::Client rpcClient;
    if (!rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec)) {
        TriggerWlidService();
        rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec);
    }
    if (rpcClient.IsBound()) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        auto userArg{ converter.from_bytes(user) };
        HANDLE context{ 0 };
        if (WLIDCreateContext(userArg.data(), L"", IDCRL::IDENTITY_CONTEXT_MODERN | IDCRL::IDENTITY_CONTEXT_SET_APP_GUID, &context) == RPC_S_OK && context) {
            auto targetArg{ converter.from_bytes(target) };
            auto policyArg{ converter.from_bytes(policy) };
            auto methodArg{ converter.from_bytes(method) };
            WLIDRequestParams request = { 0 };
            // wns.windows.com
            request.wszServiceTarget = L"scope=service::substrate.office.com::MBI_SSL_SHORT&telemetry=MATS&uaid=ABCDEF12-3456-7890-AAAA-DEADB33F0000&clientid=0000000000000000";
            ; // L"scope=service::http://Passport.NET/purpose::PURPOSE_GETKEYDATA_ROAMING&uaid=2611726E-88C7-4C28-A611-954B18CED1CB&clientid=%7B12E984BD-5803-4D78-9EFB-BED7B9212C26%7D&ssoappgroup=windows";
              //
            // L"wns.windows.com";
            request.wszServicePolicy = L"TOKEN_BROKER"; // MBI_SSL
            request.policyEncoding = (xmlOutput) ? PolicyEncoding::XmlEncoding : PolicyEncoding::StringEncoding;
            long authState{ S_OK };
            long authRequired{ S_OK };
            long requestStatus{ S_OK };
            long responseCount{ 0 };
            PWLIDResponseParams responseParamsArray{ nullptr };
            auto test1{ sizeof(WLIDRequestParams) };
            auto test2{ sizeof(WLIDResponseParams) };
            long unknown{ 0 };
            if (WLIDAcquireTokensWithNGC(
                    context,
                    IDCRL::LOGONIDENTITY_IGNORE_CACHED_TOKENS,
                    1,
                    &request,
                    L"",
                    0,
                    L"Silent",
                    &authState,
                    &authRequired,
                    &requestStatus,
                    &responseCount,
                    &responseParamsArray,
                    &unknown) == RPC_S_OK) {
                for (size_t index{ 0 }; index < responseCount; index++) {
                    std::wcout << L"Token " << index << L":" << std::endl;
                    auto& responseParams{ responseParamsArray[index] };
                    // std::wcout << L"    hrAuthRequired: " << handleData.wszUserName << std::endl;
                }
                succeeded = true;
            } else {
                std::cout << "Could not acquire tokens for the specified user, service target, and service policy." << std::endl;
            }
            (void)WLIDDeleteContext(1, &context);
        }
    } else {
        std::cout << ServiceError << std::endl;
    }
    return (succeeded) ? 0 : -1;
}

int handles(int, char**) {
    bool succeeded{ false };
    Rpc::Client rpcClient;
    if (!rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec)) {
        TriggerWlidService();
        rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec);
    }
    if (rpcClient.IsBound()) {
        DWORD handleDataCount;
        PWLID_OPEN_HANDLE_DATA handleDataArray{ nullptr };
        if (WLIDGetOpenHandlesData(&handleDataCount, &handleDataArray) == RPC_S_OK && handleDataArray) {
            std::vector<std::wstring> userNames;
            for (size_t index = 0; index < handleDataCount; index++) {
                auto& handleData{ handleDataArray[index] };
                std::wcout << L"Handle " << index << L":" << std::endl;
                std::wcout << L"    User name    : " << handleData.wszUserName << std::endl;
                std::wcout << L"    Logon id     : " << std::setfill(L'0') << std::setw(8) << handleData.LUID_HighPart << L"-" << std::setw(8) << handleData.LUID_LowPart << std::endl;
                std::wcout << L"    Session      : " << handleData.dwSession << std::endl;
                std::wcout << L"    Process id   : " << handleData.dwProcessID << std::endl;
                std::wcout << L"    Is active    : " << ((handleData.fIsActive) ? L"yes" : L"no") << std::endl;
                if (handleData.wszUserName) {
                    if (std::find(userNames.begin(), userNames.end(), handleData.wszUserName) == userNames.end()) {
                        userNames.emplace_back(handleData.wszUserName);
                    }
                    MIDL_user_free(handleData.wszUserName);
                }
            }
            MIDL_user_free(handleDataArray);
            if (userNames.size()) {
                std::sort(userNames.begin(), userNames.end(), [](const std::wstring& a, const std::wstring& b) {
                    return a.compare(b);
                });
                std::wcout << std::endl
                           << L"User properties:" << std::endl;
                for (auto& userName : userNames) {
                    DWORD propertyCount;
                    PWLIDIdentityProperty pProps{ nullptr };
                    if (WLIDGetUserPropertiesFromSystemStore(userName.data(), &propertyCount, &pProps) == RPC_S_OK && pProps) {
                        std::wcout << L"    " << userName << ":" << std::endl;
                        size_t promptWidth{ 0 };
                        for (size_t propIndex{ 0 }; propIndex < propertyCount; propIndex++) {
                            auto propertyLength{ std::wcslen(pProps[propIndex].pszProperty) };
                            promptWidth = (propertyLength > promptWidth) ? propertyLength : promptWidth;
                        }
                        for (size_t propIndex{ 0 }; propIndex < propertyCount; propIndex++) {
                            std::wstring prompt{ pProps[propIndex].pszProperty };
                            prompt.insert(prompt.size(), promptWidth - prompt.size(), L' ');
                            prompt.insert(0, 8, L' ');
                            prompt.append(L": ");
                            std::wcout << prompt << pProps[propIndex].pszValue << std::endl;
                            MIDL_user_free(pProps[propIndex].pszProperty);
                            MIDL_user_free(pProps[propIndex].pszValue);
                        }
                        MIDL_user_free(pProps);
                    }
                }
                bool userKeysHeaderShown{ false };
                for (auto& userName : userNames) {
                    HANDLE context{ 0 };
                    if (WLIDCreateContext(userName.data(), L"", 0, &context) == RPC_S_OK && context) {
                        LPWSTR keyVersion;
                        LPWSTR keyMaterial;
                        LONGLONG keyVersionTimeStamp;
                        if (WLIDGetKeyLatest(context, 0, L"", &keyVersion, &keyMaterial, &keyVersionTimeStamp) == RPC_S_OK && (keyVersion || keyMaterial)) {
                            if (!userKeysHeaderShown) {
                                std::wcout << std::endl
                                           << L"User keys:" << std::endl;
                                userKeysHeaderShown = true;
                            }
                            std::wcout << L"    " << userName << ":" << std::endl;
                            if (keyVersion) {
                                std::wcout << "        Version  : " << keyVersion << std::endl;
                                MIDL_user_free(keyVersion);
                            }
                            if (keyMaterial) {
                                std::wcout << "        Material : " << keyMaterial << std::endl;
                                MIDL_user_free(keyMaterial);
                            }
                            std::wcout << "        Timestamp: " << keyVersionTimeStamp << std::endl;
                        }
                        (void)WLIDDeleteContext(1, &context);
                    }
                }
            }
            succeeded = true;
        } else {
            std::cout << "Could not gather handle data." << std::endl;
        }
    } else {
        std::cout << ServiceError << std::endl;
    }
    return (succeeded) ? 0 : -1;
}

int nonce(int, char**) {
    bool succeeded{ false };
    auto internet{ InternetOpenW(L"", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0) };
    if (internet) {
        auto connection{ InternetConnectW(internet, L"login.microsoftonline.com", 443, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0) };
        if (connection) {
            DWORD flags{ INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE };
            auto request{ HttpOpenRequestW(connection, L"POST", L"/common/oauth2/token", nullptr, nullptr, nullptr, flags, 0) };
            if (request) {
                std::string body{ "grant_type=srv_challenge" };
                if (HttpSendRequestW(request, nullptr, 0, body.data(), body.length())) {
                    DWORD status{ 0 };
                    DWORD bufferLength{ sizeof(status) };
                    if (HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &bufferLength, 0)) {
                        // A post response may not contain a content length header
                        // So do not refer to it when reading all bytes from the body of the POST response
                        size_t chunkSize{ 1024 };
                        std::vector<std::vector<byte>> chunks;
                        DWORD bytesRead{ 0 };
                        size_t totalRead{ 0 };
                        do {
                            // On additional iterations of the loop, resize the previously recieved chunk is necessary
                            if (chunks.size()) {
                                chunks.back().resize(bytesRead);
                            }
                            chunks.emplace_back(std::vector<byte>(chunkSize, 0));
                            totalRead += bytesRead;
                        } while (InternetReadFile(request, chunks.back().data(), chunkSize, &bytesRead) && bytesRead);
                        if (totalRead) {
                            // Using chunk size intervals when coalescing data to make the process easier to write
                            std::vector<byte> buffer(chunks.size() * chunkSize, 0);
                            size_t bytesCopied{ 0 };
                            for (size_t index{ 0 }; index < chunks.size(); index++) {
                                auto& chunk{ chunks[index] };
                                std::memcpy(buffer.data() + bytesCopied, chunk.data(), chunk.size());
                                bytesCopied += chunk.size();
                            }
                            std::wstring response{ buffer.data(), buffer.data() + buffer.size() };
                            std::wcout << response << std::endl;
                            succeeded = true;
                        }
                    }
                }
                InternetCloseHandle(request);
            }
            InternetCloseHandle(connection);
        }
        InternetCloseHandle(internet);
    }
    return (succeeded) ? 0 : -1;
}

int tbcache(int, char**) {
    bool succeeded{ true };
    auto cacheDir{ std::filesystem::path(std::getenv("LOCALAPPDATA")) };
    cacheDir /= "Microsoft\\TokenBroker\\Cache";
    if (std::filesystem::exists(cacheDir) && std::filesystem::is_directory(cacheDir)) {
        for (auto const& entry : std::filesystem::directory_iterator{ cacheDir, std::filesystem::directory_options::skip_permission_denied }) {
            std::wifstream ifs(entry.path(), std::ios::binary);
            ifs.imbue(std::locale(ifs.getloc(), new std::codecvt_utf16<wchar_t, 0x10ffff, std::little_endian>));
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto utf8Content{ converter.to_bytes(std::wstring(std::istreambuf_iterator<wchar_t>{ ifs }, {})) };
            nlohmann::json data = nlohmann::json::parse(utf8Content);
            try {
                auto object{ data["TBDataStoreObject"] };
                auto header{ object["Header"] };
                std::cout << entry.path().filename() << " - " << header["ObjectType"].get<std::string>() << "(version " << header["SchemaVersionMajor"].get<int>()
                          << "." << header["SchemaVersionMinor"].get<int>() << ")" << std::endl;
                auto props{ object["ObjectData"]["SystemDefinedProperties"] };
                size_t promptWidth{ 0 };
                for (auto prop = props.begin(); prop != props.end(); prop++) {
                    auto propertyLength{ prop.key().length() };
                    promptWidth = (propertyLength > promptWidth) ? propertyLength : promptWidth;
                }
                for (auto prop = props.begin(); prop != props.end(); prop++) {
                    std::string prompt{ prop.key() };
                    prompt.insert(prompt.size(), promptWidth - prompt.size(), L' ');
                    std::cout << "- " << prompt << ": ";
                    auto value{ prop.value() };
                    auto type{ value["Type"] };
                    auto isProtected{ value["IsProtected"].get<bool>() };
                    if (value["Value"].is_array()) {
                        std::cout << std::endl;
                        for (auto& item : value["Value"]) {
                            auto valueData{ item.get<std::string>() };
                            std::cout << "    - " << ((isProtected) ? (UnprotectTbCacheValue(valueData)) : valueData) << std::endl;
                        }
                    } else {
                        auto valueData{ value["Value"].get<std::string>() };
                        std::cout << ((isProtected) ? (UnprotectTbCacheValue(valueData)) : valueData) << std::endl;
                    }
                }
            } catch (...) {
                std::cout << "Cache file " << entry.path().filename() << " is in an unexpected format." << std::endl;
                succeeded = false;
            }
        }
    } else {
        std::cout << "The token broker cache directory does not exist." << std::endl;
        succeeded = false;
    }
    return (succeeded) ? 0 : -1;
}

int tokens(int, char**) {
    bool succeeded{ false };
    Rpc::Client rpcClient;
    if (!rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec)) {
        TriggerWlidService();
        rpcClient.Bind(&LiveIdSvcRpcImplicitHandle, LiveIdSvc_v1_0_c_ifspec);
    }
    if (rpcClient.IsBound()) {
        LPWSTR deviceToken{ nullptr };
        if (WLIDGetDeviceShortLivedToken(&deviceToken) == RPC_S_OK && deviceToken) {
            std::wcout << L"Device token (short lived): " << std::endl
                       << deviceToken << std::endl;
            MIDL_user_free(deviceToken);
        }
        LPWSTR deviceDaToken{ nullptr };
        if (WLIDGetDeviceDAToken(&deviceDaToken) == RPC_S_OK && deviceDaToken) {
            if (deviceToken) {
                std::wcout << std::endl;
            }
            std::wcout << L"Device token (DA): " << std::endl
                       << deviceDaToken << std::endl;
            MIDL_user_free(deviceDaToken);
        }
        PWLIDSignedTokens signedTokens{ nullptr };
        if (WLIDGetSignedTokens(&signedTokens) == RPC_S_OK && signedTokens) {
            std::wcout << std::endl
                       << L"DA signed tokens:" << std::endl;
            if (signedTokens->pUserDASigned) {
                std::wcout << L"    User token: " << std::endl
                           << signedTokens->pUserDASigned << std::endl;
                MIDL_user_free(signedTokens->pUserDASigned);
            }
            if (signedTokens->pDeviceDASigned) {
                if (signedTokens->pUserDASigned) {
                    std::wcout << std::endl;
                }
                std::wcout << L"    Device token: " << std::endl
                           << signedTokens->pDeviceDASigned << std::endl;
                MIDL_user_free(signedTokens->pDeviceDASigned);
            }
            MIDL_user_free(signedTokens);
        }
        DWORD handleDataCount;
        PWLID_OPEN_HANDLE_DATA handleDataArray{ nullptr };
        if (WLIDGetOpenHandlesData(&handleDataCount, &handleDataArray) == RPC_S_OK && handleDataArray) {
            std::vector<std::wstring> userNames;
            for (size_t index = 0; index < handleDataCount; index++) {
                auto userName{ handleDataArray[index].wszUserName };
                if (userName) {
                    if (std::find(userNames.begin(), userNames.end(), userName) == userNames.end()) {
                        userNames.emplace_back(userName);
                    }
                    MIDL_user_free(userName);
                }
            }
            MIDL_user_free(handleDataArray);
            if (userNames.size()) {
                std::sort(userNames.begin(), userNames.end(), [](const std::wstring& a, const std::wstring& b) {
                    return a.compare(b);
                });
                bool popTokensHeaderShown{ false };
                for (auto& userName : userNames) {
                    GUID activityId = { 0 };
                    DWORD tokenCount;
                    PProofOfPossessionCookieinfo pTokens{ nullptr };
                    if (WLIDGetProofOfPossessionTokens(userName.data(), &activityId, &tokenCount, &pTokens) == RPC_S_OK && pTokens) {
                        if (!popTokensHeaderShown) {
                            std::wcout << std::endl
                                       << L"User proof of possession (PoP) tokens:" << std::endl;
                            popTokensHeaderShown = true;
                        }
                        for (size_t tokenIndex{ 0 }; tokenIndex < tokenCount; tokenIndex++) {
                            if (tokenIndex > 0) {
                                std::cout << std::endl;
                            }
                            std::wcout << L"    " << userName << "(token " << tokenIndex << "):" << std::endl;
                            auto& token{ pTokens[tokenIndex] };
                            std::wcout << L"        Name     : " << token.name << std::endl;
                            std::wcout << L"        Data     : " << token.data << std::endl;
                            std::wcout << L"        Flags    : " << token.flags << std::endl;
                            std::wcout << L"        P3PHeader: " << token.p3pHeader << std::endl;
                            if (token.name) {
                                MIDL_user_free(token.name);
                            }
                            if (token.data) {
                                MIDL_user_free(token.data);
                            }
                            if (token.p3pHeader) {
                                MIDL_user_free(token.p3pHeader);
                            }
                        }
                        MIDL_user_free(pTokens);
                    }
                }
            }
        }
        succeeded = true;
    } else {
        std::cout << ServiceError << std::endl;
    }
    return (succeeded) ? 0 : -1;
}
}