// Copyright (C) 2025 Evan McBroom
#include "commands.hpp"
#include "sspi.hpp"
#include <codecvt>
#include <locale>
#include <magic_enum.hpp>
#include <spdlog/spdlog.h>
#include <string>

namespace AllPackages {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "all" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.allow_unrecognised_options();
        // clang-format off
        unparsedOptions.add_options("Function arguments")
            ("cleanup-credentials", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"))
            ("dc-flags", "Dc flags to use with PinKdc", cxxopts::value<long long>())
            ("dc-name", "The KDC name to use with PinKdc", cxxopts::value<std::string>()->default_value(""))
            ("dluid", "Destination logon session", cxxopts::value<long long>())
            ("domain-name", "", cxxopts::value<std::string>())
            ("optimistic-logon", "Optimistic logon flag", cxxopts::value<bool>()->default_value("false"))
            ("sluid", "Source logon session", cxxopts::value<long long>())
            ("to-sso-session", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"));
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        // Flag for ticket retrieval commands
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::PinDc: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domainName{ converter.from_bytes(options["domain-name"].as<std::string>()) };
            auto dcName{ converter.from_bytes(options["dc-name"].as<std::string>()) };
            auto dcFlags{ options.count("dc-flags") ? options["dc-flags"].as<long long>() : 0 };
            return proxy.PinDc(domainName, dcName, dcFlags);
        }
        case PROTOCOL_MESSAGE_TYPE::TransferCred: {
            LUID sourceLuid = { 0 };
            LUID destinationLuid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
            ULONG flags{ 0 };
            flags += (options.count("cleanup-credentials")) ? static_cast<ULONG>(TransferCredFlag::CleanupCredentials) : 0;
            flags += (options.count("optimistic-logon")) ? static_cast<ULONG>(TransferCredFlag::OptimisticLogon) : 0;
            flags += (options.count("to-sso-session")) ? static_cast<ULONG>(TransferCredFlag::ToSsoSession) : 0;
            return proxy.TransferCred(&sourceLuid, &destinationLuid, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::UnpinAllDcs: {
            return proxy.UnpinAllDcs();
        }
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Cloudap {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "cloudap" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("luid", "Logon session", cxxopts::value<long long>());
        unparsedOptions.add_options("Function arguments")
            ("arso-data", "Data to store in LSA secret when ARSO password is created", cxxopts::value<std::string>())
            ("authority", "Authority type (1 or 2)", cxxopts::value<unsigned int>())
            ("auth-req", "RDP authentication request (MS-RDPBCGR 4.11.2)", cxxopts::value<std::string>())
            ("dluid", "Destination logon session", cxxopts::value<unsigned int>())
            ("disable", "Disable an option", cxxopts::value<std::string>())
            ("enable", "Enable an option", cxxopts::value<std::string>())
            ("flags", "Cloudap test flags", cxxopts::value<unsigned int>())
            ("nonce", "Cookie nonce", cxxopts::value<std::string>())
            ("server", "Who to request a SSO cookie from", cxxopts::value<std::string>()->default_value("login.microsoftonline.com"))
            ("sluid", "Source logon session", cxxopts::value<unsigned int>())
            ("user", "Microsoft user account (e.g., an email)", cxxopts::value<std::string>());
        // clang-format on
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        if (magic_enum::enum_contains<Aad::CALL>(args[1])) {
            auto proxy{ Aad::Api(lsa) };
            switch (magic_enum::enum_cast<Aad::CALL>(args[1]).value()) {
            case Aad::CALL::CheckDeviceKeysHealth:
                return proxy.CheckDeviceKeysHealth();
            case Aad::CALL::CreateBindingKey:
                return proxy.CreateBindingKey();
            case Aad::CALL::CreateDeviceSSOCookie:
                return proxy.CreateDeviceSSOCookie(options["server"].as<std::string>(), options["nonce"].as<std::string>());
            case Aad::CALL::CreateEnterpriseSSOCookie:
                return proxy.CreateEnterpriseSSOCookie(options["server"].as<std::string>(), options["nonce"].as<std::string>());
            case Aad::CALL::CreateNonce:
                return proxy.CreateNonce();
            case Aad::CALL::CreateSSOCookie:
                return proxy.CreateSSOCookie(options["server"].as<std::string>(), options["nonce"].as<std::string>());
            case Aad::CALL::DeviceAuth:
                return proxy.DeviceAuth();
            case Aad::CALL::DeviceValidityCheck:
                return proxy.DeviceValidityCheck();
            case Aad::CALL::GenerateBindingClaims:
                break;
            case Aad::CALL::GetPrtAuthority:
                return proxy.GetPrtAuthority(static_cast<Aad::AUTHORITY_TYPE>(options["authority"].as<unsigned int>()));
            case Aad::CALL::RefreshP2PCACert:
                return proxy.RefreshP2PCACert();
            case Aad::CALL::RefreshP2PCerts:
                return proxy.RefreshP2PCerts();
            case Aad::CALL::SignPayload:
                return proxy.SignPayload();
            case Aad::CALL::ValidateRdpAssertionRequest:
                return proxy.ValidateRdpAssertionRequest(options["auth-req"].as<std::string>());
            default:
                break;
            }
            return false;
        } else if (magic_enum::enum_contains<Msa::CALL>(args[1])) {
            auto proxy{ Msa::Api(lsa) };
            switch (magic_enum::enum_cast<Msa::CALL>(args[1]).value()) {
            case Msa::CALL::GetSignedProofOfPossessionTokens: {
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                auto user{ converter.from_bytes(options["user"].as<std::string>()) };
                return proxy.GetSignedProofOfPossessionTokens(user);
            }
            default:
                break;
            }
            return false;
        } else {
            auto proxy{ Api(lsa) };
            switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
            case PROTOCOL_MESSAGE_TYPE::CallPluginGeneric:
                return false;
            case PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon: {
                LUID luid = { 0 };
                if (options["luid"].count()) {
                    reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                }
                return proxy.DisableOptimizedLogon(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GenARSOPwd: {
                LUID luid = { 0 };
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GenARSOPwd(&luid, options["arso-data"].as<std::string>());
            }
            case PROTOCOL_MESSAGE_TYPE::GetAccountInfo:
                return proxy.GetAccountInfo();
            case PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider: {
                LUID luid = { 0 };
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetAuthenticatingProvider(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus: {
                LUID luid = { 0 };
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetDpApiCredKeyDecryptStatus(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo:
                return proxy.GetPublicCachedInfo();
            case PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo: {
                LUID luid = { 0 };
                if (options["luid"].count()) {
                    reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                }
                return proxy.GetPwdExpiryInfo(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetTokenBlob: {
                LUID luid = { 0 };
                if (options["luid"].count()) {
                    reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                }
                return proxy.GetTokenBlob(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType: {
                LUID luid = { 0 };
                if (options["luid"].count()) {
                    reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                }
                return proxy.GetUnlockKeyType(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache: {
                LUID luid = { 0 };
                if (options["luid"].count()) {
                    reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                }
                return proxy.IsCloudToOnPremTgtPresentInCache(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::ProfileDeleted:
                return proxy.ProfileDeleted();
            case PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode:
                return proxy.ProvisionNGCNode();
            case PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob:
                return proxy.RefreshTokenBlob();
            case PROTOCOL_MESSAGE_TYPE::ReinitPlugin:
                return proxy.ReinitPlugin();
            case PROTOCOL_MESSAGE_TYPE::RenameAccount:
                return proxy.RenameAccount();
            case PROTOCOL_MESSAGE_TYPE::SetTestParas:
                return proxy.SetTestParas(options["flags"].as<unsigned int>());
            case PROTOCOL_MESSAGE_TYPE::TransferCreds: {
                LUID sourceLuid = { 0 };
                LUID destinationLuid = { 0 };
                reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
                reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
                return proxy.TransferCreds(&sourceLuid, &destinationLuid);
            }
            default:
                spdlog::error("Unsupported function.");
                break;
            }
            return false;
        }
    }
}

namespace Kerberos {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "kerberos" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.allow_unrecognised_options();
        // clang-format off
        unparsedOptions.add_options("Function arguments")
            ("all", "Purge all tickets flag", cxxopts::value<bool>()->default_value("false"))
            ("cache-option", "cacheOption field for KerbRetrieveTicketMessage", cxxopts::value<unsigned long>())
            ("cleanup-credentials", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"))
            ("client-name", "The client name data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("client-realm", "The client realm data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("dc-flags", "Dc flags to use with PinKdc", cxxopts::value<long long>())
            ("dc-address", "", cxxopts::value<std::string>())
            ("dc-name", "The KDC name to use with PinKdc", cxxopts::value<std::string>()->default_value(""))
            ("dluid", "Destination logon session", cxxopts::value<long long>())
            ("domain-name", "", cxxopts::value<std::string>())
            ("enc-type", "EncryptionType field for KerbRetrieveTicketMessage", cxxopts::value<unsigned long>())
            ("luid", "Logon session", cxxopts::value<long long>())
            ("optimistic-logon", "Optimistic logon flag", cxxopts::value<bool>()->default_value("false"))
            ("password", "", cxxopts::value<std::string>())
            ("remove-cred", "To use with AddExtraCredentials", cxxopts::value<bool>()->default_value("false"))
            ("replace-cred", "To use with AddExtraCredentials", cxxopts::value<bool>()->default_value("false"))
            ("server-name", "The server name data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("server-realm", "The server realm data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("sluid", "Source logon session", cxxopts::value<long long>())
            ("target-name", "TargetName field for KerbRetrieveTicketMessage", cxxopts::value<std::string>())
            ("ticket-flags", "TicketFlags field for KerbRetrieveTicketMessage", cxxopts::value<unsigned long>())
            ("user-name", "", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        // Flag for ticket retrieval commands
        bool retrieveEncoded{ false };
        bool useAddBindingCacheEntryEx{ false };
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::KerbAddBindingCacheEntryExMessage:
            useAddBindingCacheEntryEx = true;
            [[fallthrough]];
        case PROTOCOL_MESSAGE_TYPE::KerbAddBindingCacheEntryMessage: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto realmName{ converter.from_bytes(options["domain-name"].as<std::string>()) };
            auto kdcAddress{ converter.from_bytes(options["dc-address"].as<std::string>()) };
            // Assume the address is of type inet if it contains a '.' (IPv4) or a ':' (IPv6)
            // Otherwise assume it is a NetBIOS address
            auto addressType{ (kdcAddress.find(L'.') != std::string::npos || kdcAddress.find(L':') != std::string::npos) ? DS_INET_ADDRESS : DS_NETBIOS_ADDRESS };
            if (useAddBindingCacheEntryEx) {
                auto dcFlags{ options.count("dc-flags") ? options["dc-flags"].as<long long>() : 0 };
                return proxy.AddBindingCacheEntryEx(realmName, kdcAddress, addressType, dcFlags);
            }
            return proxy.AddBindingCacheEntry(realmName, kdcAddress, addressType);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbAddExtraCredentialsMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            if (options.count("replace-cred") && options.count("remove-cred")) {
                std::cout << "You should only specify either --replace-cred or --remove-cred." << std::endl;
                return false;
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domainName{ converter.from_bytes(options["domain-name"].as<std::string>()) };
            auto userName{ converter.from_bytes(options["user-name"].as<std::string>()) };
            auto password{ converter.from_bytes(options["password"].as<std::string>()) };
            auto flags{ options.count("replace-cred")  ? KERB_REQUEST_REPLACE_CREDENTIAL
                        : options.count("remove-cred") ? KERB_REQUEST_REMOVE_CREDENTIAL
                                                       : KERB_REQUEST_ADD_CREDENTIAL };
            return proxy.AddExtraCredentials(&luid, domainName, userName, password, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbCleanupMachinePkinitCredsMessage: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.CleanupMachinePkinitCreds(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbPinKdcMessage: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domainName{ converter.from_bytes(options["domain-name"].as<std::string>()) };
            auto dcName{ converter.from_bytes(options["dc-name"].as<std::string>()) };
            auto dcFlags{ options.count("dc-flags") ? options["dc-flags"].as<long long>() : 0 };
            return proxy.PinKdc(domainName, dcName, dcFlags);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbPrintCloudKerberosDebugMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.PrintCloudKerberosDebug(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbPurgeBindingCacheMessage:
            return proxy.PurgeBindingCache();
        case PROTOCOL_MESSAGE_TYPE::KerbPurgeKdcProxyCacheMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.PurgeKdcProxyCache(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbPurgeTicketCacheMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return proxy.PurgeTicketCache(
                &luid,
                converter.from_bytes(options["server-name"].as<std::string>()),
                converter.from_bytes(options["server-realm"].as<std::string>()));
        }
        case PROTOCOL_MESSAGE_TYPE::KerbPurgeTicketCacheExMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return proxy.PurgeTicketCacheEx(
                &luid,
                (options["all"].count()) ? KERB_PURGE_ALL_TICKETS : 0,
                converter.from_bytes(options["client-name"].as<std::string>()),
                converter.from_bytes(options["client-realm"].as<std::string>()),
                converter.from_bytes(options["server-name"].as<std::string>()),
                converter.from_bytes(options["server-realm"].as<std::string>()));
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryBindingCacheMessage:
            return proxy.QueryBindingCache();
        case PROTOCOL_MESSAGE_TYPE::KerbQueryDomainExtendedPoliciesMessage: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return proxy.QueryDomainExtendedPolicies(converter.from_bytes(options["domain-name"].as<std::string>()));
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryKdcProxyCacheMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryKdcProxyCache(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryS4U2ProxyCacheMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryS4U2ProxyCache(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryTicketCache(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheExMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryTicketCacheEx(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheEx2Message: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryTicketCacheEx2(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheEx3Message: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryTicketCacheEx3(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbRetrieveEncodedTicketMessage:
            retrieveEncoded = true;
            [[fallthrough]];
        case PROTOCOL_MESSAGE_TYPE::KerbRetrieveTicketMessage: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto targetName{ converter.from_bytes(options["target-name"].as<std::string>()) };
            ULONG flags{ (options["ticket-flags"].count()) ? options["ticket-flags"].as<ULONG>() : KERB_USE_DEFAULT_TICKET_FLAGS };
            ULONG cacheOption{ (options["cache-option"].count()) ? options["cache-option"].as<ULONG>() : KERB_RETRIEVE_TICKET_AS_KERB_CRED };
            ULONG encType{ (options["enc-type"].count()) ? options["cache-option"].as<ULONG>() : KERB_ETYPE_NULL };
            if (retrieveEncoded) {
                return proxy.RetrieveEncodedTicket(&luid, targetName, flags, cacheOption, encType);
            } else {
                return proxy.RetrieveTicket(&luid, targetName, flags, cacheOption, encType);
            }
        }
        case PROTOCOL_MESSAGE_TYPE::KerbRetrieveKeyTabMessage: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domainName{ converter.from_bytes(options["domain-name"].as<std::string>()) };
            auto userName{ converter.from_bytes(options["user-name"].as<std::string>()) };
            auto password{ converter.from_bytes(options["password"].as<std::string>()) };
            return proxy.RetrieveKeyTab(domainName, userName, password);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbTransferCredentialsMessage: {
            LUID sourceLuid = { 0 };
            LUID destinationLuid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
            ULONG flags{ 0 };
            flags += (options.count("cleanup-credentials")) ? static_cast<ULONG>(TransferCredFlag::CleanupCredentials) : 0;
            flags += (options.count("optimistic-logon")) ? static_cast<ULONG>(TransferCredFlag::OptimisticLogon) : 0;
            return proxy.TransferCreds(&sourceLuid, &destinationLuid, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::KerbUnpinAllKdcsMessage: {
            return proxy.UnpinAllKdcs();
        }
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Live {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "live" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments");
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::GetSignedProofOfPossessionToken:
            return proxy.GetSignedProofOfPossessionToken();
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Msv1_0 {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "msv1_0" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.allow_unrecognised_options();
        // clang-format off
        unparsedOptions.add_options()
            ("d,dc", "Send request to domain controller", cxxopts::value<bool>()->default_value("false"));
        unparsedOptions.add_options("Function arguments")
            ("challenge", "Asciihex Lm20 challenge data", cxxopts::value<std::string>())
            ("delete", "Delete entry", cxxopts::value<bool>()->default_value("false"))
            ("disable", "Disable an option", cxxopts::value<bool>()->default_value("false"))
            ("dluid", "Destination logon session", cxxopts::value<long long>())
            ("domain", "Domain name", cxxopts::value<std::string>())
            ("gcr-allow-lm", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-allow-no-target", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-allow-ntlm", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-machine-credential", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-ntlm3-parms", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-target-info", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-use-oem-set", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-use-owf-password", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("gcr-vsm-protected-password", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("generate-client-challenge", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("hash", "Asciihex hash", cxxopts::value<std::string>())
            ("imp", "Impersonating", cxxopts::value<bool>()->default_value("false"))
            ("luid", "Logon session", cxxopts::value<long long>())
            ("mitlogon", "Upn for Mit logon", cxxopts::value<std::string>())
            ("mixingbits", "Asciihex mixing data", cxxopts::value<std::string>())
            ("new-pass", "New password", cxxopts::value<std::string>())
            ("old-pass", "Old password", cxxopts::value<std::string>())
            ("option", "Process option", cxxopts::value<unsigned long>())
            ("pass", "Password", cxxopts::value<std::string>())
            ("protected-user", "Is the user protected", cxxopts::value<bool>())
            ("return-non-nt-user-session-key", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("return-primary-logon-domain-name", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("return-primary-username", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("return-reserved-parameter", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("sha1v2", "Use SHA OWF instead of NT OWF", cxxopts::value<bool>()->default_value("false"))
            ("sluid", "Source logon session", cxxopts::value<long long>())
            ("smartcard", "Set smart card flag", cxxopts::value<bool>()->default_value("false"))
            ("suppcreds", "Asciihex supplemental creds", cxxopts::value<std::string>())
            ("use-primary-password", "Lm20 challenge response flag", cxxopts::value<bool>())
            ("user", "User name", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::MsV1_0CacheLookupEx:
            break;
        case PROTOCOL_MESSAGE_TYPE::MsV1_0ChangeCachedPassword: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return proxy.ChangeCachedPassword(
                converter.from_bytes(options["domain"].as<std::string>()),
                converter.from_bytes(options["user"].as<std::string>()),
                converter.from_bytes(options["new-pass"].as<std::string>()));
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0ClearCachedCredentials:
            return proxy.ClearCachedCredentials();
        case PROTOCOL_MESSAGE_TYPE::MsV1_0DecryptDpapiMasterKey:
            return proxy.DecryptDpapiMasterKey();
        case PROTOCOL_MESSAGE_TYPE::MsV1_0DeleteTbalSecrets:
            return proxy.DeleteTbalSecrets();
        case PROTOCOL_MESSAGE_TYPE::MsV1_0DeriveCredential: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            auto credType{ (options.count("sha1v2")) ? MSV1_0_DERIVE_SHA1V2 : MSV1_0_DERIVE_SHA1 };
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::vector<byte> mixingBits;
            mixingBits = HexDecode(std::cout, converter.from_bytes(options["mixingbits"].as<std::string>()));
            return proxy.DeriveCredential(&luid, credType, mixingBits);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0EnumerateUsers:
            return proxy.EnumerateUsers();
        case PROTOCOL_MESSAGE_TYPE::MsV1_0GetCredentialKey: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCredentialKey(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0GetStrongCredentialKey: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            bool isProtectedUser{ false };
            if (options["protected-user"].count()) {
                isProtectedUser = options["protected-user"].as<bool>();
            }
            return proxy.GetStrongCredentialKey(&luid, isProtectedUser);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0GetUserInfo: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetUserInfo(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0Lm20ChallengeRequest:
            return proxy.Lm20ChallengeRequest();
        case PROTOCOL_MESSAGE_TYPE::MsV1_0Lm20GetChallengeResponse: {
            ULONG flags{ 0 };
            flags += (options.count("use-primary-password")) ? USE_PRIMARY_PASSWORD : 0;
            flags += (options.count("return-primary-username")) ? RETURN_PRIMARY_USERNAME : 0;
            flags += (options.count("return-primary-logon-domain-name")) ? RETURN_PRIMARY_LOGON_DOMAINNAME : 0;
            flags += (options.count("return-non-nt-user-session-key")) ? RETURN_NON_NT_USER_SESSION_KEY : 0;
            flags += (options.count("generate-client-challenge")) ? GENERATE_CLIENT_CHALLENGE : 0;
            flags += (options.count("gcr-ntlm3-parms")) ? GCR_NTLM3_PARMS : 0;
            flags += (options.count("gcr-target-info")) ? GCR_TARGET_INFO : 0;
            flags += (options.count("return-reserved-parameter")) ? RETURN_RESERVED_PARAMETER : 0;
            flags += (options.count("gcr-allow-ntlm")) ? GCR_ALLOW_NTLM : 0;
            flags += (options.count("gcr-allow-no-target")) ? GCR_ALLOW_NO_TARGET : 0;
            flags += (options.count("gcr-use-oem-set")) ? GCR_USE_OEM_SET : 0;
            flags += (options.count("gcr-machine-credential")) ? GCR_MACHINE_CREDENTIAL : 0;
            flags += (options.count("gcr-use-owf-password")) ? GCR_USE_OWF_PASSWORD : 0;
            flags += (options.count("gcr-vsm-protected-password")) ? GCR_VSM_PROTECTED_PASSWORD : 0;
            flags += (options.count("gcr-allow-lm")) ? GCR_ALLOW_LM : 0;
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::vector<byte> challenge;
            challenge = HexDecode(std::cout, converter.from_bytes(options["challenge"].as<std::string>()));
            return proxy.Lm20GetChallengeResponse(flags, &luid, challenge);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0ProvisionTbal: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.ProvisionTbal(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::MsV1_0SetProcessOption:
            return proxy.SetProcessOption(options["option"].as<unsigned long>(), options["disable"].as<bool>());
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
        return false;
    }
}

namespace NegoExts {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "negoexts" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("cert", "Certificate data type", cxxopts::value<bool>()->default_value("false"))
            ("csp", "Credential support provider data type", cxxopts::value<bool>()->default_value("false"))
            ("data", "Context information data", cxxopts::value<std::string>()->default_value(""))
            ("handle", "Context handle", cxxopts::value<long long>())
            ("luid", "Logon session", cxxopts::value<long long>())
            ("password", "Password data type", cxxopts::value<bool>()->default_value("false"))
            ("target", "Target name or their host name for the WST context", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<NEGOEXTS_MESSAGE_TYPE>(args[1]).value()) {
        case NEGOEXTS_MESSAGE_TYPE::NegFlushContext: {
            return proxy.FlushContext(options["handle"].as<long long>());
        }
        case NEGOEXTS_MESSAGE_TYPE::NegGetCredUIContext: {
            GUID credType = { 0 };
            if (options.count("cert")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_CERT;
            } else if (options.count("csp")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA;
            } else if (options.count("password")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_PASSWORD;
            }
            LUID session = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&session)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCredUIContext(options["handle"].as<long long>(), credType, session);
        }
        case NEGOEXTS_MESSAGE_TYPE::NegLookupContext: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto target{ converter.from_bytes(options["target"].as<std::string>()) };
            return proxy.LookupContext(target);
        }
        case NEGOEXTS_MESSAGE_TYPE::NegUpdateCredentials: {
            GUID credType = { 0 };
            if (options.count("cert")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_CERT;
            } else if (options.count("csp")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA;
            } else if (options.count("password")) {
                credType = SEC_WINNT_AUTH_DATA_TYPE_PASSWORD;
            }
            return proxy.UpdateCredentials(options["handle"].as<long long>(), credType, options["data"].as<std::string>());
        }
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Negotiate {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "negotiate" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("cleanup-credentials", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"))
            ("luid", "Logon session", cxxopts::value<long long>())
            ("optimistic-logon", "Optimistic logon flag", cxxopts::value<bool>()->default_value("false"))
            ("to-sso-session", "To SSO session flag", cxxopts::value<bool>()->default_value("false"));
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<NEGOTIATE_MESSAGES>(args[1]).value()) {
        case NEGOTIATE_MESSAGES::NegEnumPackagePrefixes:
            return proxy.EnumPackagePrefixes();
        case NEGOTIATE_MESSAGES::NegGetCallerName: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCallerName(&luid);
        }
        case NEGOTIATE_MESSAGES::NegTransferCredentials: {
            LUID sourceLuid = { 0 };
            LUID destinationLuid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
            ULONG flags{ 0 };
            flags += (options.count("cleanup-credentials")) ? static_cast<ULONG>(TransferCredFlag::CleanupCredentials) : 0;
            flags += (options.count("optimistic-logon")) ? static_cast<ULONG>(TransferCredFlag::OptimisticLogon) : 0;
            flags += (options.count("to-sso-session")) ? static_cast<ULONG>(TransferCredFlag::ToSsoSession) : 0;
            return proxy.TransferCreds(&sourceLuid, &destinationLuid, flags);
        }
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Pku2u {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "pku2u" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("all", "Purge all tickets flag", cxxopts::value<bool>()->default_value("false"))
            ("client-name", "The client name data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("client-realm", "The client realm data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("luid", "Logon session", cxxopts::value<long long>())
            ("server-name", "The server name data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""))
            ("server-realm", "The server realm data for a kerberos ticket", cxxopts::value<std::string>()->default_value(""));
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::PurgeTicketCacheEx: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return proxy.PurgeTicketCacheEx(
                &luid,
                (options["all"].count()) ? KERB_PURGE_ALL_TICKETS : 0,
                converter.from_bytes(options["client-name"].as<std::string>()),
                converter.from_bytes(options["client-realm"].as<std::string>()),
                converter.from_bytes(options["server-name"].as<std::string>()),
                converter.from_bytes(options["server-realm"].as<std::string>()));
        }
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return proxy.QueryTicketCacheEx2(&luid);
        }
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Schannel {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "schannel" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Schannel Function")
            ("f,function", "Function name", cxxopts::value<std::string>());
        // Arguments for functions that require additional inputs
        unparsedOptions.add_options("Function arguments")
            ("server", "Server name", cxxopts::value<std::string>())
            ("luid", "Logon session", cxxopts::value<long long>())
            ("clients", "All clients flag", cxxopts::value<bool>()->default_value("false"))
            ("client-entry", "Client entry flag", cxxopts::value<bool>()->default_value("false"))
            ("locators", "Purge locators flag", cxxopts::value<bool>()->default_value("false"))
            ("servers", "All servers flag", cxxopts::value<bool>()->default_value("false"))
            ("server-entry", "Server entry flag", cxxopts::value<bool>()->default_value("false"));
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::SslSessionCacheInfoMessage: {
            return false; // CacheInfo();
        }
        case PROTOCOL_MESSAGE_TYPE::SslSessionLookupCertMessage:
            return false; // LookupCert();
        case PROTOCOL_MESSAGE_TYPE::SslSessionLookupExternalCertMessage: {
            return false; // return LookupExternalCert();
        }
        case PROTOCOL_MESSAGE_TYPE::SslSessionPerfmonInfoMessage: {
            DWORD flags{ 0 }; // The flags are ignored by the dispatch function
            return proxy.PerfmonInfo(flags);
        }
        case PROTOCOL_MESSAGE_TYPE::SslPurgeSessionCacheMessage: {
            LUID luid = { 0 };
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto server{ converter.from_bytes(options["server"].as<std::string>()) };
            DWORD flags{ 0 };
            flags |= (options.count("client-entry")) ? SSL_PURGE_CLIENT_ENTRIES : 0;
            flags |= (options.count("server-entry")) ? SSL_PURGE_SERVER_ENTRIES : 0;
            flags |= (options.count("clients")) ? SSL_PURGE_CLIENT_ALL_ENTRIES : 0;
            flags |= (options.count("servers")) ? SSL_PURGE_SERVER_ALL_ENTRIES : 0;
            flags |= (options.count("locators")) ? SSL_PURGE_SERVER_ENTRIES_DISCARD_LOCATORS : 0;
            return proxy.PurgeCache(&luid, server, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::SslSessionStreamSizesMessage:
            return proxy.StreamSizes();
        default:
            spdlog::error("Unsupported function.");
            return false;
        }
    }
}

namespace Spm {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "spm" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Function arguments")
            ("package", "Package name", cxxopts::value<std::string>())
            ("luid", "Logon session", cxxopts::value<long long>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };

        switch (magic_enum::enum_cast<SpmApi::NUMBER>(args[1]).value()) {
        case SpmApi::NUMBER::EnumLogonSessions:
            return lsa->EnumLogonSessions();
        case SpmApi::NUMBER::EnumPackages:
            return lsa->EnumPackages();
        case SpmApi::NUMBER::GetLogonSessionData: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return lsa->GetLogonSessionData(&luid);
        }
        case SpmApi::NUMBER::GetUserInfo: {
            LUID luid = { 0 };
            if (options["luid"].count()) {
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            }
            return lsa->GetUserInfo(&luid);
        }
        case SpmApi::NUMBER::QueryPackage: {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto package{ converter.from_bytes(options["package"].as<std::string>()) };
            return lsa->QueryPackage(package);
        }
        default:
            spdlog::error("Unsupported function.");
            break;
        }
        return false;
    }
}

namespace Wdigest {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args) {
        char* command{ "wdigest" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Wdigest Function");
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Api(lsa) };
        return false;
    }
}
