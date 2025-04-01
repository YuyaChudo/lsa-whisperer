// Copyright (C) 2025 Evan McBroom
#include "sspi/schannel.hpp"
#include "sspi/crypt.hpp"
#include <codecvt>
#include <iostream>
#include <string>
#include <vector>

namespace Schannel {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) const {
        SSL_SESSION_CACHE_INFO_REQUEST request = { SslSessionCacheInfoMessage };
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) const {
        // SSL_CERT_LOGON_REQ request;
        // PSSL_CERT_LOGON_RESP response;
        // return CallPackage(request, &response);
        return false;
    }

    bool Api::LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) const {
        SSL_EXTERNAL_CERT_LOGON_REQ request = { SslSessionLookupExternalCertMessage };
        request.Length = 0; // ?
        request.CredentialType = type;
        request.Credential = nullptr; // ?
        request.Flags = flags;
        PSSL_EXTERNAL_CERT_LOGON_RESP response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "Length   : " << response->Length << std::endl;
            std::cout << "UserToken: " << response->UserToken << std::endl;
            std::cout << "Flags    : " << response->Flags << std::endl;
        }
        return result;
    }

    bool Api::PerfmonInfo(ULONG flags) const {
        SSL_PERFMON_INFO_REQUEST request = { SslSessionPerfmonInfoMessage };
        request.Flags = flags;
        PSSL_PERFMON_INFO_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "ClientCacheEntries       : " << response->ClientCacheEntries << std::endl;
            std::cout << "ServerCacheEntries       : " << response->ServerCacheEntries << std::endl;
            std::cout << "ClientActiveEntries      : " << response->ClientActiveEntries << std::endl;
            std::cout << "ServerActiveEntries      : " << response->ServerActiveEntries << std::endl;
            std::cout << "ClientHandshakesPerSecond: " << response->ClientHandshakesPerSecond << std::endl;
            std::cout << "ServerHandshakesPerSecond: " << response->ServerHandshakesPerSecond << std::endl;
            std::cout << "ClientReconnectsPerSecond: " << response->ClientReconnectsPerSecond << std::endl;
            std::cout << "ServerReconnectsPerSecond: " << response->ServerReconnectsPerSecond << std::endl;
        }
        return result;
    }

    bool Api::PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) const {
        SSL_PURGE_SESSION_CACHE_REQUEST request = { SslPurgeSessionCacheMessage };
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::StreamSizes() const {
        SSL_STREAM_SIZES_REQ request = { SslSessionStreamSizesMessage };
        PSSL_STREAM_SIZES_RESP response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "Length   : " << response->Length << std::endl;
            std::cout << "cbHeader : " << response->cbHeader << std::endl;
            std::cout << "cbTrailer: " << response->cbTrailer << std::endl;
        }
        return result;
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(UNISP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}