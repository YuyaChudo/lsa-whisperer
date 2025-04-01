// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace Schannel {
    /// <summary>
    /// This enum definition was never identified, but its
    /// name and members where defined through manual audits
    /// and locating members SslPurgeSessionCacheMessage and
    /// SslSessionCacheInfoMessage in NT sources.
    /// </summary>
    enum PROTOCOL_MESSAGE_TYPE : ULONG {
        SslSessionLookupCertMessage = 2,
        SslPurgeSessionCacheMessage,
        SslSessionCacheInfoMessage,
        SslSessionPerfmonInfoMessage,
        SslSessionLookupExternalCertMessage,
        SslSessionMapEncodedCredentialMessage,
        SslSessionStreamSizesMessage
    };

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // A subset of the supported functions in pku2u
        bool CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) const;
        bool LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) const;
        bool PerfmonInfo(ULONG flags) const;
        bool PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool StreamSizes() const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}