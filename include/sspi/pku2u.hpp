// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace Pku2u {
    /// <summary>
    /// A subset of _KERB_PROTOCOL_MESSAGE_TYPE.
    /// </summary>
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PurgeTicketCacheEx = 0x0F,
        QueryTicketCacheEx2 = 0x14,
    };

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        bool PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool QueryTicketCacheEx2(PLUID luid) const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}