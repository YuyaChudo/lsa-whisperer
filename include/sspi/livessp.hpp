// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace Live {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        RenameAccount,
        TransferCredential,
        GetSignedProofOfPossessionToken,
        SetUnsignedProofOfPossessionToken,
        DeleteProofOfPossessionToken
    };

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        bool GetSignedProofOfPossessionToken() const;

        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const;
    };
}