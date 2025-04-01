// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace Negotiate {
    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // A subset of the supported functions in negotiate
        bool EnumPackagePrefixes() const;
        bool GetCallerName(PLUID logonId) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}