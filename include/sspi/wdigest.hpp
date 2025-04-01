// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace Wdigest {
    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // A subset of the supported functions in pku2u
        bool VerifyDigest() const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackagePassthrough(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}