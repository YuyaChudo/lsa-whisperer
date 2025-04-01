// Copyright (C) 2025 Evan McBroom
#include "sspi/wdigest.hpp"
#include "sspi/crypt.hpp"
#include <codecvt>
#include <iostream>
#include <string>
#include <vector>

namespace Wdigest {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::VerifyDigest() const {
        DIGEST_BLOB_REQUEST request = { VERIFY_DIGEST_MESSAGE };
        PDIGEST_BLOB_RESPONSE response;
        return CallPackagePassthrough(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackagePassthrough(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(WDIGEST_SP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}