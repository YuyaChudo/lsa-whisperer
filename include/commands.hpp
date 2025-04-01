// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi.hpp"
#include <cxxopts.hpp>

namespace AllPackages {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Cloudap {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Kerberos {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Live {
    bool Call(const std::shared_ptr<Lsa::Api>& proxy, const std::vector<char*>& args);
}

namespace Msv1_0 {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace NegoExts {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Negotiate {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Pku2u {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Schannel {
    bool Call(const std::shared_ptr<Lsa::Api>& proxy, const std::vector<char*>& args);
}

namespace Spm {
    bool Call(const std::shared_ptr<Lsa::Api>& lsa, const std::vector<char*>& args);
}

namespace Wdigest {
    bool Call(const std::shared_ptr<Lsa::Api>& proxy, const std::vector<char*>& args);
}