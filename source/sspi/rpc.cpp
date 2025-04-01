// Copyright (C) 2025 Evan McBroom
#include "sspi/rpc.hpp"
#include <iostream>
#include <vector>

extern "C" {
void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes) {
    return malloc(cBytes);
}

void __RPC_USER midl_user_free(void* pBuffer) {
    free(pBuffer);
}
}

namespace Rpc {
    Client::Client()
        : protoSeq(reinterpret_cast<RPC_WSTR>(L"ncalrpc")), server(), endpoint(nullptr), uuid(nullptr) {
    }

    Client::Client(RPC_WSTR alpcPort)
        : protoSeq(reinterpret_cast<RPC_WSTR>(L"ncalrpc")), server(), endpoint(alpcPort), uuid(nullptr) {
    }

    Client::Client(const std::wstring& server, RPC_WSTR protoSeq, RPC_WSTR endpoint, RPC_WSTR uuid)
        : protoSeq(protoSeq), server(server), endpoint(endpoint), uuid(uuid) {
    }

    Client::~Client() {
        RpcStringFreeW(&stringBinding);
        if (bound && binding) {
            RpcBindingFree(&binding);
        }
    }

    // clang-format off
    bool Client::Bind(RPC_IF_HANDLE ifSpec) {
        RpcTryExcept
            auto address{ (server.length()) ? reinterpret_cast<RPC_WSTR>(server.data()) : nullptr };
            if (RpcStringBindingComposeW(uuid, protoSeq, address, endpoint, nullptr, &stringBinding) == RPC_S_OK) {
                if (RpcBindingFromStringBindingW(stringBinding, &binding) == RPC_S_OK) {
                    bound = (ifSpec) ? (RpcEpResolveBinding(binding, ifSpec) == RPC_S_OK) : true;
                }
            } else {
                std::wcerr << L"Error composing string for RPC binding: " << server << std::endl;
            }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
                std::wcerr << L"Could not connect to: " << reinterpret_cast<LPWSTR>(stringBinding);
        RpcEndExcept
        return bound;
    }

    bool Client::Bind(RPC_BINDING_HANDLE* binding, RPC_IF_HANDLE ifSpec) {
        RpcTryExcept
            auto address{ (server.length()) ? reinterpret_cast<RPC_WSTR>(server.data()) : nullptr };
            if (RpcStringBindingComposeW(uuid, protoSeq, address, endpoint, nullptr, &stringBinding) == RPC_S_OK) {
                if (RpcBindingFromStringBindingW(stringBinding, binding) == RPC_S_OK) {
                    bound = (ifSpec) ? (RpcEpResolveBinding(*binding, ifSpec) == RPC_S_OK) : true;
                }
            } else {
                std::wcerr << L"Error composing string for RPC binding: " << server << std::endl;
            }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
                std::wcerr << L"Could not connect to: " << reinterpret_cast<LPWSTR>(stringBinding);
        RpcEndExcept
        return bound;
    }
    // clang-format on

    RPC_WSTR String(const UUID& uuid) {
        RPC_WSTR rpcString;
        return (UuidToStringW(&uuid, &rpcString) == RPC_S_OK) ? rpcString : nullptr;
    }
}