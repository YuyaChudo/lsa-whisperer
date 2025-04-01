// Copyright (C) 2025 Evan McBroom
#pragma once
#include <phnt_windows.h>
#include <string>

// The midl_user_* functions will be annotated to with Microsoft's source-code annotation language (SAL). We could
// modify the function signatures to match these annotations but there is no guarantee they will be consistent across
// SDK functions. So instead we will disable the two warnings regarding the mismatch in function annotations to prevent
// the VS projects with default settings from yelling at us.
#pragma warning(disable : 28251)
#pragma warning(disable : 28252)

extern "C" {
void* __RPC_USER midl_user_allocate(_In_ size_t size);
void __RPC_USER midl_user_free(void* pBuffer);
}

namespace Rpc {
    class Client {
    public:
        /// <summary>
        /// No server information is required for RPC servers with an ALPC transport
        /// if the client code calls Bind with the ifSpec parameter.
        /// </summary>
        Client();
        Client(RPC_WSTR alpcPort);
        Client(const std::wstring& server, RPC_WSTR protoSeq, RPC_WSTR endpoint, RPC_WSTR uuid = nullptr);
        ~Client();

        bool Bind(RPC_IF_HANDLE ifSpec = nullptr);

        /// <summary>
        /// Either partially or fully bind the server handle. The server handle
        /// will only be fully bound if the ifSpec parameter is supplied. Otherwise,
        /// the RPC runtime will attempt to fully bind the server handle the first
        /// time it is used to call a client stub.
        /// </summary>
        /// <param name="binding">The server handle to bind.</param>
        /// <param name="ifSpec">The MIDL generated interface specification.</param>
        bool Bind(RPC_BINDING_HANDLE* binding, RPC_IF_HANDLE ifSpec = nullptr);

        template<class Func, class... Args>
        error_status_t Call(Func function, Args... arguments) const {
            RpcTryExcept return function(arguments...);
            RpcExcept(EXCEPTION_EXECUTE_HANDLER)
                    std::wcerr
                << L"Exception during RPC function call for binding: " << reinterpret_cast<LPWSTR>(this->stringBinding) << std::endl;
            std::wcerr << GetExceptionCode() << std::endl;
            return GetExceptionCode();
            RpcEndExcept
        }

        
        template<class Func, class... Args>
        error_status_t CallWithBinding(Func function, Args... arguments) const {
            return Call(function, this->binding, arguments...);
        }

        /// <returns>True if the server handle was either partially or fully bound.</returns>
        auto IsBound() const {
            return bound;
        }

        auto RpcString() const {
            return stringBinding;
        }

        RPC_BINDING_HANDLE binding{ nullptr };

    private:
        bool bound{ false };
        RPC_WSTR endpoint;
        RPC_WSTR protoSeq;
        std::wstring server;
        RPC_WSTR stringBinding{ nullptr };
        RPC_WSTR uuid;
    };

    RPC_WSTR String(const UUID& uuid);
}