// Copyright (C) 2024 Evan McBroom
#pragma once
#include "lwdk.h"

namespace AuApi {
    typedef struct _MESSAGE {
        PORT_MESSAGE pmMessage;
        union {
            REGISTER_CONNECT_INFO ConnectionRequest;
            struct {
                NUMBER ApiNumber;
                NTSTATUS ReturnedStatus;
                union {
                    Args::LOOKUP_PACKAGE LookupPackage;
                    Args::CALL_PACKAGE CallPackage;
                } Arguments;
            };
        };

        _MESSAGE() = default;
        _MESSAGE(AuApi::NUMBER api);
    } MESSAGE, *PMESSAGE;
}

namespace SpmApi {
    typedef struct _MESSAGE {
        PORT_MESSAGE pmMessage;
        union {
            AuApi::REGISTER_CONNECT_INFO ConnectionRequest;
            API_CALL_INFO ApiCallRequest;
        };

        _MESSAGE() = default;
        _MESSAGE(SpmApi::NUMBER api, size_t argSize = 0, unsigned short flags = 0, void* context = nullptr, bool kernelMode = false);
    } MESSAGE, *PMESSAGE;
}