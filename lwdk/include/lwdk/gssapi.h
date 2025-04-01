// Copyright (C) 2024 Evan McBroom
//
// RFC2743: Generic Security Service Application Program Interface Version 2, Update 1
//
#pragma once
#include <phnt_windows.h>

#include "um/msasn1.h"

#define InitialContextToken_PDU  0

#define SIZE_GSSAPI_Module_PDU_0 sizeof(InitialContextToken)

#ifdef __cplusplus
extern "C" {
#endif

struct InitialContextToken;

typedef ASN1objectidentifier_t MechType;
typedef ASN1open_t SubsequentContextToken;
typedef ASN1open_t PerMsgToken;
typedef ASN1open_t SealedMessage;

typedef struct InitialContextToken {
    MechType thisMech;
    ASN1open_t innerToken;
} InitialContextToken;

extern ASN1module_t GSSAPI_Module;
extern void ASN1CALL GSSAPI_Module_Startup();
extern void ASN1CALL GSSAPI_Module_Cleanup();

#ifdef __cplusplus
} // Closes extern "C" above
namespace Asn1 {
    namespace Gssapi {
        using InitialContextToken = ::InitialContextToken;
    }
}
#endif