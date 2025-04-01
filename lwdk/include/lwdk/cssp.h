// Copyright (C) 2024 Evan McBroom
//
// [MS-CSSP]: Credential Security Support Provider (CredSSP) Protocol
//
#pragma once
#include <phnt_windows.h>

#include "um/msasn1.h"

#define TSCredentials_PDU      0
#define TSPasswordCreds_PDU    1
#define TSRequest_PDU          2
#define TSSmartCardCreds_PDU   3
#define TSRemoteGuardCreds_PDU 4

#define SIZE_CSSP_Module_PDU_0 sizeof(TSCredentials)
#define SIZE_CSSP_Module_PDU_1 sizeof(TSPasswordCreds)
#define SIZE_CSSP_Module_PDU_2 sizeof(TSRequest)
#define SIZE_CSSP_Module_PDU_3 sizeof(TSSmartCardCreds)
#define SIZE_CSSP_Module_PDU_4 sizeof(TSRemoteGuardCreds)

#ifdef __cplusplus
extern "C" {
#endif

struct NegoData;
struct NegoData_Seq;
struct TSCredentials;
struct TSCspDataDetail;
struct TSPasswordCreds;
struct TSRemoteGuardCreds;
struct TSRemoteGuardCreds_supplementalCreds;
struct TSRemoteGuardPackageCred;
struct TSRequest;
struct TSSmartCardCreds;

typedef struct NegoData* PNegoData;
typedef struct TSRemoteGuardCreds_supplementalCreds* PTSRemoteGuardCreds_supplementalCreds;

typedef struct NegoData_Seq {
    ASN1octetstring_t negoToken;
} NegoData_Seq;

typedef struct NegoData {
    PNegoData next;
    NegoData_Seq value;
} NegoData_Element;

typedef struct TSCredentials {
    ASN1int32_t credType;
    ASN1octetstring_t credentials;
} TSCredentials;

typedef struct TSCspDataDetail {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t keySpec;
#define cardName_present 0x80
    ASN1octetstring_t cardName;
#define readerName_present 0x40
    ASN1octetstring_t readerName;
#define containerName_present 0x20
    ASN1octetstring_t containerName;
#define cspName_present 0x10
    ASN1octetstring_t cspName;
} TSCspDataDetail;

typedef struct TSPasswordCreds {
    ASN1octetstring_t domainName;
    ASN1octetstring_t userName;
    ASN1octetstring_t password;
} TSPasswordCreds;

typedef struct TSRequest {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t version;
#define negoTokens_present 0x80
    PNegoData negoTokens;
#define authInfo_present 0x40
    ASN1octetstring_t authInfo;
#define pubKeyAuth_present 0x20
    ASN1octetstring_t pubKeyAuth;
#define errorCode_present 0x10
    ASN1int32_t errorCode;
#define clientNonce_present 0x8
    ASN1octetstring_t clientNonce;
} TSRequest;

typedef struct TSSmartCardCreds {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1octetstring_t pin;
    TSCspDataDetail cspData;
#define userHint_present 0x80
    ASN1octetstring_t userHint;
#define domainHint_present 0x40
    ASN1octetstring_t domainHint;
} TSSmartCardCreds;

typedef struct TSRemoteGuardPackageCred {
    ASN1octetstring_t packageName;
    ASN1octetstring_t credBuffer;
} TSRemoteGuardPackageCred;

typedef struct TSRemoteGuardCreds {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    TSRemoteGuardPackageCred logonCred;
#define supplementalCreds_present 0x80
    PTSRemoteGuardCreds_supplementalCreds supplementalCreds;
} TSRemoteGuardCreds;

typedef struct TSRemoteGuardCreds_supplementalCreds {
    PTSRemoteGuardCreds_supplementalCreds next;
    TSRemoteGuardPackageCred value;
} TSRemoteGuardCreds_supplementalCreds_Element;

extern ASN1module_t CSSP_Module;
extern void ASN1CALL CSSP_Module_Startup();
extern void ASN1CALL CSSP_Module_Cleanup();

#ifdef __cplusplus
} // Closes extern "C" above
namespace Asn1 {
    namespace Cssp {
        using NegoData = ::NegoData;
        using NegoData_Seq = ::NegoData_Seq;
        using TSCredentials = ::TSCredentials;
        using TSCspDataDetail = ::TSCspDataDetail;
        using TSPasswordCreds = ::TSPasswordCreds;
        using TSRemoteGuardCreds = ::TSRemoteGuardCreds;
        using TSRemoteGuardCreds_supplementalCreds = ::TSRemoteGuardCreds_supplementalCreds;
        using TSRemoteGuardPackageCred = ::TSRemoteGuardPackageCred;
        using TSRequest = ::TSRequest;
        using TSSmartCardCreds = ::TSSmartCardCreds;
    }
}
#endif
