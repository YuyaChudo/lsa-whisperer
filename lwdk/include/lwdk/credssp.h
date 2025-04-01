// Copyright (C) 2024 Evan McBroom
//
// Credential Delegation SSP (credssp)
//
#pragma once
#include <phnt_windows.h>

#include <sspi.h>

#ifdef __cplusplus
extern "C" {
#endif

enum _CREDSSP_CRET_TYPE;
enum _CREDSSP_SUBMIT_TYPE;

struct _CREDSSP_CERT_FORMAT;
struct _CREDSSP_CONTEXT;
struct _CREDSSP_CRED;
struct _CREDSSP_CRED_EX;

typedef enum _CREDSSP_CRET_TYPE {
    CredSspCertHash = 1,
    CredSspCertHashStore = 2,
    CredSspCertBin = 3,
} CREDSSP_CRET_TYPE,
    *PCREDSSP_CRET_TYPE;

typedef enum _CREDSSP_SUBMIT_TYPE {
    CredsspPasswordCreds = 2,
    CredsspSchannelCreds = 4,
    CredsspCertificateCreds = 13,
    CredsspSubmitBufferBoth = 50,
    CredsspSubmitBufferBothOld = 51,
    CredsspCredEx = 100,
} CREDSSP_SUBMIT_TYPE,
    *PCREDSSP_SUBMIT_TYPE;

typedef struct _CREDSSP_CERT_FORMAT {
    CREDSSP_CRET_TYPE Type;
    ULONG cbData;
    UCHAR Data[ANYSIZE_ARRAY];
} CREDSSP_CERT_FORMAT, *PCREDSSP_CERT_FORMAT;

typedef struct _CREDSSP_CONTEXT {
    SecHandle hSchannelContext;
    SecHandle hSpnegoContext;
    ULONG State;
    ULONG fContextReq;
    union {
        SecPkgContext_Sizes Sizes;
        SecPkgContext_StreamSizes StreamSizes;
    };
    PWCHAR pszTargetName;
    PSecBufferDesc pSpnegoToken;
    ULONG SpnegofContextAttr;
    LARGE_INTEGER SpnegotsExpiry;
    PUCHAR pCertData;
    ULONG cbCertData;
    PUCHAR pPartialDecrypt;
    ULONG cbPartialDecrypt;
    ULONG cbPartialEncrypt;
    PUCHAR pOCSP;
    ULONG cbOCSP;
} CREDSSP_CONTEXT, *PCREDSSP_CONTEXT;

typedef struct _CREDSSP_CRED {
    CREDSSP_SUBMIT_TYPE Type;
    PVOID pSchannelCred;
    PVOID pSpnegoCred;
} CREDSSP_CRED, *PCREDSSP_CRED;

typedef struct _CREDSSP_CRED_EX {
    CREDSSP_SUBMIT_TYPE Type;
    ULONG Version;
    ULONG Flags;
    ULONG Reserved;
    CREDSSP_CRED Cred;
} CREDSSP_CRED_EX, *PCREDSSP_CRED_EX;

#ifdef __cplusplus
} // Closes extern "C" above
namespace CredSsp {
    // Enumerations
    using CRET_TYPE = _CREDSSP_CRET_TYPE;
    using SUBMIT_TYPE = _CREDSSP_SUBMIT_TYPE;

    using CERT_FORMAT = _CREDSSP_CERT_FORMAT;
    using CONTEXT = _CREDSSP_CONTEXT;
    using CRED = _CREDSSP_CRED;
    using CRED_EX = _CREDSSP_CRED_EX;
}
#endif