// Copyright (C) 2024 Evan McBroom
//
// [MS-CSSP]: Credential Security Support Provider (CredSSP) Protocol
//
#include "lwdk/cssp.h"

ASN1module_t CSSP_Module = NULL;

static int ASN1CALL ASN1Enc_NegoData_Seq(ASN1encoding_t enc, ASN1uint32_t tag, NegoData_Seq* val);
static int ASN1CALL ASN1Enc_NegoData(ASN1encoding_t enc, ASN1uint32_t tag, PNegoData* val);
static int ASN1CALL ASN1Enc_TSCredentials(ASN1encoding_t enc, ASN1uint32_t tag, TSCredentials* val);
static int ASN1CALL ASN1Enc_TSCspDataDetail(ASN1encoding_t enc, ASN1uint32_t tag, TSCspDataDetail* val);
static int ASN1CALL ASN1Enc_TSPasswordCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSPasswordCreds* val);
static int ASN1CALL ASN1Enc_TSRequest(ASN1encoding_t enc, ASN1uint32_t tag, TSRequest* val);
static int ASN1CALL ASN1Enc_TSSmartCardCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSSmartCardCreds* val);
static int ASN1CALL ASN1Enc_TSRemoteGuardPackageCred(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardPackageCred* val);
static int ASN1CALL ASN1Enc_TSRemoteGuardCreds_supplementalCreds(ASN1encoding_t enc, ASN1uint32_t tag, PTSRemoteGuardCreds_supplementalCreds* val);
static int ASN1CALL ASN1Enc_TSRemoteGuardCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardCreds* val);
static int ASN1CALL ASN1Dec_NegoData_Seq(ASN1decoding_t dec, ASN1uint32_t tag, NegoData_Seq* val);
static int ASN1CALL ASN1Dec_NegoData(ASN1decoding_t dec, ASN1uint32_t tag, PNegoData* val);
static int ASN1CALL ASN1Dec_TSCredentials(ASN1decoding_t dec, ASN1uint32_t tag, TSCredentials* val);
static int ASN1CALL ASN1Dec_TSCspDataDetail(ASN1decoding_t dec, ASN1uint32_t tag, TSCspDataDetail* val);
static int ASN1CALL ASN1Dec_TSPasswordCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSPasswordCreds* val);
static int ASN1CALL ASN1Dec_TSRequest(ASN1decoding_t dec, ASN1uint32_t tag, TSRequest* val);
static int ASN1CALL ASN1Dec_TSSmartCardCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSSmartCardCreds* val);
static int ASN1CALL ASN1Dec_TSRemoteGuardPackageCred(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardPackageCred* val);
static int ASN1CALL ASN1Dec_TSRemoteGuardCreds_supplementalCreds(ASN1decoding_t dec, ASN1uint32_t tag, PTSRemoteGuardCreds_supplementalCreds* val);
static int ASN1CALL ASN1Dec_TSRemoteGuardCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardCreds* val);
static void ASN1CALL ASN1Free_NegoData_Seq(NegoData_Seq* val);
static void ASN1CALL ASN1Free_NegoData(PNegoData* val);
static void ASN1CALL ASN1Free_TSCredentials(TSCredentials* val);
static void ASN1CALL ASN1Free_TSCspDataDetail(TSCspDataDetail* val);
static void ASN1CALL ASN1Free_TSPasswordCreds(TSPasswordCreds* val);
static void ASN1CALL ASN1Free_TSRequest(TSRequest* val);
static void ASN1CALL ASN1Free_TSSmartCardCreds(TSSmartCardCreds* val);
static void ASN1CALL ASN1Free_TSRemoteGuardPackageCred(TSRemoteGuardPackageCred* val);
static void ASN1CALL ASN1Free_TSRemoteGuardCreds_supplementalCreds(PTSRemoteGuardCreds_supplementalCreds* val);
static void ASN1CALL ASN1Free_TSRemoteGuardCreds(TSRemoteGuardCreds* val);

typedef ASN1BerEncFun_t ASN1EncFun_t;
static const ASN1EncFun_t encfntab[5] = {
    (ASN1EncFun_t)ASN1Enc_TSCredentials,
    (ASN1EncFun_t)ASN1Enc_TSPasswordCreds,
    (ASN1EncFun_t)ASN1Enc_TSRequest,
    (ASN1EncFun_t)ASN1Enc_TSSmartCardCreds,
    (ASN1EncFun_t)ASN1Enc_TSRemoteGuardCreds,
};
typedef ASN1BerDecFun_t ASN1DecFun_t;
static const ASN1DecFun_t decfntab[5] = {
    (ASN1DecFun_t)ASN1Dec_TSCredentials,
    (ASN1DecFun_t)ASN1Dec_TSPasswordCreds,
    (ASN1DecFun_t)ASN1Dec_TSRequest,
    (ASN1DecFun_t)ASN1Dec_TSSmartCardCreds,
    (ASN1DecFun_t)ASN1Dec_TSRemoteGuardCreds,
};
static const ASN1FreeFun_t freefntab[5] = {
    (ASN1FreeFun_t)ASN1Free_TSCredentials,
    (ASN1FreeFun_t)ASN1Free_TSPasswordCreds,
    (ASN1FreeFun_t)ASN1Free_TSRequest,
    (ASN1FreeFun_t)ASN1Free_TSSmartCardCreds,
    (ASN1FreeFun_t)ASN1Free_TSRemoteGuardCreds,
};
static const ULONG sizetab[5] = {
    SIZE_CSSP_Module_PDU_0,
    SIZE_CSSP_Module_PDU_1,
    SIZE_CSSP_Module_PDU_2,
    SIZE_CSSP_Module_PDU_3,
    SIZE_CSSP_Module_PDU_4,
};

void ASN1CALL CSSP_Module_Startup() {
    CSSP_Module = ASN1_CreateModule(0x10000, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 5, (const ASN1GenericFun_t*)encfntab, (const ASN1GenericFun_t*)decfntab, freefntab, sizetab, 0x70737363);
}

void ASN1CALL CSSP_Module_Cleanup() {
    ASN1_CloseModule(CSSP_Module);
    CSSP_Module = NULL;
}

static int ASN1CALL ASN1Enc_NegoData_Seq(ASN1encoding_t enc, ASN1uint32_t tag, NegoData_Seq* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->negoToken).length, ((val)->negoToken).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_NegoData_Seq(ASN1decoding_t dec, ASN1uint32_t tag, NegoData_Seq* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0 = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->negoToken))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_NegoData_Seq(NegoData_Seq* val) {
    if (val) {
        ASN1octetstring_free(&(val)->negoToken);
    }
}

static int ASN1CALL ASN1Enc_NegoData(ASN1encoding_t enc, ASN1uint32_t tag, PNegoData* val) {
    PNegoData f = 0;
    ASN1uint32_t nLenOff = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_NegoData_Seq(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_NegoData(ASN1decoding_t dec, ASN1uint32_t tag, PNegoData* val) {
    PNegoData* f = 0;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PNegoData)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_NegoData_Seq(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_NegoData(PNegoData* val) {
    PNegoData f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_NegoData_Seq(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_TSCredentials(ASN1encoding_t enc, ASN1uint32_t tag, TSCredentials* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1BEREncS32(enc, 0x2, (val)->credType))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->credentials).length, ((val)->credentials).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSCredentials(ASN1decoding_t dec, ASN1uint32_t tag, TSCredentials* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0 = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecS32Val(dd0, 0x2, &(val)->credType))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->credentials))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSCredentials(TSCredentials* val) {
    if (val) {
        ASN1octetstring_free(&(val)->credentials);
    }
}

static int ASN1CALL ASN1Enc_TSCspDataDetail(ASN1encoding_t enc, ASN1uint32_t tag, TSCspDataDetail* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1BEREncS32(enc, 0x2, (val)->keySpec))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->cardName).length, ((val)->cardName).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x40) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->readerName).length, ((val)->readerName).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x20) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->containerName).length, ((val)->containerName).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x10) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000004, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->cspName).length, ((val)->cspName).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSCspDataDetail(ASN1decoding_t dec, ASN1uint32_t tag, TSCspDataDetail* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0 = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecS32Val(dd0, 0x2, &(val)->keySpec))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000001) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->cardName))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000002) {
        (val)->o[0] |= 0x40;
        if (!ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->readerName))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x20;
        if (!ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->containerName))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000004) {
        (val)->o[0] |= 0x10;
        if (!ASN1BERDecExplicitTag(dd, 0x80000004, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->cspName))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSCspDataDetail(TSCspDataDetail* val) {
    if (val) {
        if ((val)->o[0] & 0x80) {
            ASN1octetstring_free(&(val)->cardName);
        }
        if ((val)->o[0] & 0x40) {
            ASN1octetstring_free(&(val)->readerName);
        }
        if ((val)->o[0] & 0x20) {
            ASN1octetstring_free(&(val)->containerName);
        }
        if ((val)->o[0] & 0x10) {
            ASN1octetstring_free(&(val)->cspName);
        }
    }
}

static int ASN1CALL ASN1Enc_TSPasswordCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSPasswordCreds* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->domainName).length, ((val)->domainName).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->userName).length, ((val)->userName).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->password).length, ((val)->password).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSPasswordCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSPasswordCreds* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0 = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->domainName))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->userName))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->password))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSPasswordCreds(TSPasswordCreds* val) {
    if (val) {
        ASN1octetstring_free(&(val)->domainName);
        ASN1octetstring_free(&(val)->userName);
        ASN1octetstring_free(&(val)->password);
    }
}

static int ASN1CALL ASN1Enc_TSRequest(ASN1encoding_t enc, ASN1uint32_t tag, TSRequest* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1BEREncS32(enc, 0x2, (val)->version))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
            return 0;
        if (!ASN1Enc_NegoData(enc, 0, &(val)->negoTokens))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x40) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->authInfo).length, ((val)->authInfo).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x20) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->pubKeyAuth).length, ((val)->pubKeyAuth).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x10) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000004, &nLenOff0))
            return 0;
        if (!ASN1BEREncS32(enc, 0x2, (val)->errorCode))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x8) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000005, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->clientNonce).length, ((val)->clientNonce).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSRequest(ASN1decoding_t dec, ASN1uint32_t tag, TSRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecS32Val(dd0, 0x2, &(val)->version))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000001) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
            return 0;
        if (!ASN1Dec_NegoData(dd0, 0, &(val)->negoTokens))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000002) {
        (val)->o[0] |= 0x40;
        if (!ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->authInfo))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x20;
        if (!ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->pubKeyAuth))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000004) {
        (val)->o[0] |= 0x10;
        if (!ASN1BERDecExplicitTag(dd, 0x80000004, &dd0, &di0))
            return 0;
        if (!ASN1BERDecS32Val(dd0, 0x2, &(val)->errorCode))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000005) {
        (val)->o[0] |= 0x8;
        if (!ASN1BERDecExplicitTag(dd, 0x80000005, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->clientNonce))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSRequest(TSRequest* val) {
    if (val) {
        if ((val)->o[0] & 0x80) {
            ASN1Free_NegoData(&(val)->negoTokens);
        }
        if ((val)->o[0] & 0x40) {
            ASN1octetstring_free(&(val)->authInfo);
        }
        if ((val)->o[0] & 0x20) {
            ASN1octetstring_free(&(val)->pubKeyAuth);
        }
        if ((val)->o[0] & 0x8) {
            ASN1octetstring_free(&(val)->clientNonce);
        }
    }
}

static int ASN1CALL ASN1Enc_TSSmartCardCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSSmartCardCreds* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->pin).length, ((val)->pin).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1Enc_TSCspDataDetail(enc, 0, &(val)->cspData))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->userHint).length, ((val)->userHint).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if ((val)->o[0] & 0x40) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0))
            return 0;
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->domainHint).length, ((val)->domainHint).value))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSSmartCardCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSSmartCardCreds* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->pin))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1Dec_TSCspDataDetail(dd0, 0, &(val)->cspData))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000002) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->userHint))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x40;
        if (!ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0))
            return 0;
        if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->domainHint))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSSmartCardCreds(TSSmartCardCreds* val) {
    if (val) {
        ASN1octetstring_free(&(val)->pin);
        ASN1Free_TSCspDataDetail(&(val)->cspData);
        if ((val)->o[0] & 0x80) {
            ASN1octetstring_free(&(val)->userHint);
        }
        if ((val)->o[0] & 0x40) {
            ASN1octetstring_free(&(val)->domainHint);
        }
    }
}

static int ASN1CALL ASN1Enc_TSRemoteGuardPackageCred(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardPackageCred* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->packageName).length, ((val)->packageName).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->credBuffer).length, ((val)->credBuffer).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSRemoteGuardPackageCred(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardPackageCred* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->packageName))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->credBuffer))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSRemoteGuardPackageCred(TSRemoteGuardPackageCred* val) {
    if (val) {
        ASN1octetstring_free(&(val)->packageName);
        ASN1octetstring_free(&(val)->credBuffer);
    }
}

static int ASN1CALL ASN1Enc_TSRemoteGuardCreds_supplementalCreds(ASN1encoding_t enc, ASN1uint32_t tag, PTSRemoteGuardCreds_supplementalCreds* val) {
    ASN1uint32_t nLenOff0 = 0;
    PTSRemoteGuardCreds_supplementalCreds f;
    ASN1uint32_t nLenOff = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_TSRemoteGuardPackageCred(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSRemoteGuardCreds_supplementalCreds(ASN1decoding_t dec, ASN1uint32_t tag, PTSRemoteGuardCreds_supplementalCreds* val) {
    PTSRemoteGuardCreds_supplementalCreds* f;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd0, 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PTSRemoteGuardCreds_supplementalCreds)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_TSRemoteGuardPackageCred(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dd0, dd, di))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd0, di0))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSRemoteGuardCreds_supplementalCreds(PTSRemoteGuardCreds_supplementalCreds* val) {
    PTSRemoteGuardCreds_supplementalCreds f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_TSRemoteGuardPackageCred(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_TSRemoteGuardCreds(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardCreds* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
        return 0;
    if (!ASN1Enc_TSRemoteGuardPackageCred(enc, 0, &(val)->logonCred))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1Enc_TSRemoteGuardCreds_supplementalCreds(enc, 0, &(val)->supplementalCreds))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSRemoteGuardCreds(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardCreds* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
        return 0;
    if (!ASN1Dec_TSRemoteGuardPackageCred(dd0, 0, &(val)->logonCred))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000001) {
        (val)->o[0] |= 0x80;
        if (!ASN1Dec_TSRemoteGuardCreds_supplementalCreds(dd, 0, &(val)->supplementalCreds))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSRemoteGuardCreds(TSRemoteGuardCreds* val) {
    if (val) {
        ASN1Free_TSRemoteGuardPackageCred(&(val)->logonCred);
        if ((val)->o[0] & 0x80) {
            ASN1Free_TSRemoteGuardCreds_supplementalCreds(&(val)->supplementalCreds);
        }
    }
}
