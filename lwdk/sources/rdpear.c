// Copyright (C) 2024 Evan McBroom
//
// [MS-RDPEAR]: Remote Desktop Protocol Authentication Redirection Virtual Channel
//
#include "lwdk/rdpear.h"

ASN1module_t RDPEAR_Module = NULL;

static int ASN1CALL ASN1Enc_TSRemoteGuardInnerPacket(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardInnerPacket* val);
static int ASN1CALL ASN1Dec_TSRemoteGuardInnerPacket(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardInnerPacket* val);
static void ASN1CALL ASN1Free_TSRemoteGuardInnerPacket(TSRemoteGuardInnerPacket* val);

typedef ASN1BerEncFun_t ASN1EncFun_t;
static const ASN1EncFun_t encfntab[1] = {
    (ASN1EncFun_t)ASN1Enc_TSRemoteGuardInnerPacket,
};
typedef ASN1BerDecFun_t ASN1DecFun_t;
static const ASN1DecFun_t decfntab[1] = {
    (ASN1DecFun_t)ASN1Dec_TSRemoteGuardInnerPacket,
};
static const ASN1FreeFun_t freefntab[1] = {
    (ASN1FreeFun_t)ASN1Free_TSRemoteGuardInnerPacket,
};
static const ULONG sizetab[1] = {
    SIZE_RDPEAR_Module_PDU_0,
};

TSRemoteGuardVersion TSRemoteGuardInnerPacket_version_default = 0;

void ASN1CALL RDPEAR_Module_Startup() {
    RDPEAR_Module = ASN1_CreateModule(0x10000, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 1, (const ASN1GenericFun_t*)encfntab, (const ASN1GenericFun_t*)decfntab, freefntab, sizetab, 0x65706472);
}

void ASN1CALL RDPEAR_Module_Cleanup() {
    ASN1_CloseModule(RDPEAR_Module);
    RDPEAR_Module = NULL;
}

static int ASN1CALL ASN1Enc_TSRemoteGuardInnerPacket(ASN1encoding_t enc, ASN1uint32_t tag, TSRemoteGuardInnerPacket* val) {
    ASN1uint32_t nLenOff = 0;
    ASN1octet_t o[1] = { 0 };
    ASN1uint32_t nLenOff0 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    CopyMemory(o, (val)->o, 1);
    if ((val)->version == 0)
        o[0] &= ~0x80;
    if (o[0] & 0x80) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0))
            return 0;
        if (!ASN1BEREncS32(enc, 0xa, (val)->version))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if (!ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->packageName).length, ((val)->packageName).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->buffer).length, ((val)->buffer).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (o[0] & 0x40) {
        if (!ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0))
            return 0;
        if (!ASN1BEREncOpenType(enc, &(val)->extension))
            return 0;
        if (!ASN1BEREncEndOfContents(enc, nLenOff0))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_TSRemoteGuardInnerPacket(ASN1decoding_t dec, ASN1uint32_t tag, TSRemoteGuardInnerPacket* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0 = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000000) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0))
            return 0;
        if (!ASN1BERDecS32Val(dd0, 0xa, &(val)->version))
            return 0;
        if (!ASN1BERDecEndOfContents(dd, dd0, di0))
            return 0;
    }
    if (!ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->packageName))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0))
        return 0;
    if (!ASN1BERDecOctetString(dd0, 0x4, &(val)->buffer))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (ASN1BERDecPeekTag(dd, &t)) {
        if (t == 0x80000003) {
            (val)->o[0] |= 0x40;
            if (!ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0))
                return 0;
            if (!ASN1BERDecOpenType(dd0, &(val)->extension))
                return 0;
            if (!ASN1BERDecEndOfContents(dd, dd0, di0))
                return 0;
        }
    }
    if (!((val)->o[0] & 0x80))
        (val)->version = 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_TSRemoteGuardInnerPacket(TSRemoteGuardInnerPacket* val) {
    if (val) {
        ASN1octetstring_free(&(val)->packageName);
        ASN1octetstring_free(&(val)->buffer);
        if ((val)->o[0] & 0x40) {
            ASN1open_free(&(val)->extension);
        }
    }
}
