// Copyright (C) 2024 Evan McBroom
//
// RFC2743: Generic Security Service Application Program Interface Version 2, Update 1
//
#include "lwdk/gssapi.h"

ASN1module_t GSSAPI_Module = NULL;

static int ASN1CALL ASN1Enc_InitialContextToken(ASN1encoding_t enc, ASN1uint32_t tag, InitialContextToken *val);
static int ASN1CALL ASN1Dec_InitialContextToken(ASN1decoding_t dec, ASN1uint32_t tag, InitialContextToken *val);
static void ASN1CALL ASN1Free_InitialContextToken(InitialContextToken *val);

typedef ASN1BerEncFun_t ASN1EncFun_t;
static const ASN1EncFun_t encfntab[1] = {
    (ASN1EncFun_t) ASN1Enc_InitialContextToken,
};
typedef ASN1BerDecFun_t ASN1DecFun_t;
static const ASN1DecFun_t decfntab[1] = {
    (ASN1DecFun_t) ASN1Dec_InitialContextToken,
};
static const ASN1FreeFun_t freefntab[1] = {
    (ASN1FreeFun_t) ASN1Free_InitialContextToken,
};
static const ULONG sizetab[1] = {
    SIZE_GSSAPI_Module_PDU_0,
};

void ASN1CALL GSSAPI_Module_Startup()
{
    GSSAPI_Module = ASN1_CreateModule(0x10000, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 1, (const ASN1GenericFun_t *) encfntab, (const ASN1GenericFun_t *) decfntab, freefntab, sizetab, 0x61737367);
}

void ASN1CALL GSSAPI_Module_Cleanup()
{
    ASN1_CloseModule(GSSAPI_Module);
    GSSAPI_Module = NULL;
}

static int ASN1CALL ASN1Enc_InitialContextToken(ASN1encoding_t enc, ASN1uint32_t tag, InitialContextToken *val)
{
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000000, &nLenOff))
	return 0;
    if (!ASN1BEREncObjectIdentifier(enc, 0x6, &(val)->thisMech))
	return 0;
    if (!ASN1BEREncOpenType(enc, &(val)->innerToken))
	return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
	return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_InitialContextToken(ASN1decoding_t dec, ASN1uint32_t tag, InitialContextToken *val)
{
    ASN1decoding_t dd = 0;
    ASN1octet_t *di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000000, &dd, &di))
	return 0;
    if (!ASN1BERDecObjectIdentifier(dd, 0x6, &(val)->thisMech))
	return 0;
    if (!ASN1BERDecOpenType(dd, &(val)->innerToken))
	return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
	return 0;
    return 1;
}

static void ASN1CALL ASN1Free_InitialContextToken(InitialContextToken *val)
{
    if (val) {
	ASN1objectidentifier_free(&(val)->thisMech);
	ASN1open_free(&(val)->innerToken);
    }
}

