// Copyright (C) 2024 Evan McBroom
//
// Ldap protocol asn.1
//
#include "lwdk/ldap.h"

ASN1module_t LDAP_Module = NULL;

static int ASN1CALL ASN1Enc_PartialAttributeList_Seq_vals(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttributeList_Seq_vals* val);
static int ASN1CALL ASN1Enc_AttributeList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, AttributeList_Seq* val);
static int ASN1CALL ASN1Enc_AttributeTypeAndValues_vals(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeTypeAndValues_vals* val);
static int ASN1CALL ASN1Enc_PartialAttributeList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, PartialAttributeList_Seq* val);
static int ASN1CALL ASN1Enc_MatchingRuleAssertion_matchingRules(ASN1encoding_t enc, ASN1uint32_t tag, PMatchingRuleAssertion_matchingRules* val);
static int ASN1CALL ASN1Enc_SubstringFilterList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, SubstringFilterList_Seq* val);
static int ASN1CALL ASN1Enc_PartialAttribute_vals(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttribute_vals* val);
static int ASN1CALL ASN1Enc_AttributeDescriptionList(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeDescriptionList* val);
static int ASN1CALL ASN1Enc_AttributeValueAssertion(ASN1encoding_t enc, ASN1uint32_t tag, AttributeValueAssertion* val);
static int ASN1CALL ASN1Enc_PartialAttribute(ASN1encoding_t enc, ASN1uint32_t tag, PartialAttribute* val);
static int ASN1CALL ASN1Enc_LDAPResult(ASN1encoding_t enc, ASN1uint32_t tag, LDAPResult* val);
static int ASN1CALL ASN1Enc_Referral(ASN1encoding_t enc, ASN1uint32_t tag, PReferral* val);
static int ASN1CALL ASN1Enc_Control(ASN1encoding_t enc, ASN1uint32_t tag, Control* val);
static int ASN1CALL ASN1Enc_SaslCredentials(ASN1encoding_t enc, ASN1uint32_t tag, SaslCredentials* val);
static int ASN1CALL ASN1Enc_SubstringFilter(ASN1encoding_t enc, ASN1uint32_t tag, SubstringFilter* val);
static int ASN1CALL ASN1Enc_SubstringFilterList(ASN1encoding_t enc, ASN1uint32_t tag, PSubstringFilterList* val);
static int ASN1CALL ASN1Enc_MatchingRuleAssertion(ASN1encoding_t enc, ASN1uint32_t tag, MatchingRuleAssertion* val);
static int ASN1CALL ASN1Enc_SearchResultEntry(ASN1encoding_t enc, ASN1uint32_t tag, SearchResultEntry* val);
static int ASN1CALL ASN1Enc_PartialAttributeList(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttributeList* val);
static int ASN1CALL ASN1Enc_SearchResultReference(ASN1encoding_t enc, ASN1uint32_t tag, PSearchResultReference* val);
static int ASN1CALL ASN1Enc_SearchResultDone(ASN1encoding_t enc, ASN1uint32_t tag, SearchResultDone* val);
static int ASN1CALL ASN1Enc_ModifyRequest(ASN1encoding_t enc, ASN1uint32_t tag, ModifyRequest* val);
static int ASN1CALL ASN1Enc_AttributeTypeAndValues(ASN1encoding_t enc, ASN1uint32_t tag, AttributeTypeAndValues* val);
static int ASN1CALL ASN1Enc_ModifyResponse(ASN1encoding_t enc, ASN1uint32_t tag, ModifyResponse* val);
static int ASN1CALL ASN1Enc_AddRequest(ASN1encoding_t enc, ASN1uint32_t tag, AddRequest* val);
static int ASN1CALL ASN1Enc_AttributeList(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeList* val);
static int ASN1CALL ASN1Enc_AttributeVals(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeVals* val);
static int ASN1CALL ASN1Enc_AddResponse(ASN1encoding_t enc, ASN1uint32_t tag, AddResponse* val);
static int ASN1CALL ASN1Enc_DelResponse(ASN1encoding_t enc, ASN1uint32_t tag, DelResponse* val);
static int ASN1CALL ASN1Enc_ModifyDNRequest(ASN1encoding_t enc, ASN1uint32_t tag, ModifyDNRequest* val);
static int ASN1CALL ASN1Enc_ModifyDNResponse(ASN1encoding_t enc, ASN1uint32_t tag, ModifyDNResponse* val);
static int ASN1CALL ASN1Enc_CompareRequest(ASN1encoding_t enc, ASN1uint32_t tag, CompareRequest* val);
static int ASN1CALL ASN1Enc_CompareResponse(ASN1encoding_t enc, ASN1uint32_t tag, CompareResponse* val);
static int ASN1CALL ASN1Enc_ExtendedRequest(ASN1encoding_t enc, ASN1uint32_t tag, ExtendedRequest* val);
static int ASN1CALL ASN1Enc_ExtendedResponse(ASN1encoding_t enc, ASN1uint32_t tag, ExtendedResponse* val);
static int ASN1CALL ASN1Enc_ModificationList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, ModificationList_Seq* val);
static int ASN1CALL ASN1Enc_Controls(ASN1encoding_t enc, ASN1uint32_t tag, PControls* val);
static int ASN1CALL ASN1Enc_AuthenticationChoice(ASN1encoding_t enc, ASN1uint32_t tag, AuthenticationChoice* val);
static int ASN1CALL ASN1Enc_BindResponse(ASN1encoding_t enc, ASN1uint32_t tag, BindResponse* val);
static int ASN1CALL ASN1Enc_Filter(ASN1encoding_t enc, ASN1uint32_t tag, Filter* val);
static int ASN1CALL ASN1Enc_ModificationList(ASN1encoding_t enc, ASN1uint32_t tag, PModificationList* val);
static int ASN1CALL ASN1Enc_Filter_or(ASN1encoding_t enc, ASN1uint32_t tag, PFilter_or* val);
static int ASN1CALL ASN1Enc_Filter_and(ASN1encoding_t enc, ASN1uint32_t tag, PFilter_and* val);
static int ASN1CALL ASN1Enc_BindRequest(ASN1encoding_t enc, ASN1uint32_t tag, BindRequest* val);
static int ASN1CALL ASN1Enc_SearchRequest(ASN1encoding_t enc, ASN1uint32_t tag, SearchRequest* val);
static int ASN1CALL ASN1Enc_LDAPMsg_protocolOp(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMsg_protocolOp* val);
static int ASN1CALL ASN1Enc_LDAPMsg(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMsg* val);
static int ASN1CALL ASN1Enc_LDAPMessage(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMessage* val);
static int ASN1CALL ASN1Dec_PartialAttributeList_Seq_vals(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttributeList_Seq_vals* val);
static int ASN1CALL ASN1Dec_AttributeList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, AttributeList_Seq* val);
static int ASN1CALL ASN1Dec_AttributeTypeAndValues_vals(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeTypeAndValues_vals* val);
static int ASN1CALL ASN1Dec_PartialAttributeList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, PartialAttributeList_Seq* val);
static int ASN1CALL ASN1Dec_MatchingRuleAssertion_matchingRules(ASN1decoding_t dec, ASN1uint32_t tag, PMatchingRuleAssertion_matchingRules* val);
static int ASN1CALL ASN1Dec_SubstringFilterList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, SubstringFilterList_Seq* val);
static int ASN1CALL ASN1Dec_PartialAttribute_vals(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttribute_vals* val);
static int ASN1CALL ASN1Dec_AttributeDescriptionList(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeDescriptionList* val);
static int ASN1CALL ASN1Dec_AttributeValueAssertion(ASN1decoding_t dec, ASN1uint32_t tag, AttributeValueAssertion* val);
static int ASN1CALL ASN1Dec_PartialAttribute(ASN1decoding_t dec, ASN1uint32_t tag, PartialAttribute* val);
static int ASN1CALL ASN1Dec_LDAPResult(ASN1decoding_t dec, ASN1uint32_t tag, LDAPResult* val);
static int ASN1CALL ASN1Dec_Referral(ASN1decoding_t dec, ASN1uint32_t tag, PReferral* val);
static int ASN1CALL ASN1Dec_Control(ASN1decoding_t dec, ASN1uint32_t tag, Control* val);
static int ASN1CALL ASN1Dec_SaslCredentials(ASN1decoding_t dec, ASN1uint32_t tag, SaslCredentials* val);
static int ASN1CALL ASN1Dec_SubstringFilter(ASN1decoding_t dec, ASN1uint32_t tag, SubstringFilter* val);
static int ASN1CALL ASN1Dec_SubstringFilterList(ASN1decoding_t dec, ASN1uint32_t tag, PSubstringFilterList* val);
static int ASN1CALL ASN1Dec_MatchingRuleAssertion(ASN1decoding_t dec, ASN1uint32_t tag, MatchingRuleAssertion* val);
static int ASN1CALL ASN1Dec_SearchResultEntry(ASN1decoding_t dec, ASN1uint32_t tag, SearchResultEntry* val);
static int ASN1CALL ASN1Dec_PartialAttributeList(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttributeList* val);
static int ASN1CALL ASN1Dec_SearchResultReference(ASN1decoding_t dec, ASN1uint32_t tag, PSearchResultReference* val);
static int ASN1CALL ASN1Dec_SearchResultDone(ASN1decoding_t dec, ASN1uint32_t tag, SearchResultDone* val);
static int ASN1CALL ASN1Dec_ModifyRequest(ASN1decoding_t dec, ASN1uint32_t tag, ModifyRequest* val);
static int ASN1CALL ASN1Dec_AttributeTypeAndValues(ASN1decoding_t dec, ASN1uint32_t tag, AttributeTypeAndValues* val);
static int ASN1CALL ASN1Dec_ModifyResponse(ASN1decoding_t dec, ASN1uint32_t tag, ModifyResponse* val);
static int ASN1CALL ASN1Dec_AddRequest(ASN1decoding_t dec, ASN1uint32_t tag, AddRequest* val);
static int ASN1CALL ASN1Dec_AttributeList(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeList* val);
static int ASN1CALL ASN1Dec_AttributeVals(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeVals* val);
static int ASN1CALL ASN1Dec_AddResponse(ASN1decoding_t dec, ASN1uint32_t tag, AddResponse* val);
static int ASN1CALL ASN1Dec_DelResponse(ASN1decoding_t dec, ASN1uint32_t tag, DelResponse* val);
static int ASN1CALL ASN1Dec_ModifyDNRequest(ASN1decoding_t dec, ASN1uint32_t tag, ModifyDNRequest* val);
static int ASN1CALL ASN1Dec_ModifyDNResponse(ASN1decoding_t dec, ASN1uint32_t tag, ModifyDNResponse* val);
static int ASN1CALL ASN1Dec_CompareRequest(ASN1decoding_t dec, ASN1uint32_t tag, CompareRequest* val);
static int ASN1CALL ASN1Dec_CompareResponse(ASN1decoding_t dec, ASN1uint32_t tag, CompareResponse* val);
static int ASN1CALL ASN1Dec_ExtendedRequest(ASN1decoding_t dec, ASN1uint32_t tag, ExtendedRequest* val);
static int ASN1CALL ASN1Dec_ExtendedResponse(ASN1decoding_t dec, ASN1uint32_t tag, ExtendedResponse* val);
static int ASN1CALL ASN1Dec_ModificationList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, ModificationList_Seq* val);
static int ASN1CALL ASN1Dec_Controls(ASN1decoding_t dec, ASN1uint32_t tag, PControls* val);
static int ASN1CALL ASN1Dec_AuthenticationChoice(ASN1decoding_t dec, ASN1uint32_t tag, AuthenticationChoice* val);
static int ASN1CALL ASN1Dec_BindResponse(ASN1decoding_t dec, ASN1uint32_t tag, BindResponse* val);
static int ASN1CALL ASN1Dec_Filter(ASN1decoding_t dec, ASN1uint32_t tag, Filter* val);
static int ASN1CALL ASN1Dec_ModificationList(ASN1decoding_t dec, ASN1uint32_t tag, PModificationList* val);
static int ASN1CALL ASN1Dec_Filter_or(ASN1decoding_t dec, ASN1uint32_t tag, PFilter_or* val);
static int ASN1CALL ASN1Dec_Filter_and(ASN1decoding_t dec, ASN1uint32_t tag, PFilter_and* val);
static int ASN1CALL ASN1Dec_BindRequest(ASN1decoding_t dec, ASN1uint32_t tag, BindRequest* val);
static int ASN1CALL ASN1Dec_SearchRequest(ASN1decoding_t dec, ASN1uint32_t tag, SearchRequest* val);
static int ASN1CALL ASN1Dec_LDAPMsg_protocolOp(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMsg_protocolOp* val);
static int ASN1CALL ASN1Dec_LDAPMsg(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMsg* val);
static int ASN1CALL ASN1Dec_LDAPMessage(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMessage* val);
static void ASN1CALL ASN1Free_PartialAttributeList_Seq_vals(PPartialAttributeList_Seq_vals* val);
static void ASN1CALL ASN1Free_AttributeList_Seq(AttributeList_Seq* val);
static void ASN1CALL ASN1Free_AttributeTypeAndValues_vals(PAttributeTypeAndValues_vals* val);
static void ASN1CALL ASN1Free_PartialAttributeList_Seq(PartialAttributeList_Seq* val);
static void ASN1CALL ASN1Free_MatchingRuleAssertion_matchingRules(PMatchingRuleAssertion_matchingRules* val);
static void ASN1CALL ASN1Free_SubstringFilterList_Seq(SubstringFilterList_Seq* val);
static void ASN1CALL ASN1Free_PartialAttribute_vals(PPartialAttribute_vals* val);
static void ASN1CALL ASN1Free_AttributeDescriptionList(PAttributeDescriptionList* val);
static void ASN1CALL ASN1Free_AttributeValueAssertion(AttributeValueAssertion* val);
static void ASN1CALL ASN1Free_PartialAttribute(PartialAttribute* val);
static void ASN1CALL ASN1Free_LDAPResult(LDAPResult* val);
static void ASN1CALL ASN1Free_Referral(PReferral* val);
static void ASN1CALL ASN1Free_Control(Control* val);
static void ASN1CALL ASN1Free_SaslCredentials(SaslCredentials* val);
static void ASN1CALL ASN1Free_SubstringFilter(SubstringFilter* val);
static void ASN1CALL ASN1Free_SubstringFilterList(PSubstringFilterList* val);
static void ASN1CALL ASN1Free_MatchingRuleAssertion(MatchingRuleAssertion* val);
static void ASN1CALL ASN1Free_SearchResultEntry(SearchResultEntry* val);
static void ASN1CALL ASN1Free_PartialAttributeList(PPartialAttributeList* val);
static void ASN1CALL ASN1Free_SearchResultReference(PSearchResultReference* val);
static void ASN1CALL ASN1Free_SearchResultDone(SearchResultDone* val);
static void ASN1CALL ASN1Free_ModifyRequest(ModifyRequest* val);
static void ASN1CALL ASN1Free_AttributeTypeAndValues(AttributeTypeAndValues* val);
static void ASN1CALL ASN1Free_ModifyResponse(ModifyResponse* val);
static void ASN1CALL ASN1Free_AddRequest(AddRequest* val);
static void ASN1CALL ASN1Free_AttributeList(PAttributeList* val);
static void ASN1CALL ASN1Free_AttributeVals(PAttributeVals* val);
static void ASN1CALL ASN1Free_AddResponse(AddResponse* val);
static void ASN1CALL ASN1Free_DelResponse(DelResponse* val);
static void ASN1CALL ASN1Free_ModifyDNRequest(ModifyDNRequest* val);
static void ASN1CALL ASN1Free_ModifyDNResponse(ModifyDNResponse* val);
static void ASN1CALL ASN1Free_CompareRequest(CompareRequest* val);
static void ASN1CALL ASN1Free_CompareResponse(CompareResponse* val);
static void ASN1CALL ASN1Free_ExtendedRequest(ExtendedRequest* val);
static void ASN1CALL ASN1Free_ExtendedResponse(ExtendedResponse* val);
static void ASN1CALL ASN1Free_ModificationList_Seq(ModificationList_Seq* val);
static void ASN1CALL ASN1Free_Controls(PControls* val);
static void ASN1CALL ASN1Free_AuthenticationChoice(AuthenticationChoice* val);
static void ASN1CALL ASN1Free_BindResponse(BindResponse* val);
static void ASN1CALL ASN1Free_Filter(Filter* val);
static void ASN1CALL ASN1Free_ModificationList(PModificationList* val);
static void ASN1CALL ASN1Free_Filter_or(PFilter_or* val);
static void ASN1CALL ASN1Free_Filter_and(PFilter_and* val);
static void ASN1CALL ASN1Free_BindRequest(BindRequest* val);
static void ASN1CALL ASN1Free_SearchRequest(SearchRequest* val);
static void ASN1CALL ASN1Free_LDAPMsg_protocolOp(LDAPMsg_protocolOp* val);
static void ASN1CALL ASN1Free_LDAPMsg(LDAPMsg* val);
static void ASN1CALL ASN1Free_LDAPMessage(LDAPMessage* val);

typedef ASN1BerEncFun_t ASN1EncFun_t;
static const ASN1EncFun_t encfntab[2] = {
    (ASN1EncFun_t)ASN1Enc_PartialAttribute,
    (ASN1EncFun_t)ASN1Enc_LDAPMessage,
};
typedef ASN1BerDecFun_t ASN1DecFun_t;
static const ASN1DecFun_t decfntab[2] = {
    (ASN1DecFun_t)ASN1Dec_PartialAttribute,
    (ASN1DecFun_t)ASN1Dec_LDAPMessage,
};
static const ASN1FreeFun_t freefntab[2] = {
    (ASN1FreeFun_t)ASN1Free_PartialAttribute,
    (ASN1FreeFun_t)ASN1Free_LDAPMessage,
};
static const ULONG sizetab[2] = {
    SIZE_LDAP_Module_PDU_0,
    SIZE_LDAP_Module_PDU_1,
};

ASN1bool_t Control_criticality_default = 0;
ASN1int32_t maxInt = 2147483647;

void ASN1CALL LDAP_Module_Startup() {
    LDAP_Module = ASN1_CreateModule(0x10000, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 2, (const ASN1GenericFun_t*)encfntab, (const ASN1GenericFun_t*)decfntab, freefntab, sizetab, 0x7061646c);
}

void ASN1CALL LDAP_Module_Cleanup() {
    ASN1_CloseModule(LDAP_Module);
    LDAP_Module = NULL;
}

static int ASN1CALL ASN1Enc_PartialAttributeList_Seq_vals(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttributeList_Seq_vals* val) {
    PPartialAttributeList_Seq_vals f;
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x11, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1DEREncOctetString(enc2, 0x4, (f->value).length, (f->value).value))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PartialAttributeList_Seq_vals(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttributeList_Seq_vals* val) {
    PPartialAttributeList_Seq_vals* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x11, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PPartialAttributeList_Seq_vals)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_PartialAttributeList_Seq_vals(PPartialAttributeList_Seq_vals* val) {
    PPartialAttributeList_Seq_vals f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AttributeList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, AttributeList_Seq* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1Enc_AttributeVals(enc, 0, &(val)->vals))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, AttributeList_Seq* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->type))
        return 0;
    if (!ASN1Dec_AttributeVals(dd, 0, &(val)->vals))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeList_Seq(AttributeList_Seq* val) {
    if (val) {
        ASN1octetstring_free(&(val)->type);
        ASN1Free_AttributeVals(&(val)->vals);
    }
}

static int ASN1CALL ASN1Enc_AttributeTypeAndValues_vals(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeTypeAndValues_vals* val) {
    PAttributeTypeAndValues_vals f;
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x11, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1DEREncOctetString(enc2, 0x4, (f->value).length, (f->value).value))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeTypeAndValues_vals(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeTypeAndValues_vals* val) {
    PAttributeTypeAndValues_vals* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x11, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PAttributeTypeAndValues_vals)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeTypeAndValues_vals(PAttributeTypeAndValues_vals* val) {
    PAttributeTypeAndValues_vals f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_PartialAttributeList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, PartialAttributeList_Seq* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1Enc_PartialAttributeList_Seq_vals(enc, 0, &(val)->vals))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PartialAttributeList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, PartialAttributeList_Seq* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->type))
        return 0;
    if (!ASN1Dec_PartialAttributeList_Seq_vals(dd, 0, &(val)->vals))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_PartialAttributeList_Seq(PartialAttributeList_Seq* val) {
    if (val) {
        ASN1octetstring_free(&(val)->type);
        ASN1Free_PartialAttributeList_Seq_vals(&(val)->vals);
    }
}

static int ASN1CALL ASN1Enc_MatchingRuleAssertion_matchingRules(ASN1encoding_t enc, ASN1uint32_t tag, PMatchingRuleAssertion_matchingRules* val) {
    PMatchingRuleAssertion_matchingRules f;
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000001, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1DEREncOctetString(enc2, 0x4, (f->value).length, (f->value).value))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_MatchingRuleAssertion_matchingRules(ASN1decoding_t dec, ASN1uint32_t tag, PMatchingRuleAssertion_matchingRules* val) {
    PMatchingRuleAssertion_matchingRules* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000001, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PMatchingRuleAssertion_matchingRules)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_MatchingRuleAssertion_matchingRules(PMatchingRuleAssertion_matchingRules* val) {
    PMatchingRuleAssertion_matchingRules f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_SubstringFilterList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, SubstringFilterList_Seq* val) {
    switch ((val)->choice) {
    case 1:
        if (!ASN1DEREncOctetString(enc, 0x80000000, ((val)->u.initial).length, ((val)->u.initial).value))
            return 0;
        break;
    case 2:
        if (!ASN1DEREncOctetString(enc, 0x80000001, ((val)->u.any).length, ((val)->u.any).value))
            return 0;
        break;
    case 3:
        if (!ASN1DEREncOctetString(enc, 0x80000002, ((val)->u.final).length, ((val)->u.final).value))
            return 0;
        break;
    default:
        ASN1EncSetError(enc, ASN1_ERR_CHOICE);
        return 0;
    }
    return 1;
}

static int ASN1CALL ASN1Dec_SubstringFilterList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, SubstringFilterList_Seq* val) {
    ASN1uint32_t t = 0;
    if (!ASN1BERDecPeekTag(dec, &t))
        return 0;
    switch (t) {
    case 0x80000000:
        (val)->choice = 1;
        if (!ASN1BERDecOctetString(dec, 0x80000000, &(val)->u.initial))
            return 0;
        break;
    case 0x80000001:
        (val)->choice = 2;
        if (!ASN1BERDecOctetString(dec, 0x80000001, &(val)->u.any))
            return 0;
        break;
    case 0x80000002:
        (val)->choice = 3;
        if (!ASN1BERDecOctetString(dec, 0x80000002, &(val)->u.final))
            return 0;
        break;
    default:
        ASN1DecSetError(dec, ASN1_ERR_CORRUPT);
        return 0;
    }
    return 1;
}

static void ASN1CALL ASN1Free_SubstringFilterList_Seq(SubstringFilterList_Seq* val) {
    if (val) {
        switch ((val)->choice) {
        case 1:
            ASN1octetstring_free(&(val)->u.initial);
            break;
        case 2:
            ASN1octetstring_free(&(val)->u.any);
            break;
        case 3:
            ASN1octetstring_free(&(val)->u.final);
            break;
        }
    }
}

static int ASN1CALL ASN1Enc_PartialAttribute_vals(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttribute_vals* val) {
    PPartialAttribute_vals f;
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x11, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1DEREncOctetString(enc2, 0x4, (f->value).length, (f->value).value))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PartialAttribute_vals(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttribute_vals* val) {
    PPartialAttribute_vals* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x11, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PPartialAttribute_vals)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_PartialAttribute_vals(PPartialAttribute_vals* val) {
    PPartialAttribute_vals f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AttributeDescriptionList(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeDescriptionList* val) {
    PAttributeDescriptionList f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncOctetString(enc, 0x4, (f->value).length, (f->value).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeDescriptionList(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeDescriptionList* val) {
    PAttributeDescriptionList* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PAttributeDescriptionList)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeDescriptionList(PAttributeDescriptionList* val) {
    PAttributeDescriptionList f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AttributeValueAssertion(ASN1encoding_t enc, ASN1uint32_t tag, AttributeValueAssertion* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->attributeType).length, ((val)->attributeType).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->assertionValue).length, ((val)->assertionValue).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeValueAssertion(ASN1decoding_t dec, ASN1uint32_t tag, AttributeValueAssertion* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->attributeType))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->assertionValue))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeValueAssertion(AttributeValueAssertion* val) {
    if (val) {
        ASN1octetstring_free(&(val)->attributeType);
        ASN1octetstring_free(&(val)->assertionValue);
    }
}

static int ASN1CALL ASN1Enc_PartialAttribute(ASN1encoding_t enc, ASN1uint32_t tag, PartialAttribute* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1Enc_PartialAttribute_vals(enc, 0, &(val)->vals))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PartialAttribute(ASN1decoding_t dec, ASN1uint32_t tag, PartialAttribute* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->type))
        return 0;
    if (!ASN1Dec_PartialAttribute_vals(dd, 0, &(val)->vals))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_PartialAttribute(PartialAttribute* val) {
    if (val) {
        ASN1octetstring_free(&(val)->type);
        ASN1Free_PartialAttribute_vals(&(val)->vals);
    }
}

static int ASN1CALL ASN1Enc_LDAPResult(ASN1encoding_t enc, ASN1uint32_t tag, LDAPResult* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->resultCode))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->matchedDN).length, ((val)->matchedDN).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->errorMessage).length, ((val)->errorMessage).value))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1Enc_Referral(enc, 0x80000003, &(val)->referral))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_LDAPResult(ASN1decoding_t dec, ASN1uint32_t tag, LDAPResult* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->resultCode))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->matchedDN))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->errorMessage))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x80;
        if (!ASN1Dec_Referral(dd, 0x80000003, &(val)->referral))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_LDAPResult(LDAPResult* val) {
    if (val) {
        ASN1octetstring_free(&(val)->matchedDN);
        ASN1octetstring_free(&(val)->errorMessage);
        if ((val)->o[0] & 0x80) {
            ASN1Free_Referral(&(val)->referral);
        }
    }
}

static int ASN1CALL ASN1Enc_Referral(ASN1encoding_t enc, ASN1uint32_t tag, PReferral* val) {
    PReferral f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncOctetString(enc, 0x4, (f->value).length, (f->value).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_Referral(ASN1decoding_t dec, ASN1uint32_t tag, PReferral* val) {
    PReferral* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PReferral)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_Referral(PReferral* val) {
    PReferral f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_Control(ASN1encoding_t enc, ASN1uint32_t tag, Control* val) {
    ASN1uint32_t nLenOff;
    ASN1octet_t o[1];
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    CopyMemory(o, (val)->o, 1);
    if (!(val)->criticality)
        o[0] &= ~0x80;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->controlType).length, ((val)->controlType).value))
        return 0;
    if (o[0] & 0x80) {
        if (!ASN1BEREncBool(enc, 0x1, (val)->criticality))
            return 0;
    }
    if (o[0] & 0x40) {
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->controlValue).length, ((val)->controlValue).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_Control(ASN1decoding_t dec, ASN1uint32_t tag, Control* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->controlType))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x1) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecBool(dd, 0x1, &(val)->criticality))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x4) {
        (val)->o[0] |= 0x40;
        if (!ASN1BERDecOctetString(dd, 0x4, &(val)->controlValue))
            return 0;
    }
    if (!((val)->o[0] & 0x80))
        (val)->criticality = 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_Control(Control* val) {
    if (val) {
        ASN1octetstring_free(&(val)->controlType);
        if ((val)->o[0] & 0x40) {
            ASN1octetstring_free(&(val)->controlValue);
        }
    }
}

static int ASN1CALL ASN1Enc_SaslCredentials(ASN1encoding_t enc, ASN1uint32_t tag, SaslCredentials* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->mechanism).length, ((val)->mechanism).value))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1DEREncOctetString(enc, 0x4, ((val)->credentials).length, ((val)->credentials).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SaslCredentials(ASN1decoding_t dec, ASN1uint32_t tag, SaslCredentials* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->mechanism))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x4) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecOctetString(dd, 0x4, &(val)->credentials))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SaslCredentials(SaslCredentials* val) {
    if (val) {
        ASN1octetstring_free(&(val)->mechanism);
        if ((val)->o[0] & 0x80) {
            ASN1octetstring_free(&(val)->credentials);
        }
    }
}

static int ASN1CALL ASN1Enc_SubstringFilter(ASN1encoding_t enc, ASN1uint32_t tag, SubstringFilter* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1Enc_SubstringFilterList(enc, 0, &(val)->substrings))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SubstringFilter(ASN1decoding_t dec, ASN1uint32_t tag, SubstringFilter* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->type))
        return 0;
    if (!ASN1Dec_SubstringFilterList(dd, 0, &(val)->substrings))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SubstringFilter(SubstringFilter* val) {
    if (val) {
        ASN1octetstring_free(&(val)->type);
        ASN1Free_SubstringFilterList(&(val)->substrings);
    }
}

static int ASN1CALL ASN1Enc_SubstringFilterList(ASN1encoding_t enc, ASN1uint32_t tag, PSubstringFilterList* val) {
    PSubstringFilterList f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_SubstringFilterList_Seq(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SubstringFilterList(ASN1decoding_t dec, ASN1uint32_t tag, PSubstringFilterList* val) {
    PSubstringFilterList* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PSubstringFilterList)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_SubstringFilterList_Seq(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SubstringFilterList(PSubstringFilterList* val) {
    PSubstringFilterList f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_SubstringFilterList_Seq(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_MatchingRuleAssertion(ASN1encoding_t enc, ASN1uint32_t tag, MatchingRuleAssertion* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1Enc_MatchingRuleAssertion_matchingRules(enc, 0, &(val)->matchingRules))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x80000002, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x80000003, ((val)->matchValue).length, ((val)->matchValue).value))
        return 0;
    if (!ASN1BEREncBool(enc, 0x80000004, (val)->dnAttributes))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_MatchingRuleAssertion(ASN1decoding_t dec, ASN1uint32_t tag, MatchingRuleAssertion* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1Dec_MatchingRuleAssertion_matchingRules(dd, 0, &(val)->matchingRules))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x80000002, &(val)->type))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x80000003, &(val)->matchValue))
        return 0;
    if (!ASN1BERDecBool(dd, 0x80000004, &(val)->dnAttributes))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_MatchingRuleAssertion(MatchingRuleAssertion* val) {
    if (val) {
        ASN1Free_MatchingRuleAssertion_matchingRules(&(val)->matchingRules);
        ASN1octetstring_free(&(val)->type);
        ASN1octetstring_free(&(val)->matchValue);
    }
}

static int ASN1CALL ASN1Enc_SearchResultEntry(ASN1encoding_t enc, ASN1uint32_t tag, SearchResultEntry* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000004, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->objectName).length, ((val)->objectName).value))
        return 0;
    if (!ASN1Enc_PartialAttributeList(enc, 0, &(val)->attributes))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SearchResultEntry(ASN1decoding_t dec, ASN1uint32_t tag, SearchResultEntry* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000004, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->objectName))
        return 0;
    if (!ASN1Dec_PartialAttributeList(dd, 0, &(val)->attributes))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SearchResultEntry(SearchResultEntry* val) {
    if (val) {
        ASN1octetstring_free(&(val)->objectName);
        ASN1Free_PartialAttributeList(&(val)->attributes);
    }
}

static int ASN1CALL ASN1Enc_PartialAttributeList(ASN1encoding_t enc, ASN1uint32_t tag, PPartialAttributeList* val) {
    PPartialAttributeList f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_PartialAttributeList_Seq(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PartialAttributeList(ASN1decoding_t dec, ASN1uint32_t tag, PPartialAttributeList* val) {
    PPartialAttributeList* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PPartialAttributeList)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_PartialAttributeList_Seq(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_PartialAttributeList(PPartialAttributeList* val) {
    PPartialAttributeList f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_PartialAttributeList_Seq(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_SearchResultReference(ASN1encoding_t enc, ASN1uint32_t tag, PSearchResultReference* val) {
    PSearchResultReference f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000013, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncOctetString(enc, 0x4, (f->value).length, (f->value).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SearchResultReference(ASN1decoding_t dec, ASN1uint32_t tag, PSearchResultReference* val) {
    PSearchResultReference* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000013, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PSearchResultReference)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SearchResultReference(PSearchResultReference* val) {
    PSearchResultReference f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_SearchResultDone(ASN1encoding_t enc, ASN1uint32_t tag, SearchResultDone* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x40000005, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SearchResultDone(ASN1decoding_t dec, ASN1uint32_t tag, SearchResultDone* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x40000005, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SearchResultDone(SearchResultDone* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_ModifyRequest(ASN1encoding_t enc, ASN1uint32_t tag, ModifyRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000006, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->object).length, ((val)->object).value))
        return 0;
    if (!ASN1Enc_ModificationList(enc, 0, &(val)->changes))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModifyRequest(ASN1decoding_t dec, ASN1uint32_t tag, ModifyRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000006, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->object))
        return 0;
    if (!ASN1Dec_ModificationList(dd, 0, &(val)->changes))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModifyRequest(ModifyRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->object);
        ASN1Free_ModificationList(&(val)->changes);
    }
}

static int ASN1CALL ASN1Enc_AttributeTypeAndValues(ASN1encoding_t enc, ASN1uint32_t tag, AttributeTypeAndValues* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->type).length, ((val)->type).value))
        return 0;
    if (!ASN1Enc_AttributeTypeAndValues_vals(enc, 0, &(val)->vals))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeTypeAndValues(ASN1decoding_t dec, ASN1uint32_t tag, AttributeTypeAndValues* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->type))
        return 0;
    if (!ASN1Dec_AttributeTypeAndValues_vals(dd, 0, &(val)->vals))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeTypeAndValues(AttributeTypeAndValues* val) {
    if (val) {
        ASN1octetstring_free(&(val)->type);
        ASN1Free_AttributeTypeAndValues_vals(&(val)->vals);
    }
}

static int ASN1CALL ASN1Enc_ModifyResponse(ASN1encoding_t enc, ASN1uint32_t tag, ModifyResponse* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x40000007, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModifyResponse(ASN1decoding_t dec, ASN1uint32_t tag, ModifyResponse* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x40000007, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModifyResponse(ModifyResponse* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_AddRequest(ASN1encoding_t enc, ASN1uint32_t tag, AddRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000008, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->entry).length, ((val)->entry).value))
        return 0;
    if (!ASN1Enc_AttributeList(enc, 0, &(val)->attributes))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AddRequest(ASN1decoding_t dec, ASN1uint32_t tag, AddRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000008, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->entry))
        return 0;
    if (!ASN1Dec_AttributeList(dd, 0, &(val)->attributes))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AddRequest(AddRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->entry);
        ASN1Free_AttributeList(&(val)->attributes);
    }
}

static int ASN1CALL ASN1Enc_AttributeList(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeList* val) {
    PAttributeList f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_AttributeList_Seq(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeList(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeList* val) {
    PAttributeList* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PAttributeList)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_AttributeList_Seq(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeList(PAttributeList* val) {
    PAttributeList f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_AttributeList_Seq(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AttributeVals(ASN1encoding_t enc, ASN1uint32_t tag, PAttributeVals* val) {
    PAttributeVals f;
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x11, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1DEREncOctetString(enc2, 0x4, (f->value).length, (f->value).value))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AttributeVals(ASN1decoding_t dec, ASN1uint32_t tag, PAttributeVals* val) {
    PAttributeVals* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x11, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PAttributeVals)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1BERDecOctetString(dd, 0x4, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AttributeVals(PAttributeVals* val) {
    PAttributeVals f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1octetstring_free(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AddResponse(ASN1encoding_t enc, ASN1uint32_t tag, AddResponse* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x40000009, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_AddResponse(ASN1decoding_t dec, ASN1uint32_t tag, AddResponse* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x40000009, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_AddResponse(AddResponse* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_DelResponse(ASN1encoding_t enc, ASN1uint32_t tag, DelResponse* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x4000000b, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_DelResponse(ASN1decoding_t dec, ASN1uint32_t tag, DelResponse* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x4000000b, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_DelResponse(DelResponse* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_ModifyDNRequest(ASN1encoding_t enc, ASN1uint32_t tag, ModifyDNRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x4000000c, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->entry).length, ((val)->entry).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->newrdn).length, ((val)->newrdn).value))
        return 0;
    if (!ASN1BEREncBool(enc, 0x1, (val)->deleteoldrdn))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1DEREncOctetString(enc, 0x80000000, ((val)->newSuperior).length, ((val)->newSuperior).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModifyDNRequest(ASN1decoding_t dec, ASN1uint32_t tag, ModifyDNRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x4000000c, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->entry))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->newrdn))
        return 0;
    if (!ASN1BERDecBool(dd, 0x1, &(val)->deleteoldrdn))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000000) {
        (val)->o[0] |= 0x80;
        if (!ASN1BERDecOctetString(dd, 0x80000000, &(val)->newSuperior))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModifyDNRequest(ModifyDNRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->entry);
        ASN1octetstring_free(&(val)->newrdn);
        if ((val)->o[0] & 0x80) {
            ASN1octetstring_free(&(val)->newSuperior);
        }
    }
}

static int ASN1CALL ASN1Enc_ModifyDNResponse(ASN1encoding_t enc, ASN1uint32_t tag, ModifyDNResponse* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x4000000d, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModifyDNResponse(ASN1decoding_t dec, ASN1uint32_t tag, ModifyDNResponse* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x4000000d, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModifyDNResponse(ModifyDNResponse* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_CompareRequest(ASN1encoding_t enc, ASN1uint32_t tag, CompareRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x4000000e, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->entry).length, ((val)->entry).value))
        return 0;
    if (!ASN1Enc_AttributeValueAssertion(enc, 0, &(val)->ava))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_CompareRequest(ASN1decoding_t dec, ASN1uint32_t tag, CompareRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x4000000e, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->entry))
        return 0;
    if (!ASN1Dec_AttributeValueAssertion(dd, 0, &(val)->ava))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_CompareRequest(CompareRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->entry);
        ASN1Free_AttributeValueAssertion(&(val)->ava);
    }
}

static int ASN1CALL ASN1Enc_CompareResponse(ASN1encoding_t enc, ASN1uint32_t tag, CompareResponse* val) {
    if (!ASN1Enc_LDAPResult(enc, tag ? tag : 0x4000000f, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_CompareResponse(ASN1decoding_t dec, ASN1uint32_t tag, CompareResponse* val) {
    if (!ASN1Dec_LDAPResult(dec, tag ? tag : 0x4000000f, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_CompareResponse(CompareResponse* val) {
    if (val) {
        ASN1Free_LDAPResult(val);
    }
}

static int ASN1CALL ASN1Enc_ExtendedRequest(ASN1encoding_t enc, ASN1uint32_t tag, ExtendedRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000017, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x80000000, ((val)->requestName).length, ((val)->requestName).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x80000001, ((val)->requestValue).length, ((val)->requestValue).value))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ExtendedRequest(ASN1decoding_t dec, ASN1uint32_t tag, ExtendedRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000017, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x80000000, &(val)->requestName))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x80000001, &(val)->requestValue))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ExtendedRequest(ExtendedRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->requestName);
        ASN1octetstring_free(&(val)->requestValue);
    }
}

static int ASN1CALL ASN1Enc_ExtendedResponse(ASN1encoding_t enc, ASN1uint32_t tag, ExtendedResponse* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000018, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->resultCode))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->matchedDN).length, ((val)->matchedDN).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->errorMessage).length, ((val)->errorMessage).value))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1Enc_Referral(enc, 0x80000003, &(val)->referral))
            return 0;
    }
    if ((val)->o[0] & 0x40) {
        if (!ASN1DEREncOctetString(enc, 0x8000000a, ((val)->responseName).length, ((val)->responseName).value))
            return 0;
    }
    if ((val)->o[0] & 0x20) {
        if (!ASN1DEREncOctetString(enc, 0x8000000b, ((val)->response).length, ((val)->response).value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ExtendedResponse(ASN1decoding_t dec, ASN1uint32_t tag, ExtendedResponse* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000018, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->resultCode))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->matchedDN))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->errorMessage))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x80;
        if (!ASN1Dec_Referral(dd, 0x80000003, &(val)->referral))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x8000000a) {
        (val)->o[0] |= 0x40;
        if (!ASN1BERDecOctetString(dd, 0x8000000a, &(val)->responseName))
            return 0;
    }
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x8000000b) {
        (val)->o[0] |= 0x20;
        if (!ASN1BERDecOctetString(dd, 0x8000000b, &(val)->response))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ExtendedResponse(ExtendedResponse* val) {
    if (val) {
        ASN1octetstring_free(&(val)->matchedDN);
        ASN1octetstring_free(&(val)->errorMessage);
        if ((val)->o[0] & 0x80) {
            ASN1Free_Referral(&(val)->referral);
        }
        if ((val)->o[0] & 0x40) {
            ASN1octetstring_free(&(val)->responseName);
        }
        if ((val)->o[0] & 0x20) {
            ASN1octetstring_free(&(val)->response);
        }
    }
}

static int ASN1CALL ASN1Enc_ModificationList_Seq(ASN1encoding_t enc, ASN1uint32_t tag, ModificationList_Seq* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->operation))
        return 0;
    if (!ASN1Enc_AttributeTypeAndValues(enc, 0, &(val)->modification))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModificationList_Seq(ASN1decoding_t dec, ASN1uint32_t tag, ModificationList_Seq* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->operation))
        return 0;
    if (!ASN1Dec_AttributeTypeAndValues(dd, 0, &(val)->modification))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModificationList_Seq(ModificationList_Seq* val) {
    if (val) {
        ASN1Free_AttributeTypeAndValues(&(val)->modification);
    }
}

static int ASN1CALL ASN1Enc_Controls(ASN1encoding_t enc, ASN1uint32_t tag, PControls* val) {
    PControls f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_Control(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_Controls(ASN1decoding_t dec, ASN1uint32_t tag, PControls* val) {
    PControls* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PControls)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_Control(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_Controls(PControls* val) {
    PControls f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_Control(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_AuthenticationChoice(ASN1encoding_t enc, ASN1uint32_t tag, AuthenticationChoice* val) {
    switch ((val)->choice) {
    case 1:
        if (!ASN1DEREncOctetString(enc, 0x80000000, ((val)->u.simple).length, ((val)->u.simple).value))
            return 0;
        break;
    case 2:
        if (!ASN1Enc_SaslCredentials(enc, 0x80000003, &(val)->u.sasl))
            return 0;
        break;
    case 3:
        if (!ASN1DEREncOctetString(enc, 0x80000009, ((val)->u.sicilyNegotiate).length, ((val)->u.sicilyNegotiate).value))
            return 0;
        break;
    case 4:
        if (!ASN1DEREncOctetString(enc, 0x8000000a, ((val)->u.sicilyInitial).length, ((val)->u.sicilyInitial).value))
            return 0;
        break;
    case 5:
        if (!ASN1DEREncOctetString(enc, 0x8000000b, ((val)->u.sicilySubsequent).length, ((val)->u.sicilySubsequent).value))
            return 0;
        break;
    default:
        ASN1EncSetError(enc, ASN1_ERR_CHOICE);
        return 0;
    }
    return 1;
}

static int ASN1CALL ASN1Dec_AuthenticationChoice(ASN1decoding_t dec, ASN1uint32_t tag, AuthenticationChoice* val) {
    ASN1uint32_t t = 0;
    if (!ASN1BERDecPeekTag(dec, &t))
        return 0;
    switch (t) {
    case 0x80000000:
        (val)->choice = 1;
        if (!ASN1BERDecOctetString(dec, 0x80000000, &(val)->u.simple))
            return 0;
        break;
    case 0x80000003:
        (val)->choice = 2;
        if (!ASN1Dec_SaslCredentials(dec, 0x80000003, &(val)->u.sasl))
            return 0;
        break;
    case 0x80000009:
        (val)->choice = 3;
        if (!ASN1BERDecOctetString(dec, 0x80000009, &(val)->u.sicilyNegotiate))
            return 0;
        break;
    case 0x8000000a:
        (val)->choice = 4;
        if (!ASN1BERDecOctetString(dec, 0x8000000a, &(val)->u.sicilyInitial))
            return 0;
        break;
    case 0x8000000b:
        (val)->choice = 5;
        if (!ASN1BERDecOctetString(dec, 0x8000000b, &(val)->u.sicilySubsequent))
            return 0;
        break;
    default:
        ASN1DecSetError(dec, ASN1_ERR_CORRUPT);
        return 0;
    }
    return 1;
}

static void ASN1CALL ASN1Free_AuthenticationChoice(AuthenticationChoice* val) {
    if (val) {
        switch ((val)->choice) {
        case 1:
            ASN1octetstring_free(&(val)->u.simple);
            break;
        case 2:
            ASN1Free_SaslCredentials(&(val)->u.sasl);
            break;
        case 3:
            ASN1octetstring_free(&(val)->u.sicilyNegotiate);
            break;
        case 4:
            ASN1octetstring_free(&(val)->u.sicilyInitial);
            break;
        case 5:
            ASN1octetstring_free(&(val)->u.sicilySubsequent);
            break;
        }
    }
}

static int ASN1CALL ASN1Enc_BindResponse(ASN1encoding_t enc, ASN1uint32_t tag, BindResponse* val) {
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000001, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->resultCode))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->matchedDN).length, ((val)->matchedDN).value))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->errorMessage).length, ((val)->errorMessage).value))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1Enc_Referral(enc, 0x80000003, &(val)->referral))
            return 0;
    }
    if (!ASN1BEREncExplicitTag(enc, 0x80000007, &nLenOff0))
        return 0;
    if (!ASN1Enc_AuthenticationChoice(enc, 0, &(val)->serverCreds))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff0))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_BindResponse(ASN1decoding_t dec, ASN1uint32_t tag, BindResponse* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    ASN1decoding_t dd0 = 0;
    ASN1octet_t* di0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000001, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->resultCode))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->matchedDN))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->errorMessage))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x80;
        if (!ASN1Dec_Referral(dd, 0x80000003, &(val)->referral))
            return 0;
    }
    if (!ASN1BERDecExplicitTag(dd, 0x80000007, &dd0, &di0))
        return 0;
    if (!ASN1Dec_AuthenticationChoice(dd0, 0, &(val)->serverCreds))
        return 0;
    if (!ASN1BERDecEndOfContents(dd, dd0, di0))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_BindResponse(BindResponse* val) {
    if (val) {
        ASN1octetstring_free(&(val)->matchedDN);
        ASN1octetstring_free(&(val)->errorMessage);
        if ((val)->o[0] & 0x80) {
            ASN1Free_Referral(&(val)->referral);
        }
        ASN1Free_AuthenticationChoice(&(val)->serverCreds);
    }
}

static int ASN1CALL ASN1Enc_Filter(ASN1encoding_t enc, ASN1uint32_t tag, Filter* val) {
    switch ((val)->choice) {
    case 1:
        if (!ASN1Enc_Filter_and(enc, 0, &(val)->u.and))
            return 0;
        break;
    case 2:
        if (!ASN1Enc_Filter_or(enc, 0, &(val)->u.or))
            return 0;
        break;
    case 3:
        if (!ASN1Enc_Filter(enc, 0, (Filter*)&(val)->u.not ))
            return 0;
        break;
    case 4:
        if (!ASN1Enc_AttributeValueAssertion(enc, 0x80000003, &(val)->u.equalityMatch))
            return 0;
        break;
    case 5:
        if (!ASN1Enc_SubstringFilter(enc, 0x80000004, &(val)->u.substrings))
            return 0;
        break;
    case 6:
        if (!ASN1Enc_AttributeValueAssertion(enc, 0x80000005, &(val)->u.greaterOrEqual))
            return 0;
        break;
    case 7:
        if (!ASN1Enc_AttributeValueAssertion(enc, 0x80000006, &(val)->u.lessOrEqual))
            return 0;
        break;
    case 8:
        if (!ASN1DEREncOctetString(enc, 0x80000007, ((val)->u.present).length, ((val)->u.present).value))
            return 0;
        break;
    case 9:
        if (!ASN1Enc_AttributeValueAssertion(enc, 0x80000008, &(val)->u.approxMatch))
            return 0;
        break;
    case 10:
        if (!ASN1Enc_MatchingRuleAssertion(enc, 0x80000009, &(val)->u.extensibleMatch))
            return 0;
        break;
    default:
        ASN1EncSetError(enc, ASN1_ERR_CHOICE);
        return 0;
    }
    return 1;
}

static int ASN1CALL ASN1Dec_Filter(ASN1decoding_t dec, ASN1uint32_t tag, Filter* val) {
    ASN1uint32_t t = 0;
    if (!ASN1BERDecPeekTag(dec, &t))
        return 0;
    switch (t) {
    case 0x80000000:
        (val)->choice = 1;
        if (!ASN1Dec_Filter_and(dec, 0, &(val)->u.and))
            return 0;
        break;
    case 0x80000001:
        (val)->choice = 2;
        if (!ASN1Dec_Filter_or(dec, 0, &(val)->u.or))
            return 0;
        break;
    case 0x80000002:
        (val)->choice = 3;
        if (!ASN1Dec_Filter(dec, 0, (Filter*)&(val)->u.not ))
            return 0;
        break;
    case 0x80000003:
        (val)->choice = 3;
        if (!ASN1Dec_AttributeValueAssertion(dec, 0x80000003, &(val)->u.equalityMatch))
            return 0;
        break;
    case 0x80000004:
        (val)->choice = 4;
        if (!ASN1Dec_SubstringFilter(dec, 0x80000004, &(val)->u.substrings))
            return 0;
        break;
    case 0x80000005:
        (val)->choice = 5;
        if (!ASN1Dec_AttributeValueAssertion(dec, 0x80000005, &(val)->u.greaterOrEqual))
            return 0;
        break;
    case 0x80000006:
        (val)->choice = 6;
        if (!ASN1Dec_AttributeValueAssertion(dec, 0x80000006, &(val)->u.lessOrEqual))
            return 0;
        break;
    case 0x80000007:
        (val)->choice = 7;
        if (!ASN1BERDecOctetString(dec, 0x80000007, &(val)->u.present))
            return 0;
        break;
    case 0x80000008:
        (val)->choice = 8;
        if (!ASN1Dec_AttributeValueAssertion(dec, 0x80000008, &(val)->u.approxMatch))
            return 0;
        break;
    case 0x80000009:
        (val)->choice = 9;
        if (!ASN1Dec_MatchingRuleAssertion(dec, 0x80000009, &(val)->u.extensibleMatch))
            return 0;
        break;
    default:
        ASN1DecSetError(dec, ASN1_ERR_CORRUPT);
        return 0;
    }
    return 1;
}

static void ASN1CALL ASN1Free_Filter(Filter* val) {
    if (val) {
        switch ((val)->choice) {
        case 1:
            ASN1Free_Filter_and(&(val)->u.and);
            break;
        case 2:
            ASN1Free_Filter_or(&(val)->u.or);
            break;
        case 3:
            ASN1Free_AttributeValueAssertion(&(val)->u.equalityMatch);
            break;
        case 4:
            ASN1Free_SubstringFilter(&(val)->u.substrings);
            break;
        case 5:
            ASN1Free_AttributeValueAssertion(&(val)->u.greaterOrEqual);
            break;
        case 6:
            ASN1Free_AttributeValueAssertion(&(val)->u.lessOrEqual);
            break;
        case 7:
            ASN1octetstring_free(&(val)->u.present);
            break;
        case 8:
            ASN1Free_AttributeValueAssertion(&(val)->u.approxMatch);
            break;
        case 9:
            ASN1Free_MatchingRuleAssertion(&(val)->u.extensibleMatch);
            break;
        }
    }
}

static int ASN1CALL ASN1Enc_ModificationList(ASN1encoding_t enc, ASN1uint32_t tag, PModificationList* val) {
    PModificationList f;
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_ModificationList_Seq(enc, 0, &f->value))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_ModificationList(ASN1decoding_t dec, ASN1uint32_t tag, PModificationList* val) {
    PModificationList* f;
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    f = val;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!(*f = (PModificationList)ASN1DecAlloc(dd, sizeof(**f))))
            return 0;
        if (!ASN1Dec_ModificationList_Seq(dd, 0, &(*f)->value))
            return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_ModificationList(PModificationList* val) {
    PModificationList f = 0, ff = 0;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_ModificationList_Seq(&f->value);
            ff = f->next;
            ASN1Free(f);
        }
    }
}

static int ASN1CALL ASN1Enc_Filter_or(ASN1encoding_t enc, ASN1uint32_t tag, PFilter_or* val) {
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1uint32_t i;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000001, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (i = 0; i < (*val)->count; i++) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1Enc_Filter(enc2, 0, &((&(*val)->value)[i])))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_Filter_or(ASN1decoding_t dec, ASN1uint32_t tag, PFilter_or* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000001, &dd, &di))
        return 0;
    (*val)->count = 0;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!ASN1Dec_Filter(dd, 0, &((&(*val)->value)[(*val)->count])))
            return 0;
        ((*val)->count)++;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_Filter_or(PFilter_or* val) {
    ASN1uint32_t i;
    if (val) {
        for (i = 0; i < (*val)->count; i++) {
            ASN1Free_Filter(&((&(*val)->value)[i]));
        }
    }
}

static int ASN1CALL ASN1Enc_Filter_and(ASN1encoding_t enc, ASN1uint32_t tag, PFilter_and* val) {
    ASN1uint32_t nLenOff;
    void* pBlk;
    ASN1uint32_t i;
    ASN1encoding_t enc2 = 0;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000000, &nLenOff))
        return 0;
    if (!ASN1DEREncBeginBlk(enc, ASN1_DER_SET_OF_BLOCK, &pBlk))
        return 0;
    for (i = 0; i < (*val)->count; i++) {
        if (!ASN1DEREncNewBlkElement(pBlk, &enc2))
            return 0;
        if (!ASN1Enc_Filter(enc2, 0, &(&(*val)->value)[i]))
            return 0;
        if (!ASN1DEREncFlushBlkElement(pBlk))
            return 0;
    }
    if (!ASN1DEREncEndBlk(pBlk))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_Filter_and(ASN1decoding_t dec, ASN1uint32_t tag, PFilter_and* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000000, &dd, &di))
        return 0;
    (*val)->count = 0;
    while (ASN1BERDecNotEndOfContents(dd, di)) {
        if (!ASN1BERDecPeekTag(dd, &t))
            return 0;
        if (!ASN1Dec_Filter(dd, 0, &(&(*val)->value)[(*val)->count]))
            return 0;
        ((*val)->count)++;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_Filter_and(PFilter_and* val) {
    ASN1uint32_t i;
    if (val) {
        for (i = 0; i < (*val)->count; i++) {
            ASN1Free_Filter(&((&(*val)->value)[i]));
        }
    }
}

static int ASN1CALL ASN1Enc_BindRequest(ASN1encoding_t enc, ASN1uint32_t tag, BindRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000000, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0x2, (val)->version))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->name).length, ((val)->name).value))
        return 0;
    if (!ASN1Enc_AuthenticationChoice(enc, 0, &(val)->authentication))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_BindRequest(ASN1decoding_t dec, ASN1uint32_t tag, BindRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000000, &dd, &di))
        return 0;
    if (!ASN1BERDecU16Val(dd, 0x2, &(val)->version))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->name))
        return 0;
    if (!ASN1Dec_AuthenticationChoice(dd, 0, &(val)->authentication))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_BindRequest(BindRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->name);
        ASN1Free_AuthenticationChoice(&(val)->authentication);
    }
}

static int ASN1CALL ASN1Enc_SearchRequest(ASN1encoding_t enc, ASN1uint32_t tag, SearchRequest* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000003, &nLenOff))
        return 0;
    if (!ASN1DEREncOctetString(enc, 0x4, ((val)->baseObject).length, ((val)->baseObject).value))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->scope))
        return 0;
    if (!ASN1BEREncU32(enc, 0xa, (val)->derefAliases))
        return 0;
    if (!ASN1BEREncU32(enc, 0x2, (val)->sizeLimit))
        return 0;
    if (!ASN1BEREncU32(enc, 0x2, (val)->timeLimit))
        return 0;
    if (!ASN1BEREncBool(enc, 0x1, (val)->typesOnly))
        return 0;
    if (!ASN1Enc_Filter(enc, 0, &(val)->filter))
        return 0;
    if (!ASN1Enc_AttributeDescriptionList(enc, 0, &(val)->attributes))
        return 0;
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_SearchRequest(ASN1decoding_t dec, ASN1uint32_t tag, SearchRequest* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000003, &dd, &di))
        return 0;
    if (!ASN1BERDecOctetString(dd, 0x4, &(val)->baseObject))
        return 0;
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->scope))
        return 0;
    if (!ASN1BERDecU32Val(dd, 0xa, (ASN1uint32_t*)&(val)->derefAliases))
        return 0;
    if (!ASN1BERDecU32Val(dd, 0x2, (ASN1uint32_t*)&(val)->sizeLimit))
        return 0;
    if (!ASN1BERDecU32Val(dd, 0x2, (ASN1uint32_t*)&(val)->timeLimit))
        return 0;
    if (!ASN1BERDecBool(dd, 0x1, &(val)->typesOnly))
        return 0;
    if (!ASN1Dec_Filter(dd, 0, &(val)->filter))
        return 0;
    if (!ASN1Dec_AttributeDescriptionList(dd, 0, &(val)->attributes))
        return 0;
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_SearchRequest(SearchRequest* val) {
    if (val) {
        ASN1octetstring_free(&(val)->baseObject);
        ASN1Free_Filter(&(val)->filter);
        ASN1Free_AttributeDescriptionList(&(val)->attributes);
    }
}

static int ASN1CALL ASN1Enc_LDAPMsg_protocolOp(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMsg_protocolOp* val) {
    switch ((val)->choice) {
    case 1:
        if (!ASN1Enc_BindRequest(enc, 0, &(val)->u.bindRequest))
            return 0;
        break;
    case 2:
        if (!ASN1Enc_BindResponse(enc, 0, &(val)->u.bindResponse))
            return 0;
        break;
    case 3:
        if (!ASN1BEREncNull(enc, 0x40000002))
            return 0;
        break;
    case 4:
        if (!ASN1Enc_SearchRequest(enc, 0, &(val)->u.searchRequest))
            return 0;
        break;
    case 5:
        if (!ASN1Enc_SearchResultEntry(enc, 0, &(val)->u.searchResEntry))
            return 0;
        break;
    case 6:
        if (!ASN1Enc_SearchResultDone(enc, 0, &(val)->u.searchResDone))
            return 0;
        break;
    case 7:
        if (!ASN1Enc_ModifyRequest(enc, 0, &(val)->u.modifyRequest))
            return 0;
        break;
    case 8:
        if (!ASN1Enc_ModifyResponse(enc, 0, &(val)->u.modifyResponse))
            return 0;
        break;
    case 9:
        if (!ASN1Enc_AddRequest(enc, 0, &(val)->u.addRequest))
            return 0;
        break;
    case 10:
        if (!ASN1Enc_AddResponse(enc, 0, &(val)->u.addResponse))
            return 0;
        break;
    case 11:
        if (!ASN1DEREncOctetString(enc, 0x4000000a, ((val)->u.delRequest).length, ((val)->u.delRequest).value))
            return 0;
        break;
    case 12:
        if (!ASN1Enc_DelResponse(enc, 0, &(val)->u.delResponse))
            return 0;
        break;
    case 13:
        if (!ASN1Enc_ModifyDNRequest(enc, 0, &(val)->u.modDNRequest))
            return 0;
        break;
    case 14:
        if (!ASN1Enc_ModifyDNResponse(enc, 0, &(val)->u.modDNResponse))
            return 0;
        break;
    case 15:
        if (!ASN1Enc_CompareRequest(enc, 0, &(val)->u.compareRequest))
            return 0;
        break;
    case 16:
        if (!ASN1Enc_CompareResponse(enc, 0, &(val)->u.compareResponse))
            return 0;
        break;
    case 17:
        if (!ASN1BEREncU32(enc, 0x40000010, (val)->u.abandonRequest))
            return 0;
        break;
    case 18:
        if (!ASN1Enc_SearchResultReference(enc, 0, &(val)->u.searchResRef))
            return 0;
        break;
    case 19:
        if (!ASN1Enc_ExtendedRequest(enc, 0, &(val)->u.extendedReq))
            return 0;
        break;
    case 20:
        if (!ASN1Enc_ExtendedResponse(enc, 0, &(val)->u.extendedResp))
            return 0;
        break;
    default:
        ASN1EncSetError(enc, ASN1_ERR_CHOICE);
        return 0;
    }
    return 1;
}

static int ASN1CALL ASN1Dec_LDAPMsg_protocolOp(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMsg_protocolOp* val) {
    ASN1uint32_t t = 0;
    if (!ASN1BERDecPeekTag(dec, &t))
        return 0;
    switch (t) {
    case 0x40000000:
        (val)->choice = 1;
        if (!ASN1Dec_BindRequest(dec, 0, &(val)->u.bindRequest))
            return 0;
        break;
    case 0x40000001:
        (val)->choice = 2;
        if (!ASN1Dec_BindResponse(dec, 0, &(val)->u.bindResponse))
            return 0;
        break;
    case 0x40000002:
        (val)->choice = 3;
        if (!ASN1BERDecNull(dec, 0x40000002))
            return 0;
        break;
    case 0x40000003:
        (val)->choice = 4;
        if (!ASN1Dec_SearchRequest(dec, 0, &(val)->u.searchRequest))
            return 0;
        break;
    case 0x40000004:
        (val)->choice = 5;
        if (!ASN1Dec_SearchResultEntry(dec, 0, &(val)->u.searchResEntry))
            return 0;
        break;
    case 0x40000005:
        (val)->choice = 6;
        if (!ASN1Dec_SearchResultDone(dec, 0, &(val)->u.searchResDone))
            return 0;
        break;
    case 0x40000006:
        (val)->choice = 7;
        if (!ASN1Dec_ModifyRequest(dec, 0, &(val)->u.modifyRequest))
            return 0;
        break;
    case 0x40000007:
        (val)->choice = 8;
        if (!ASN1Dec_ModifyResponse(dec, 0, &(val)->u.modifyResponse))
            return 0;
        break;
    case 0x40000008:
        (val)->choice = 9;
        if (!ASN1Dec_AddRequest(dec, 0, &(val)->u.addRequest))
            return 0;
        break;
    case 0x40000009:
        (val)->choice = 10;
        if (!ASN1Dec_AddResponse(dec, 0, &(val)->u.addResponse))
            return 0;
        break;
    case 0x4000000a:
        (val)->choice = 11;
        if (!ASN1BERDecOctetString(dec, 0x4000000a, &(val)->u.delRequest))
            return 0;
        break;
    case 0x4000000b:
        (val)->choice = 12;
        if (!ASN1Dec_DelResponse(dec, 0, &(val)->u.delResponse))
            return 0;
        break;
    case 0x4000000c:
        (val)->choice = 13;
        if (!ASN1Dec_ModifyDNRequest(dec, 0, &(val)->u.modDNRequest))
            return 0;
        break;
    case 0x4000000d:
        (val)->choice = 14;
        if (!ASN1Dec_ModifyDNResponse(dec, 0, &(val)->u.modDNResponse))
            return 0;
        break;
    case 0x4000000e:
        (val)->choice = 15;
        if (!ASN1Dec_CompareRequest(dec, 0, &(val)->u.compareRequest))
            return 0;
        break;
    case 0x4000000f:
        (val)->choice = 16;
        if (!ASN1Dec_CompareResponse(dec, 0, &(val)->u.compareResponse))
            return 0;
        break;
    case 0x40000010:
        (val)->choice = 17;
        if (!ASN1BERDecU32Val(dec, 0x40000010, (ASN1uint32_t*)&(val)->u.abandonRequest))
            return 0;
        break;
    case 0x40000013:
        (val)->choice = 18;
        if (!ASN1Dec_SearchResultReference(dec, 0, &(val)->u.searchResRef))
            return 0;
        break;
    case 0x40000017:
        (val)->choice = 19;
        if (!ASN1Dec_ExtendedRequest(dec, 0, &(val)->u.extendedReq))
            return 0;
        break;
    case 0x40000018:
        (val)->choice = 20;
        if (!ASN1Dec_ExtendedResponse(dec, 0, &(val)->u.extendedResp))
            return 0;
        break;
    default:
        ASN1DecSetError(dec, ASN1_ERR_CORRUPT);
        return 0;
    }
    return 1;
}

static void ASN1CALL ASN1Free_LDAPMsg_protocolOp(LDAPMsg_protocolOp* val) {
    if (val) {
        switch ((val)->choice) {
        case 1:
            ASN1Free_BindRequest(&(val)->u.bindRequest);
            break;
        case 2:
            ASN1Free_BindResponse(&(val)->u.bindResponse);
            break;
        case 4:
            ASN1Free_SearchRequest(&(val)->u.searchRequest);
            break;
        case 5:
            ASN1Free_SearchResultEntry(&(val)->u.searchResEntry);
            break;
        case 6:
            ASN1Free_SearchResultDone(&(val)->u.searchResDone);
            break;
        case 7:
            ASN1Free_ModifyRequest(&(val)->u.modifyRequest);
            break;
        case 8:
            ASN1Free_ModifyResponse(&(val)->u.modifyResponse);
            break;
        case 9:
            ASN1Free_AddRequest(&(val)->u.addRequest);
            break;
        case 10:
            ASN1Free_AddResponse(&(val)->u.addResponse);
            break;
        case 11:
            ASN1octetstring_free(&(val)->u.delRequest);
            break;
        case 12:
            ASN1Free_DelResponse(&(val)->u.delResponse);
            break;
        case 13:
            ASN1Free_ModifyDNRequest(&(val)->u.modDNRequest);
            break;
        case 14:
            ASN1Free_ModifyDNResponse(&(val)->u.modDNResponse);
            break;
        case 15:
            ASN1Free_CompareRequest(&(val)->u.compareRequest);
            break;
        case 16:
            ASN1Free_CompareResponse(&(val)->u.compareResponse);
            break;
        case 18:
            ASN1Free_SearchResultReference(&(val)->u.searchResRef);
            break;
        case 19:
            ASN1Free_ExtendedRequest(&(val)->u.extendedReq);
            break;
        case 20:
            ASN1Free_ExtendedResponse(&(val)->u.extendedResp);
            break;
        }
    }
}

static int ASN1CALL ASN1Enc_LDAPMsg(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMsg* val) {
    ASN1uint32_t nLenOff;
    if (!ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff))
        return 0;
    if (!ASN1BEREncU32(enc, 0x2, (val)->messageID))
        return 0;
    if (!ASN1Enc_LDAPMsg_protocolOp(enc, 0, &(val)->protocolOp))
        return 0;
    if ((val)->o[0] & 0x80) {
        if (!ASN1Enc_Controls(enc, 0x80000000, &(val)->controls))
            return 0;
    }
    if (!ASN1BEREncEndOfContents(enc, nLenOff))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_LDAPMsg(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMsg* val) {
    ASN1decoding_t dd = 0;
    ASN1octet_t* di = 0;
    ASN1uint32_t t = 0;
    if (!ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di))
        return 0;
    ZeroMemory((val)->o, 1);
    if (!ASN1BERDecU32Val(dd, 0x2, (ASN1uint32_t*)&(val)->messageID))
        return 0;
    if (!ASN1Dec_LDAPMsg_protocolOp(dd, 0, &(val)->protocolOp))
        return 0;
    ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000000) {
        (val)->o[0] |= 0x80;
        if (!ASN1Dec_Controls(dd, 0x80000000, &(val)->controls))
            return 0;
    }
    if (!ASN1BERDecEndOfContents(dec, dd, di))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_LDAPMsg(LDAPMsg* val) {
    if (val) {
        ASN1Free_LDAPMsg_protocolOp(&(val)->protocolOp);
        if ((val)->o[0] & 0x80) {
            ASN1Free_Controls(&(val)->controls);
        }
    }
}

static int ASN1CALL ASN1Enc_LDAPMessage(ASN1encoding_t enc, ASN1uint32_t tag, LDAPMessage* val) {
    if (!ASN1Enc_LDAPMsg(enc, tag, val))
        return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_LDAPMessage(ASN1decoding_t dec, ASN1uint32_t tag, LDAPMessage* val) {
    if (!ASN1Dec_LDAPMsg(dec, tag, val))
        return 0;
    return 1;
}

static void ASN1CALL ASN1Free_LDAPMessage(LDAPMessage* val) {
    if (val) {
        ASN1Free_LDAPMsg(val);
    }
}
