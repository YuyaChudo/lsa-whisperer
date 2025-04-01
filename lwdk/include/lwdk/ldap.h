// Copyright (C) 2024 Evan McBroom
//
// Ldap protocol asn.1
//
#pragma once
#include <phnt_windows.h>

#include "um/msasn1.h"

#define PartialAttribute_PDU 0
#define LDAPMessage_PDU      1

#define SIZE_LDAP_Module_PDU_0 sizeof(PartialAttribute)
#define SIZE_LDAP_Module_PDU_1 sizeof(LDAPMessage)

#ifdef __cplusplus
extern "C" {
#endif

enum LdapResultCode;

struct AddRequest;
struct AttributeDescriptionList;
struct AttributeList_Seq;
struct AttributeList;
struct AttributeTypeAndValues_vals;
struct AttributeTypeAndValues;
struct AttributeVals;
struct AttributeValueAssertion;
struct AuthenticationChoice;
struct BindRequest;
struct BindResponse;
struct CompareRequest;
struct Control;
struct Controls;
struct ExtendedRequest;
struct ExtendedResponse;
struct Filter_and;
struct Filter_or;
struct Filter;
struct LDAPMsg_protocolOp;
struct LDAPMsg;
struct LDAPResult;
struct MatchingRuleAssertion_matchingRules;
struct MatchingRuleAssertion;
struct ModificationList_Seq;
struct ModificationList;
struct ModifyDNRequest;
struct ModifyRequest;
struct PartialAttribute_vals;
struct PartialAttribute;
struct PartialAttributeList_Seq_vals;
struct PartialAttributeList_Seq;
struct PartialAttributeList;
struct Referral;
struct SaslCredentials;
struct SearchRequest;
struct SearchResultEntry;
struct SearchResultReference;
struct SubstringFilter;
struct SubstringFilterList_Seq;
struct SubstringFilterList;
struct UnbindRequest;

typedef enum LdapResultCode {
    ldap_success = 0,
    ldap_operationsError = 1,
    ldap_protocolError = 2,
    ldap_timeLimitExceeded = 3,
    ldap_sizeLimitExceeded = 4,
    ldap_compareFalse = 5,
    ldap_compareTrue = 6,
    ldap_authMethodNotSupported = 7,
    ldap_strongAuthRequired = 8,
    ldap_referralv2 = 9,
    ldap_referral = 10,
    ldap_adminLimitExceeded = 11,
    ldap_unavailableCriticalExtension = 12,
    ldap_confidentialityRequired = 13,
    ldap_saslBindInProgress = 14,
    ldap_noSuchAttribute = 16,
    ldap_undefinedAttributeType = 17,
    ldap_inappropriateMatching = 18,
    ldap_constraintViolation = 19,
    ldap_attributeOrValueExists = 20,
    ldap_invalidAttributeSyntax = 21,
    ldap_noSuchObject = 32,
    ldap_aliasProblem = 33,
    ldap_invalidDNSyntax = 34,
    ldap_aliasDereferencingProblem = 36,
    ldap_inappropriateAuthentication = 48,
    ldap_invalidCredentials = 49,
    ldap_insufficientAccessRights = 50,
    ldap_busy = 51,
    ldap_unavailable = 52,
    ldap_unwillingToPerform = 53,
    ldap_loopDetect = 54,
    ldap_sortControlMissing = 60,
    ldap_indexRangeError = 61,
    ldap_namingViolation = 64,
    ldap_objectClassViolation = 65,
    ldap_notAllowedOnNonLeaf = 66,
    ldap_notAllowedOnRDN = 67,
    ldap_entryAlreadyExists = 68,
    ldap_objectClassModsProhibited = 69,
    ldap_resultsTooLarge = 70,
    ldap_affectsMultipleDSAs = 71,
    ldap_virtualListViewError = 76,
    ldap_other = 80,
} LdapResultCode;

typedef struct PartialAttributeList_Seq_vals* PPartialAttributeList_Seq_vals;
typedef struct AttributeTypeAndValues_vals* PAttributeTypeAndValues_vals;
typedef struct MatchingRuleAssertion_matchingRules* PMatchingRuleAssertion_matchingRules;
typedef struct PartialAttribute_vals* PPartialAttribute_vals;
typedef struct AttributeDescriptionList* PAttributeDescriptionList;
typedef struct Referral* PReferral;
typedef struct SubstringFilterList* PSubstringFilterList;
typedef struct PartialAttributeList* PPartialAttributeList;
typedef struct SearchResultReference* PSearchResultReference;
typedef struct AttributeList* PAttributeList;
typedef struct AttributeVals* PAttributeVals;
typedef struct Controls* PControls;
typedef struct ModificationList* PModificationList;
typedef struct Filter* PFilter;
typedef struct Filter_or* PFilter_or;
typedef struct Filter_and* PFilter_and;
typedef ASN1uint32_t MessageID;
typedef ASN1octetstring_t LDAPString;
typedef ASN1octetstring_t LDAPOID;
typedef LDAPString LDAPDN;
typedef LDAPString RelativeLDAPDN;
typedef LDAPString AttributeType;
typedef LDAPString AttributeDescription;
typedef ASN1octetstring_t AttributeValue;
typedef ASN1octetstring_t AssertionValue;
typedef LDAPString MatchingRuleId;
typedef ASN1octetstring_t LDAPURL;
typedef LDAPString URI;
typedef LDAPDN DelRequest;
typedef MessageID AbandonRequest;

typedef struct UnbindRequest {
    char placeholder;
} UnbindRequest;

typedef struct PartialAttributeList_Seq_vals {
    PPartialAttributeList_Seq_vals next;
    AttributeValue value;
} PartialAttributeList_Seq_vals_Element;

typedef struct AttributeList_Seq {
    AttributeType type;
    PAttributeVals vals;
} AttributeList_Seq;

typedef struct AttributeTypeAndValues_vals {
    PAttributeTypeAndValues_vals next;
    AttributeValue value;
} AttributeTypeAndValues_vals_Element;

typedef struct PartialAttributeList_Seq {
    AttributeType type;
    PPartialAttributeList_Seq_vals vals;
} PartialAttributeList_Seq;

typedef struct MatchingRuleAssertion_matchingRules {
    PMatchingRuleAssertion_matchingRules next;
    MatchingRuleId value;
} MatchingRuleAssertion_matchingRules_Element;

typedef struct SubstringFilterList_Seq {
    ASN1choice_t choice;
    union {
#define initial_chosen 1
        LDAPString initial;
#define any_chosen 2
        LDAPString any;
#define final_chosen 3
        LDAPString final;
    } u;
} SubstringFilterList_Seq;

typedef struct PartialAttribute_vals {
    PPartialAttribute_vals next;
    AttributeValue value;
} PartialAttribute_vals_Element;

typedef struct AttributeDescriptionList {
    PAttributeDescriptionList next;
    AttributeDescription value;
} AttributeDescriptionList_Element;

typedef struct AttributeValueAssertion {
    AttributeDescription attributeType;
    AssertionValue assertionValue;
} AttributeValueAssertion;

typedef struct PartialAttribute {
    AttributeDescription type;
    PPartialAttribute_vals vals;
} PartialAttribute;

typedef struct LDAPResult {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LdapResultCode resultCode;
    LDAPDN matchedDN;
    LDAPString errorMessage;
#define referral_present 0x80
    PReferral referral;
} LDAPResult;

typedef struct Referral {
    PReferral next;
    URI value;
} Referral_Element;

typedef struct Control {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LDAPOID controlType;
#define criticality_present 0x80
    ASN1bool_t criticality;
#define controlValue_present 0x40
    ASN1octetstring_t controlValue;
} Control;

typedef struct SaslCredentials {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LDAPString mechanism;
#define credentials_present 0x80
    ASN1octetstring_t credentials;
} SaslCredentials;

typedef struct SubstringFilter {
    AttributeType type;
    PSubstringFilterList substrings;
} SubstringFilter;

typedef struct SubstringFilterList {
    PSubstringFilterList next;
    SubstringFilterList_Seq value;
} SubstringFilterList_Element;

typedef struct MatchingRuleAssertion {
    PMatchingRuleAssertion_matchingRules matchingRules;
    AttributeType type;
    AssertionValue matchValue;
    ASN1bool_t dnAttributes;
} MatchingRuleAssertion;

typedef struct SearchResultEntry {
    LDAPDN objectName;
    PPartialAttributeList attributes;
} SearchResultEntry;

typedef struct PartialAttributeList {
    PPartialAttributeList next;
    PartialAttributeList_Seq value;
} PartialAttributeList_Element;

typedef struct SearchResultReference {
    PSearchResultReference next;
    URI value;
} SearchResultReference_Element;

typedef LDAPResult SearchResultDone;

typedef struct ModifyRequest {
    LDAPDN object;
    PModificationList changes;
} ModifyRequest;

typedef struct AttributeTypeAndValues {
    AttributeDescription type;
    PAttributeTypeAndValues_vals vals;
} AttributeTypeAndValues;

typedef LDAPResult ModifyResponse;

typedef struct AddRequest {
    LDAPDN entry;
    PAttributeList attributes;
} AddRequest;

typedef struct AttributeList {
    PAttributeList next;
    AttributeList_Seq value;
} AttributeList_Element;

typedef struct AttributeVals {
    PAttributeVals next;
    AttributeValue value;
} AttributeVals_Element;

typedef LDAPResult AddResponse;

typedef LDAPResult DelResponse;

typedef struct ModifyDNRequest {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LDAPDN entry;
    RelativeLDAPDN newrdn;
    ASN1bool_t deleteoldrdn;
#define newSuperior_present 0x80
    LDAPDN newSuperior;
} ModifyDNRequest;

typedef LDAPResult ModifyDNResponse;

typedef struct CompareRequest {
    LDAPDN entry;
    AttributeValueAssertion ava;
} CompareRequest;

typedef LDAPResult CompareResponse;

typedef struct ExtendedRequest {
    LDAPString requestName;
    ASN1octetstring_t requestValue;
} ExtendedRequest;

typedef struct ExtendedResponse {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LdapResultCode resultCode;
    LDAPDN matchedDN;
    LDAPString errorMessage;
#define referral_present 0x80
    PReferral referral;
#define responseName_present 0x40
    LDAPOID responseName;
#define response_present 0x20
    ASN1octetstring_t response;
} ExtendedResponse;

typedef struct ModificationList_Seq {
    enum {
        ldap_add = 0,
        ldap_operation_delete = 1,
        ldap_replace = 2,
    } operation;
    AttributeTypeAndValues modification;
} ModificationList_Seq;

typedef struct Controls {
    PControls next;
    Control value;
} Controls_Element;

typedef struct AuthenticationChoice {
    ASN1choice_t choice;
    union {
#define simple_chosen 1
        ASN1octetstring_t simple;
#define sasl_chosen 2
        SaslCredentials sasl;
#define sicilyNegotiate_chosen 3
        ASN1octetstring_t sicilyNegotiate;
#define sicilyInitial_chosen 4
        ASN1octetstring_t sicilyInitial;
#define sicilySubsequent_chosen 5
        ASN1octetstring_t sicilySubsequent;
    } u;
} AuthenticationChoice;

typedef struct BindResponse {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    LdapResultCode resultCode;
    LDAPDN matchedDN;
    LDAPString errorMessage;
#define referral_present 0x80
    PReferral referral;
    AuthenticationChoice serverCreds;
} BindResponse;

typedef struct Filter {
    ASN1choice_t choice;
    union {
#define and_chosen 1
        PFilter_and and;
#define or_chosen 2
        PFilter_or or ;
#define not_chosen 3
        PFilter not ;
#define equalityMatch_chosen 4
        AttributeValueAssertion equalityMatch;
#define substrings_chosen 5
        SubstringFilter substrings;
#define greaterOrEqual_chosen 6
        AttributeValueAssertion greaterOrEqual;
#define lessOrEqual_chosen 7
        AttributeValueAssertion lessOrEqual;
#define present_chosen 8
        AttributeType present;
#define approxMatch_chosen 9
        AttributeValueAssertion approxMatch;
#define extensibleMatch_chosen 10
        MatchingRuleAssertion extensibleMatch;
    } u;
} Filter;

typedef struct ModificationList {
    PModificationList next;
    ModificationList_Seq value;
} ModificationList_Element;

typedef struct Filter_or {
    ASN1uint32_t count;
    Filter value;
} Filter_or;

typedef struct Filter_and {
    ASN1uint32_t count;
    Filter value;
} Filter_and;

typedef struct BindRequest {
    ASN1uint16_t version;
    LDAPDN name;
    AuthenticationChoice authentication;
} BindRequest;

typedef struct SearchRequest {
    LDAPDN baseObject;
    enum {
        ldap_baseObject = 0,
        ldap_singleLevel = 1,
        ldap_wholeSubtree = 2,
    } scope;
    enum {
        ldap_neverDerefAliases = 0,
        ldap_derefInSearching = 1,
        ldap_derefFindingBaseObj = 2,
        ldap_derefAlways = 3,
    } derefAliases;
    ASN1uint32_t sizeLimit;
    ASN1uint32_t timeLimit;
    ASN1bool_t typesOnly;
    Filter filter;
    PAttributeDescriptionList attributes;
} SearchRequest;

typedef struct LDAPMsg_protocolOp {
    ASN1choice_t choice;
    union {
#define bindRequest_chosen 1
        BindRequest bindRequest;
#define bindResponse_chosen 2
        BindResponse bindResponse;
#define unbindRequest_chosen 3
        UnbindRequest unbindRequest;
#define searchRequest_chosen 4
        SearchRequest searchRequest;
#define searchResEntry_chosen 5
        SearchResultEntry searchResEntry;
#define searchResDone_chosen 6
        SearchResultDone searchResDone;
#define modifyRequest_chosen 7
        ModifyRequest modifyRequest;
#define modifyResponse_chosen 8
        ModifyResponse modifyResponse;
#define addRequest_chosen 9
        AddRequest addRequest;
#define addResponse_chosen 10
        AddResponse addResponse;
#define delRequest_chosen 11
        DelRequest delRequest;
#define delResponse_chosen 12
        DelResponse delResponse;
#define modDNRequest_chosen 13
        ModifyDNRequest modDNRequest;
#define modDNResponse_chosen 14
        ModifyDNResponse modDNResponse;
#define compareRequest_chosen 15
        CompareRequest compareRequest;
#define compareResponse_chosen 16
        CompareResponse compareResponse;
#define abandonRequest_chosen 17
        AbandonRequest abandonRequest;
#define searchResRef_chosen 18
        PSearchResultReference searchResRef;
#define extendedReq_chosen 19
        ExtendedRequest extendedReq;
#define extendedResp_chosen 20
        ExtendedResponse extendedResp;
    } u;
} LDAPMsg_protocolOp;

typedef struct LDAPMsg {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    MessageID messageID;
    LDAPMsg_protocolOp protocolOp;
#define controls_present 0x80
    PControls controls;
} LDAPMsg;

typedef LDAPMsg LDAPMessage;

extern ASN1bool_t Control_criticality_default;
extern ASN1int32_t maxInt;

extern ASN1module_t LDAP_Module;
extern void ASN1CALL LDAP_Module_Startup();
extern void ASN1CALL LDAP_Module_Cleanup();

#ifdef __cplusplus
} // Closes extern "C" above
namespace Asn1 {
    namespace Ldap {
        // Enumerations
        using ResultCode = LdapResultCode;

        using AddRequest = AddRequest;
        using AttributeDescriptionList = AttributeDescriptionList;
        using AttributeList_Seq = AttributeList_Seq;
        using AttributeList = AttributeList;
        using AttributeTypeAndValues_vals = AttributeTypeAndValues_vals;
        using AttributeTypeAndValues = AttributeTypeAndValues;
        using AttributeVals = AttributeVals;
        using AttributeValueAssertion = AttributeValueAssertion;
        using AuthenticationChoice = AuthenticationChoice;
        using BindRequest = BindRequest;
        using BindResponse = BindResponse;
        using CompareRequest = CompareRequest;
        using Control = Control;
        using Controls = Controls;
        using ExtendedRequest = ExtendedRequest;
        using ExtendedResponse = ExtendedResponse;
        using Filter_and = Filter_and;
        using Filter_or = Filter_or;
        using Filter = Filter;
        using LDAPMsg_protocolOp = LDAPMsg_protocolOp;
        using LDAPMsg = LDAPMsg;
        using LDAPResult = LDAPResult;
        using MatchingRuleAssertion_matchingRules = MatchingRuleAssertion_matchingRules;
        using MatchingRuleAssertion = MatchingRuleAssertion;
        using ModificationList_Seq = ModificationList_Seq;
        using ModificationList = ModificationList;
        using ModifyDNRequest = ModifyDNRequest;
        using ModifyRequest = ModifyRequest;
        using PartialAttribute_vals = PartialAttribute_vals;
        using PartialAttribute = PartialAttribute;
        using PartialAttributeList_Seq_vals = PartialAttributeList_Seq_vals;
        using PartialAttributeList_Seq = PartialAttributeList_Seq;
        using PartialAttributeList = PartialAttributeList;
        using Referral = Referral;
        using SaslCredentials = SaslCredentials;
        using SearchRequest = SearchRequest;
        using SearchResultEntry = SearchResultEntry;
        using SearchResultReference = SearchResultReference;
        using SubstringFilter = SubstringFilter;
        using SubstringFilterList_Seq = SubstringFilterList_Seq;
        using SubstringFilterList = SubstringFilterList;
        using UnbindRequest = UnbindRequest;
    }
}
#endif