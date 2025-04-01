// Copyright (C) 2024 Evan McBroom
//
// PKCS #12: Personal Information Exchange Syntax v1.1
//
#pragma once
#include <phnt_windows.h>

#include "um/msasn1.h"

#define AttributeSetValue_Set_PDU   0
#define ObjectIdentifierType_PDU    1
#define OctetStringType_PDU         2
#define IntegerType_PDU             3
#define RSAPublicKey_PDU            4
#define RSAPrivateKey_PDU           5
#define DigestInfo_PDU              6
#define Attributes_PDU              7
#define MacData_PDU                 8
#define AuthenticatedSafes_PDU      9
#define SafeBag_PDU                 10
#define CertBag_PDU                 11
#define CRLBag_PDU                  12
#define SecretBag_PDU               13
#define PBEParameter_PDU            14
#define EncryptedData_PDU           15
#define PrivateKeyInfo_PDU          16
#define EncryptedPrivateKeyInfo_PDU 17
#define PFX_PDU                     18
#define SafeContents_PDU            19
#define KeyBag_PDU                  20
#define Pkcs_8ShroudedKeyBag_PDU    21

#define SIZE_PKCS12_Module_PDU_0  sizeof(AttributeSetValue_Set)
#define SIZE_PKCS12_Module_PDU_1  sizeof(ObjectIdentifierType)
#define SIZE_PKCS12_Module_PDU_2  sizeof(OctetStringType)
#define SIZE_PKCS12_Module_PDU_3  sizeof(IntegerType)
#define SIZE_PKCS12_Module_PDU_4  sizeof(RSAPublicKey)
#define SIZE_PKCS12_Module_PDU_5  sizeof(RSAPrivateKey)
#define SIZE_PKCS12_Module_PDU_6  sizeof(DigestInfo)
#define SIZE_PKCS12_Module_PDU_7  sizeof(Attributes_Element)
#define SIZE_PKCS12_Module_PDU_8  sizeof(MacData)
#define SIZE_PKCS12_Module_PDU_9  sizeof(AuthenticatedSafes_Element)
#define SIZE_PKCS12_Module_PDU_10 sizeof(SafeBag)
#define SIZE_PKCS12_Module_PDU_11 sizeof(CertBag)
#define SIZE_PKCS12_Module_PDU_12 sizeof(CRLBag)
#define SIZE_PKCS12_Module_PDU_13 sizeof(SecretBag)
#define SIZE_PKCS12_Module_PDU_14 sizeof(PBEParameter)
#define SIZE_PKCS12_Module_PDU_15 sizeof(EncryptedData)
#define SIZE_PKCS12_Module_PDU_16 sizeof(PrivateKeyInfo)
#define SIZE_PKCS12_Module_PDU_17 sizeof(EncryptedPrivateKeyInfo)
#define SIZE_PKCS12_Module_PDU_18 sizeof(PFX)
#define SIZE_PKCS12_Module_PDU_19 sizeof(SafeContents_Element)
#define SIZE_PKCS12_Module_PDU_20 sizeof(KeyBag)
#define SIZE_PKCS12_Module_PDU_21 sizeof(Pkcs_8ShroudedKeyBag)

#ifdef __cplusplus
extern "C" {
#endif
 
struct AlgorithmIdentifier;
struct Attribute;
struct Attributes;
struct AttributeSetValue;
struct AuthenticatedSafes;
struct CertBag;
struct ContentInfo;
struct CRLBag;
struct DigestInfo;
struct EncryptedContentInfo;
struct EncryptedData;
struct EncryptedPrivateKeyInfo;
struct MacData;
struct PBEParameter;
struct PFX;
struct PrivateKeyInfo;
struct RSAPrivateKey;
struct RSAPublicKey;
struct SafeBag;
struct SafeContents;
struct SecretBag;

typedef struct AttributeSetValue* PAttributeSetValue;
typedef struct Attributes* PAttributes;
typedef struct AuthenticatedSafes* PAuthenticatedSafes;
typedef struct SafeContents* PSafeContents;
typedef ASN1open_t AttributeSetValue_Set;
typedef ASN1objectidentifier2_t ObjectID;
typedef ObjectID ObjID;
typedef ASN1open_t Any;
typedef ObjectID ObjectIdentifierType;
typedef ASN1octetstring_t OctetStringType;
typedef ASN1intx_t IntegerType;
typedef ASN1intx_t HugeInteger;
typedef ASN1octetstring_t EncryptedContent;
typedef ObjectID ContentType;
typedef ASN1octetstring_t Digest;
typedef ASN1int32_t Version;
typedef ASN1octetstring_t PrivateKey;
typedef ASN1octetstring_t X509Cert;
typedef ASN1ztcharstring_t SDSICert;
typedef ASN1octetstring_t X509CRL;

typedef struct AttributeSetValue {
    PAttributeSetValue next;
    AttributeSetValue_Set value;
} AttributeSetValue_Element;

typedef struct Attribute {
    ObjectID attributeType;
    PAttributeSetValue attributeValue;
} Attribute;

typedef struct AlgorithmIdentifier {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ObjectID algorithm;
#define parameters_present 0x80
    ASN1open_t parameters;
} AlgorithmIdentifier;

typedef AlgorithmIdentifier ContentEncryptionAlgorithmIdentifier;

typedef struct RSAPublicKey {
    HugeInteger modulus;
    HugeInteger publicExponent;
} RSAPublicKey;

typedef struct RSAPrivateKey {
    Version version;
    HugeInteger modulus;
    ASN1int32_t publicExponent;
    HugeInteger privateExponent;
    HugeInteger prime1;
    HugeInteger prime2;
    HugeInteger exponent1;
    HugeInteger exponent2;
    HugeInteger coefficient;
} RSAPrivateKey;

typedef AlgorithmIdentifier DigestAlgorithmIdentifier;

typedef struct ContentInfo {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ContentType contentType;
#define content_present 0x80
    ASN1open_t content;
} ContentInfo;

typedef struct DigestInfo {
    DigestAlgorithmIdentifier digestAlgorithm;
    Digest digest;
} DigestInfo;

typedef AlgorithmIdentifier PrivateKeyAlgorithmIdentifier;

typedef struct Attributes {
    PAttributes next;
    Attribute value;
} Attributes_Element;

typedef AlgorithmIdentifier EncryptionAlgorithmIdentifier;

typedef struct MacData {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    DigestInfo safeMac;
    ASN1octetstring_t macSalt;
#define macIterationCount_present 0x80
    ASN1int32_t macIterationCount;
} MacData;

typedef struct AuthenticatedSafes {
    PAuthenticatedSafes next;
    ContentInfo value;
} AuthenticatedSafes_Element;

typedef struct SafeBag {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ObjectID safeBagType;
    ASN1open_t safeBagContent;
#define safeBagAttribs_present 0x80
    PAttributes safeBagAttribs;
} SafeBag;

typedef struct CertBag {
    ObjectID certType;
    ASN1open_t value;
} CertBag;

typedef struct CRLBag {
    ObjectID crlType;
    ASN1open_t value;
} CRLBag;

typedef struct SecretBag {
    ObjectID secretType;
    ASN1open_t secretContent;
} SecretBag;

typedef struct PBEParameter {
    ASN1octetstring_t salt;
    ASN1int32_t iterationCount;
} PBEParameter;

typedef struct EncryptedContentInfo {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ContentType contentType;
    ContentEncryptionAlgorithmIdentifier contentEncryptionAlg;
#define encryptedContent_present 0x80
    EncryptedContent encryptedContent;
} EncryptedContentInfo;

typedef struct EncryptedData {
    Version version;
    EncryptedContentInfo encryptedContentInfo;
} EncryptedData;

typedef struct PrivateKeyInfo {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    Version version;
    PrivateKeyAlgorithmIdentifier privateKeyAlgorithm;
    PrivateKey privateKey;
#define attributes_present 0x80
    PAttributes attributes;
} PrivateKeyInfo;

typedef struct EncryptedPrivateKeyInfo {
    EncryptionAlgorithmIdentifier encryptionAlgorithm;
    EncryptedData encryptedData;
} EncryptedPrivateKeyInfo;

typedef struct PFX {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    Version version;
    ContentInfo authSafes;
#define macData_present 0x80
    MacData macData;
} PFX;

typedef struct SafeContents {
    PSafeContents next;
    SafeBag value;
} SafeContents_Element;

typedef PrivateKeyInfo KeyBag;
typedef EncryptedPrivateKeyInfo Pkcs_8ShroudedKeyBag;

extern ASN1int32_t MacData_macIterationCount_default;

extern ASN1module_t PKCS12_Module;
extern void ASN1CALL PKCS12_Module_Startup();
extern void ASN1CALL PKCS12_Module_Cleanup();

#ifdef __cplusplus
} // Closes extern "C" above
namespace Asn1 {
    namespace Pkcs12 {
        using AlgorithmIdentifier = ::AlgorithmIdentifier;
        using Attribute = ::Attribute;
        using Attributes = ::Attributes;
        using AttributeSetValue = ::AttributeSetValue;
        using AuthenticatedSafes = ::AuthenticatedSafes;
        using CertBag = ::CertBag;
        using ContentInfo = ::ContentInfo;
        using CRLBag = ::CRLBag;
        using DigestInfo = ::DigestInfo;
        using EncryptedContentInfo = ::EncryptedContentInfo;
        using EncryptedData = ::EncryptedData;
        using EncryptedPrivateKeyInfo = ::EncryptedPrivateKeyInfo;
        using MacData = ::MacData;
        using PBEParameter = ::PBEParameter;
        using PFX = ::PFX;
        using PrivateKeyInfo = ::PrivateKeyInfo;
        using RSAPrivateKey = ::RSAPrivateKey;
        using RSAPublicKey = ::RSAPublicKey;
        using SafeBag = ::SafeBag;
        using SafeContents = ::SafeContents;
        using SecretBag = ::SecretBag;
    }
}
#endif