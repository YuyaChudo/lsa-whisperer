// Copyright (C) 2024 Evan McBroom
#pragma once
#include <phnt_windows.h>

#ifdef __cplusplus
extern "C" {
#endif

enum VAULT_ELEMENT_PROTECTION;
enum VAULT_ELEMENT_TYPE;
enum VAULT_INFORMATION_TYPE;
enum VAULT_NOTIFICATION_TYPE;
enum VAULT_SCHEMA_ELEMENT_ID;

struct _VAULT_ARRAY;
struct _ATTRIBUTE;
struct _VAULT_CAUB;
struct _VAULT_GUID_ARRAY;
struct _VAULT_INFORMATION;
struct _VAULT_ITEM;
struct _VAULT_ITEM_ARRAY;
struct _VAULT_ITEM_ELEMENT;
struct _VAULT_ITEM_SCHEMA;
struct _VAULT_ITEM_SCHEMA_ARRAY;
struct _VAULT_KEY_PBKDF2PARAM;
struct _VAULT_SCHEMA_ELEMENT;
struct _VAULT_VARIANT;

typedef enum VAULT_ELEMENT_PROTECTION {
    SchemaElement_Start = -1,
    SchemaElement_ProtectedAlways = 0,
    SchemaElement_ProtectedRoaming = 1,
    SchemaElement_Clear = 2,
    SchemaElement_End = 3,
} VAULT_ELEMENT_PROTECTION;

typedef enum VAULT_ELEMENT_TYPE {
    ElementType_Undefined = -1,
    ElementType_Boolean = 0,
    ElementType_Short = 1,
    ElementType_UnsignedShort = 2,
    ElementType_Integer = 3,
    ElementType_UnsignedInteger = 4,
    ElementType_Double = 5,
    ElementType_Guid = 6,
    ElementType_String = 7,
    ElementType_ByteArray = 8,
    ElementType_TimeStamp = 9,
    ElementType_ProtectedArray = 10,
    ElementType_Attribute = 11,
    ElementType_Sid = 12,
    ElementType_Last = 13,
} VAULT_ELEMENT_TYPE;

typedef enum VAULT_INFORMATION_TYPE {
    InfoInvalidInformation = 0,
    InfoFriendlyName = 1,
    InfoDefaultProtection = 2,
    InfoVaultId = 3,
    InfoVaultLocation = 4,
} VAULT_INFORMATION_TYPE;

typedef enum VAULT_NOTIFICATION_TYPE {
    NotificationType_VaultList = 0,
} VAULT_NOTIFICATION_TYPE;

typedef enum VAULT_SCHEMA_ELEMENT_ID {
    ElementId_Illegal = 0,
    ElementId_Resource = 1,
    ElementId_Identity = 2,
    ElementId_Authenticator = 3,
    ElementId_Tag = 4,
    ElementId_PackageSid = 5,
    ElementId_AppStart = 100,
    ElementId_AppEnd = 10000,
} VAULT_SCHEMA_ELEMENT_ID;

typedef struct _VAULT_CAUB {
    ULONG NumBytes;
    PBYTE pByteArray;
} VAULT_CAUB, *PVAULT_CAUB;

typedef struct _ATTRIBUTE {
    PWCHAR pszName;
    ULONG dwFlags;
    VAULT_CAUB Value;
} ATTRIBUTE, *PATTRIBUTE;

typedef struct _VAULT_ARRAY {
    ULONG VaultsCount;
    PGUID VaultGuids;
} VAULT_ARRAY, *PVAULT_ARRAY;

typedef struct _VAULT_GUID_ARRAY {
    DWORD dwCount;
    PGUID pGuids;
} VAULT_GUID_ARRAY, *PVAULT_GUID_ARRAY;

typedef struct _VAULT_INFORMATION {
    VAULT_INFORMATION_TYPE Type;
    union {
        LPWSTR FriendlyName;
        GUID ProtectionType;
        GUID VaultId;
        LPWSTR Location;
    };
} VAULT_INFORMATION, *PVAULT_INFORMATION;

typedef struct _VAULT_VARIANT {
    VAULT_ELEMENT_TYPE Type;
    union {
        BOOL Boolean;
        SHORT Short;
        USHORT UnsignedShort;
        INT Int;
        UINT UnsignedInt;
        DOUBLE Double;
        GUID Guid;
        LPWSTR String;
        VAULT_CAUB ByteArray;
        VAULT_CAUB ProtectedArray;
        PATTRIBUTE Attribute;
        PSID Sid;
    };
} VAULT_VARIANT, *PVAULT_VARIANT;

typedef struct _VAULT_ITEM_ELEMENT {
    VAULT_SCHEMA_ELEMENT_ID SchemaElementId;
    VAULT_VARIANT ItemValue;
} VAULT_ITEM_ELEMENT, *PVAULT_ITEM_ELEMENT;

typedef struct _VAULT_ITEM {
    GUID SchemaId;
    LPWSTR pszCredentialFriendlyName;
    PVAULT_ITEM_ELEMENT pResourceElement;
    PVAULT_ITEM_ELEMENT pIdentityElement;
    PVAULT_ITEM_ELEMENT pAuthenticatorElement;
    PVAULT_ITEM_ELEMENT pPackageSid;
    FILETIME LastModified;
    DWORD dwFlags;
    DWORD dwPropertiesCount;
    PVAULT_ITEM_ELEMENT pPropertyElements;
} VAULT_ITEM, *PVAULT_ITEM;

typedef struct _VAULT_ITEM_ARRAY {
    ULONG ItemsCount;
    PVAULT_ITEM Items;
} VAULT_ITEM_ARRAY, *PVAULT_ITEM_ARRAY;

typedef struct _VAULT_SCHEMA_ELEMENT {
    VAULT_SCHEMA_ELEMENT_ID SchemaElementId;
    VAULT_ELEMENT_TYPE ElementType;
    VAULT_ELEMENT_PROTECTION ElementProtection;
    ULONG dwElementFlags;
} VAULT_SCHEMA_ELEMENT, *PVAULT_SCHEMA_ELEMENT;

typedef struct _VAULT_ITEM_SCHEMA {
    GUID SchemaId;
    LPWSTR pszSchemaFriendlyName;
    PVAULT_SCHEMA_ELEMENT pResourceElement;
    PVAULT_SCHEMA_ELEMENT pIdentityElement;
    PVAULT_SCHEMA_ELEMENT pAuthenticatorElement;
    ULONG dwPropertiesCount;
    PVAULT_SCHEMA_ELEMENT pPropertyElements;
} VAULT_ITEM_SCHEMA, *PVAULT_ITEM_SCHEMA;

typedef struct _VAULT_ITEM_SCHEMA_ARRAY {
    ULONG SchemaCount;
    PVAULT_ITEM_SCHEMA Schemas;
} VAULT_ITEM_SCHEMA_ARRAY, *PVAULT_ITEM_SCHEMA_ARRAY;

typedef struct _VAULT_KEY_PBKDF2PARAM {
    ULONG magic;
    ULONGLONG cIterationCount;
    ULONG cbHashAlgorithmName;
    ULONG cbSalt;
} VAULT_KEY_PBKDF2PARAM, *PVAULT_KEY_PBKDF2PARAM;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Vault {
    // Enumerations
    using ELEMENT_PROTECTION = VAULT_ELEMENT_PROTECTION;
    using ELEMENT_TYPE = VAULT_ELEMENT_TYPE;
    using INFORMATION_TYPE = VAULT_INFORMATION_TYPE;
    using NOTIFICATION_TYPE = VAULT_NOTIFICATION_TYPE;
    using SCHEMA_ELEMENT_ID = VAULT_SCHEMA_ELEMENT_ID;

    using ARRAY = _VAULT_ARRAY;
    using ATTRIBUTE = _ATTRIBUTE;
    using CAUB = _VAULT_CAUB;
    using GUID_ARRAY = _VAULT_GUID_ARRAY;
    using INFORMATION = _VAULT_INFORMATION;
    using ITEM = _VAULT_ITEM;
    using ITEM_ARRAY = _VAULT_ITEM_ARRAY;
    using ITEM_ELEMENT = _VAULT_ITEM_ELEMENT;
    using ITEM_SCHEMA = _VAULT_ITEM_SCHEMA;
    using ITEM_SCHEMA_ARRAY = _VAULT_ITEM_SCHEMA_ARRAY;
    using KEY_PBKDF2PARAM = _VAULT_KEY_PBKDF2PARAM;
    using SCHEMA_ELEMENT = _VAULT_SCHEMA_ELEMENT;
    using VARIANT = _VAULT_VARIANT;
}
#endif