// Copyright (C) 2024 Evan McBroom
//
// Negotiate
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#include "lsa.h"
#include "um/msasn1.h"
#include "um/ntsecpkg.h"
#include <dsgetdc.h>
#include <sspi.h>

#define NEG_CRED_DONT_LINK  0x80000000 // Special flags for AcquireCredHandle
#define NEG_INVALID_PACKAGE ((ULONG_PTR)-1)

#ifdef __cplusplus
extern "C" {
#endif

enum _NEG_DOMAIN_TYPES;
enum _NEG_MATCH;

struct _NEG_CONTEXT;
struct _NEG_CONTEXT_REQ_MAP;
struct _NEG_CRED_HANDLE;
struct _NEG_CREDS;
struct _NEG_EXTRA_OID;
struct _NEG_LOGON_SESSION;
struct _NEG_PACKAGE;
struct _NEG_TRUST_LIST;

typedef enum _NEG_DOMAIN_TYPES {
    NegUpLevelDomain = 0,
    NegUpLevelTrustedDomain = 1,
    NegDownLevelDomain = 2,
    NegLocalDomain = 3
} NEG_DOMAIN_TYPES,
    *PNEG_DOMAIN_TYPES;

typedef enum _NEG_MATCH {
    MatchUnknown = 0,
    PreferredSucceed = 1,
    MatchSucceed = 2,
    MatchFailed = 3
} NEG_MATCH,
    *PNEG_MATCH;

typedef LPVOID PCHECKSUM_BUFFER;
typedef LPVOID PCHECKSUM_FUNCTION; // Defined in NT sources in cryptdll.h
typedef struct MechTypeList* PMechTypeList;

typedef struct _NEG_PACKAGE {
    LIST_ENTRY List;
    PLSAP_SECURITY_PACKAGE LsaPackage;
    ASN1objectidentifier_t ObjectId;
    struct _NEG_PACKAGE* RealPackage;
#define NEG_PREFERRED          0x00000001 // Preferred package
#define NEG_NT4_COMPAT         0x00000002 // NT4 compatible package
#define NEG_PACKAGE_EXTRA_OID  0x00000004 // Package is an extra OID for existing package
#define NEG_PACKAGE_INBOUND    0x00000008 // Package is available for inbound
#define NEG_PACKAGE_OUTBOUND   0x00000010 // Package is available for outbound
#define NEG_PACKAGE_LOOPBACK   0x00000020 // Package is preferred loopback handler
#define NEG_PACKAGE_HAS_EXTRAS 0x00000040 // Package has extra OIDS.
    ULONG Flags;
    ULONG TokenSize;
    ULONG PackageFlags;
    ULONG PrefixLen;
    UCHAR Prefix[NEGOTIATE_MAX_PREFIX];
} NEG_PACKAGE, *PNEG_PACKAGE;

typedef struct _NEG_CRED_HANDLE {
    PNEG_PACKAGE Package;
    CredHandle Handle;
#define NEG_CREDHANDLE_EXTRA_OID 0x00000001
    ULONG Flags;
} NEG_CRED_HANDLE, *PNEG_CRED_HANDLE;

typedef struct _NEG_CREDS {
#define NEGCRED_TAG 'drCN'
    ULONG Tag;
    ULONG RefCount;
    LIST_ENTRY List;
#define NEGCRED_MULTI                 0x00000004 // Contains multiple credentials (deprecated in .NET server)
#define NEGCRED_USE_SNEGO             0x00000008 // Force snego use
#define NEGCRED_KERNEL_CALLER         0x00000010 // This is a kernel caller
#define NEGCRED_EXPLICIT_CREDS        0x00000020 // Explicit creds passed in
#define NEGCRED_MULTI_PART            0x00000040 // Is part of a multi-part credential (deprecated in .NET server)
#define NEGCRED_ALLOW_NTLM            0x00000080 // Allow negotiate down to NTLM
#define NEGCRED_NEG_NTLM              0x00000100 // Negotiate NTLM
#define NEGCRED_NTLM_LOOPBACK         0x00000200 // Use NTLM on loopbacks
#define NEGCRED_DOMAIN_EXPLICIT_CREDS 0x00000400 // Explicit creds with supplied domain passed in
#define NEGCRED_DUP_MASK              (NEGCRED_KERNEL_CALLER)
    ULONG Flags;
    ULONG_PTR DefaultPackage;
    RTL_CRITICAL_SECTION CredLock;
    LIST_ENTRY AdditionalCreds;
    TimeStamp Expiry;
    LUID ClientLogonId;
    DWORD ClientProcessId;
    DWORD Count;
    PUCHAR ServerBuffer;
    DWORD ServerBufferLength;
    NEG_CRED_HANDLE Creds[ANYSIZE_ARRAY];
} NEG_CREDS, *PNEG_CREDS;

typedef struct _NEG_CONTEXT {
#define NEGCONTEXT_CHECK  'XgeN'
#define NEGCONTEXT2_CHECK '2geN'
    ULONG CheckMark;
    PNEG_CREDS Creds;
    ULONG_PTR CredIndex;
    CtxtHandle Handle;
    SECURITY_STRING Target;
    ULONG Attributes;
    SecBuffer MappedBuffer;
    BOOLEAN Mapped;
    UCHAR CallCount;
    SECURITY_STATUS LastStatus;
    PCHECKSUM_FUNCTION Check;
    PCHECKSUM_BUFFER Buffer;
    TimeStamp Expiry;
#define NEG_CONTEXT_PACKAGE_CALLED 0x01 // Have called a package
#define NEG_CONTEXT_FREE_EACH_MECH 0x02 // Free all mechs
#define NEG_CONTEXT_NEGOTIATING    0x04 // Many round trips
#define NEG_CONTEXT_FRAGMENTING    0x08 // Fragmented blob
#define NEG_CONTEXT_FRAG_INBOUND   0x10 // Assembling an input
#define NEG_CONTEXT_FRAG_OUTBOUND  0x20 // Providing an output
#define NEG_CONTEXT_UPLEVEL        0x40 // Stick to the RFC2478
#define NEG_CONTEXT_MUTUAL_AUTH    0x80 // Set mutual auth bit
    ULONG Flags;
    PUCHAR Message;
    ULONG CurrentSize;
    ULONG TotalSize;
    PMechTypeList SupportedMechs;
} NEG_CONTEXT, *PNEG_CONTEXT;

typedef struct _NEG_CONTEXT_REQ_MAP {
#define NEG_CONFIG_REQUIRED 0x00000001
#define NEG_CONFIG_OPTIONAL 0x00000002
    ULONG Level;
    ULONG ConfigFlags;
    ULONG ContextReq;
    ULONG PackageFlag;
} NEG_CONTEXT_REQ_MAP, *PNEG_CONTEXT_REQ_MAP;

typedef struct _NEG_EXTRA_OID {
    ULONG Attributes;
    ASN1objectidentifier_t Oid;
} NEG_EXTRA_OID, *PNEG_EXTRA_OID;

typedef struct _NEG_LOGON_SESSION {
    LIST_ENTRY List;
    ULONG_PTR CreatingPackage; // Package that created this logon
    ULONG_PTR DefaultPackage; // Default package to use for this logon
    UNICODE_STRING AlternateName; // Alternate name associated with this logon
    LUID LogonId; // Logon Id of this logon
    LUID ParentLogonId; // Logon Id of creating session
    ULONG RefCount; // Ref
} NEG_LOGON_SESSION, *PNEG_LOGON_SESSION;

typedef struct _NEG_TRUST_LIST {
    ULONG RefCount;
    ULONG TrustCount;
    PDS_DOMAIN_TRUSTSW Trusts;
} NEG_TRUST_LIST, *PNEG_TRUST_LIST;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Negotiate {
    // Enumerations
    enum _NEG_DOMAIN_TYPES;
    enum _NEG_MATCH;

    using CALLER_NAME_REQUEST = _NEGOTIATE_CALLER_NAME_REQUEST;
    using CALLER_NAME_RESPONSE = _NEGOTIATE_CALLER_NAME_RESPONSE;
    using CALLER_NAME_RESPONSE_WOW = _NEGOTIATE_CALLER_NAME_RESPONSE_WOW;
    using CONTEXT = _NEG_CONTEXT;
    using CONTEXT_REQ_MAP = _NEG_CONTEXT_REQ_MAP;
    using CRED_HANDLE = _NEG_CRED_HANDLE;
    using CREDS = _NEG_CREDS;
    using EXTRA_OID = _NEG_EXTRA_OID;
    using LOGON_SESSION = _NEG_LOGON_SESSION;
    using NEGO2_INFO = _SECPKG_NEGO2_INFO;
    using NegoKeys = _SecPkgContext_NegoKeys;
    using NegoPackageInfo = _SecPkgContext_NegoPackageInfo;
    using NegoStatus = _SecPkgContext_NegoStatus;
    using NegotiatedTlsExtensions = _SecPkgContext_NegotiatedTlsExtensions;
    using NEGOTIATION_INFO = _SEC_NEGOTIATION_INFO;
    using NegotiationInfoA = _SecPkgContext_NegotiationInfoA;
    using NegotiationInfoW = _SecPkgContext_NegotiationInfoW;
    using PACKAGE = _NEG_PACKAGE;
    using PACKAGE_NAMES = _NEGOTIATE_PACKAGE_NAMES;
    using PACKAGE_PREFIX = _NEGOTIATE_PACKAGE_PREFIX;
    using PACKAGE_PREFIX_WOW = _NEGOTIATE_PACKAGE_PREFIX_WOW;
    using PACKAGE_PREFIXES = _NEGOTIATE_PACKAGE_PREFIXES;
    using TRUST_LIST = _NEG_TRUST_LIST;
}
#endif