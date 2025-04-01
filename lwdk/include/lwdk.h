// Copyright (C) 2024 Evan McBroom
//
// Lsa whisperer development kit (lwdk)
//
#pragma once
// clang-format of

// The original NTSecPKG.h has numerous compatibility issues
// with other headers. We predefine _NTSECPKG_ so the original
// NTSecPKG.h isn't unintentionally included by another header
// which would cause issues for lwdk.
//#define _NTSECPKG_
#include <phnt_windows.h>
#include <phnt.h>

// Defined and includes that must occur before ntsecapi.h
#include <wincred.h>
#define SECURITY_WIN32 // Required by ntsecapi.h, security.h, and sspi.h
#define _SEC_WINNT_AUTH_TYPES // Required for some types in sspi.h to be defined
#include <sspi.h>
#include <security.h>

#include "um/ntsecapi.h"
#pragma push_macro("TokenSource")
#undef TokenSource
#include "um/ntsecpkg.h"
#pragma pop_macro("TokenSource")
#include <lsalookup.h>

#define CERT_CHAIN_FIND_BY_ISSUER_PARA_HAS_EXTRA_FIELDS
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#define CERT_REVOCATION_PARA_HAS_EXTRA_FIELDS
#define CMSG_ENVELOPED_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_IUM_FIELDS
#define CRYPT_DECRYPT_MESSAGE_PARA_HAS_EXTRA_FIELDS
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CRYPT_SIGN_MESSAGE_PARA_HAS_CMS_FIELDS
#define CRYPT_VERIFY_MESSAGE_PARA_HAS_EXTRA_FIELDS
#include <wincrypt.h>

#include <winsmcrd.h>
// clang-format on

// Miscellaneous cpdk headers not included elsewhere cardmod.h
// and msclmd.h are not included here because both include
// winscard.h which itself includes winioctl.h. The winioctl.h
// header has types that are defined outside of an include
// guard. Microsoft left a comment that this was done to be
// "helpful", but it causes type redefinitions when winioctl.h
// is included multiple times. winioctl.h is already included
// by phnt_windows.h so we must avoid included it again.
#include "cpdk/cspdk.h"

// MIDL generated headers
#include "cloudap_m.h"
#include "ngc_c.h"
#include "wlid_c.h"
#include "wlid_m.h"

#include "lwdk/cloudap.h"
#include "lwdk/cng.h"
#include "lwdk/credman.h"
#include "lwdk/credssp.h"
#include "lwdk/crypt.h"
#include "lwdk/cssp.h"
#include "lwdk/dpapi.h"
#include "lwdk/dpaping.h"
#include "lwdk/efs.h"
#include "lwdk/fve.h"
#include "lwdk/kerberos.h"
#include "lwdk/krb5.h"
#include "lwdk/ksecdd.h"
#include "lwdk/livessp.h"
#include "lwdk/lsa.h"
#include "lwdk/msv1_0.h"
#include "lwdk/native.h"
#include "lwdk/negoexts.h"
#include "lwdk/negotiate.h"
#include "lwdk/netlogon.h"
#include "lwdk/ngc.h"
#include "lwdk/ntasn1.h"
#include "lwdk/ntlm.h"
#include "lwdk/pku2u.h"
#include "lwdk/rdpear.h"
#include "lwdk/schannel.h"
#include "lwdk/spm.h"
#include "lwdk/spnego.h"
#include "lwdk/tspkg.h"
#include "lwdk/vault.h"
#include "lwdk/wdigest.h"