// Copyright (C) 2024 Evan McBroom
//
// Encryption API (crypt)
//
#pragma once
#include <phnt_windows.h> // Will include ntsam.h which defines several types originally from crypt.h

#define BLOCK_KEY_LENGTH    7
#define CLEAR_BLOCK_LENGTH  8
#define CYPHER_BLOCK_LENGTH 8

#define ENCRYPTED_LM_OWF_PASSWORD_LENGTH (CYPHER_BLOCK_LENGTH * 2)
#define LM_CHALLENGE_LENGTH              CLEAR_BLOCK_LENGTH
#define LM_OWF_PASSWORD_LENGTH           (CYPHER_BLOCK_LENGTH * 2)
#define LM_RESPONSE_LENGTH               (CYPHER_BLOCK_LENGTH * 3)
#define USER_SESSION_KEY_LENGTH          (CYPHER_BLOCK_LENGTH * 2)

#define ENCRYPTED_NT_OWF_PASSWORD_LENGTH ENCRYPTED_LM_OWF_PASSWORD_LENGTH
#define LM_SESSION_KEY_LENGTH            LM_CHALLENGE_LENGTH
#define NT_CHALLENGE_LENGTH              LM_CHALLENGE_LENGTH
#define NT_OWF_PASSWORD_LENGTH           LM_OWF_PASSWORD_LENGTH
#define NT_RESPONSE_LENGTH               LM_RESPONSE_LENGTH
#define NT_SESSION_KEY_LENGTH            LM_SESSION_KEY_LENGTH
#define SHA_OWF_PASSWORD_LENGTH          20

#define RTL_ENCRYPT_MEMORY_SIZE          8
#define RTL_ENCRYPT_OPTION_CROSS_PROCESS 0x01 // Allow Encrypt/Decrypt across process boundaries
#define RTL_ENCRYPT_OPTION_SAME_LOGON    0x02 // Allow Encrypt/Decrypt across callers with same LogonId

// System functions 36, 40, and 41 are defined here for
// posterity but commented out because they are already
// defined by ntsecapi.h.
#define RtlEncryptBlock                   SystemFunction001
#define RtlDecryptBlock                   SystemFunction002
#define RtlEncryptStdBlock                SystemFunction003
#define RtlEncryptData                    SystemFunction004
#define RtlDecryptData                    SystemFunction005
#define RtlCalculateLmOwfPassword         SystemFunction006
#define RtlCalculateNtOwfPassword         SystemFunction007
#define RtlCalculateLmResponse            SystemFunction008
#define RtlCalculateNtResponse            SystemFunction009
#define RtlCalculateUserSessionKeyLm      SystemFunction010
#define RtlCalculateUserSessionKeyNt      SystemFunction011
#define RtlEncryptLmOwfPwdWithLmOwfPwd    SystemFunction012
#define RtlDecryptLmOwfPwdWithLmOwfPwd    SystemFunction013
#define RtlEncryptNtOwfPwdWithNtOwfPwd    SystemFunction014
#define RtlDecryptNtOwfPwdWithNtOwfPwd    SystemFunction015
#define RtlEncryptLmOwfPwdWithLmSesKey    SystemFunction016
#define RtlDecryptLmOwfPwdWithLmSesKey    SystemFunction017
#define RtlEncryptNtOwfPwdWithNtSesKey    SystemFunction018
#define RtlDecryptNtOwfPwdWithNtSesKey    SystemFunction019
#define RtlEncryptLmOwfPwdWithUserKey     SystemFunction020
#define RtlDecryptLmOwfPwdWithUserKey     SystemFunction021
#define RtlEncryptNtOwfPwdWithUserKey     SystemFunction022
#define RtlDecryptNtOwfPwdWithUserKey     SystemFunction023
#define RtlEncryptLmOwfPwdWithIndex       SystemFunction024
#define RtlDecryptLmOwfPwdWithIndex       SystemFunction025
#define RtlEncryptNtOwfPwdWithIndex       SystemFunction026
#define RtlDecryptNtOwfPwdWithIndex       SystemFunction027
#define RtlGetUserSessionKeyClient        SystemFunction028
#define RtlGetUserSessionKeyServer        SystemFunction029
#define RtlEqualLmOwfPassword             SystemFunction030
#define RtlEqualNtOwfPassword             SystemFunction031
#define RtlEncryptData2                   SystemFunction032
#define RtlDecryptData2                   SystemFunction033
#define RtlGetUserSessionKeyClientBinding SystemFunction034
#define RtlCheckSignatureInFile           SystemFunction035
// #define RtlGenRandom                      SystemFunction036
// #define RtlEncryptMemory                  SystemFunction040
// #define RtlDecryptMemory                  SystemFunction041

#ifdef __cplusplus
extern "C" {
#endif

struct _BLOCK_KEY;
struct _CLEAR_BLOCK;
struct _CRYPT_BUFFER;
struct _CYPHER_BLOCK;
struct _ENCRYPTED_LM_OWF_PASSWORD;
struct _LM_OWF_PASSWORD;
struct _LM_RESPONSE;
struct _USER_SESSION_KEY;
struct SHA_OWF_PASSWORD;

typedef struct _BLOCK_KEY {
    CHAR data[BLOCK_KEY_LENGTH];
} BLOCK_KEY, *PBLOCK_KEY;

typedef struct _CLEAR_BLOCK {
    CHAR data[CLEAR_BLOCK_LENGTH];
} CLEAR_BLOCK, *PCLEAR_BLOCK;

typedef CLEAR_BLOCK LM_CHALLENGE;
typedef LM_CHALLENGE* PLM_CHALLENGE;

typedef LM_CHALLENGE LM_SESSION_KEY;
typedef LM_SESSION_KEY* PLM_SESSION_KEY;

typedef LM_CHALLENGE NT_CHALLENGE;
typedef NT_CHALLENGE* PNT_CHALLENGE;

typedef LM_SESSION_KEY NT_SESSION_KEY;
typedef NT_SESSION_KEY* PNT_SESSION_KEY;

typedef struct _CRYPT_BUFFER {
    ULONG Length;
    ULONG MaximumLength;
    LPVOID Buffer;
} CRYPT_BUFFER, *PCRYPT_BUFFER;

typedef CRYPT_BUFFER CLEAR_DATA;
typedef CLEAR_DATA* PCLEAR_DATA;

typedef CRYPT_BUFFER CYPHER_DATA;
typedef CYPHER_DATA* PCYPHER_DATA;

typedef CRYPT_BUFFER DATA_KEY;
typedef DATA_KEY* PDATA_KEY;

typedef struct _LM_OWF_PASSWORD {
    CYPHER_BLOCK data[2];
} LM_OWF_PASSWORD, *PLM_OWF_PASSWORD;

typedef LM_OWF_PASSWORD NT_OWF_PASSWORD;
typedef NT_OWF_PASSWORD* PNT_OWF_PASSWORD;

typedef struct _LM_RESPONSE {
    CYPHER_BLOCK data[3];
} LM_RESPONSE, *PLM_RESPONSE;

typedef LM_RESPONSE NT_RESPONSE;
typedef NT_RESPONSE* PNT_RESPONSE;

typedef struct _USER_SESSION_KEY {
    CYPHER_BLOCK data[2];
} USER_SESSION_KEY, *PUSER_SESSION_KEY;

typedef LONG CRYPT_INDEX;
typedef CRYPT_INDEX* PCRYPT_INDEX;

typedef CHAR* PLM_PASSWORD;

typedef UNICODE_STRING NT_PASSWORD;
typedef NT_PASSWORD* PNT_PASSWORD;

typedef struct SHA_OWF_PASSWORD {
    CHAR Data[SHA_OWF_PASSWORD_LENGTH];
} SHA_OWF_PASSWORD, *PSHA_OWF_PASSWORD;

// Block encryption
NTSTATUS RtlEncryptBlock(IN PCLEAR_BLOCK ClearBlock, IN PBLOCK_KEY BlockKey, OUT PCYPHER_BLOCK CypherBlock);
NTSTATUS RtlDecryptBlock(IN PCYPHER_BLOCK CypherBlock, IN PBLOCK_KEY BlockKey, OUT PCLEAR_BLOCK ClearBlock);
NTSTATUS RtlEncryptStdBlock(IN PBLOCK_KEY BlockKey, OUT PCYPHER_BLOCK CypherBlock);

// Arbitrary length data encryption
NTSTATUS RtlEncryptData(IN PCLEAR_DATA ClearData, IN PDATA_KEY DataKey, OUT PCYPHER_DATA CypherData);
NTSTATUS RtlDecryptData(IN PCYPHER_DATA CypherData, IN PDATA_KEY DataKey, OUT PCLEAR_DATA ClearData);

// Faster arbitrary length data encryption using RC4
NTSTATUS RtlEncryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pKey);
NTSTATUS RtlDecryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pKey);

// Password hashing (e.g., one way functions or OWFs)
NTSTATUS RtlCalculateLmOwfPassword(IN PLM_PASSWORD LmPassword, OUT PLM_OWF_PASSWORD LmOwfPassword);
NTSTATUS RtlCalculateNtOwfPassword(IN PNT_PASSWORD NtPassword, OUT PNT_OWF_PASSWORD NtOwfPassword);

// OWF comparison
BOOLEAN RtlEqualLmOwfPassword(IN PLM_OWF_PASSWORD LmOwfPassword1, IN PLM_OWF_PASSWORD LmOwfPassword2);
BOOLEAN RtlEqualNtOwfPassword(IN PNT_OWF_PASSWORD NtOwfPassword1, IN PNT_OWF_PASSWORD NtOwfPassword2);

// Response calculations for server challenges
NTSTATUS RtlCalculateLmResponse(IN PLM_CHALLENGE LmChallenge, IN PLM_OWF_PASSWORD LmOwfPassword, OUT PLM_RESPONSE LmResponse);
NTSTATUS RtlCalculateNtResponse(IN PNT_CHALLENGE NtChallenge, IN PNT_OWF_PASSWORD NtOwfPassword, OUT PNT_RESPONSE NtResponse);

// User session key calculations
NTSTATUS RtlCalculateUserSessionKeyLm(IN PLM_RESPONSE LmResponse, IN PLM_OWF_PASSWORD LmOwfPassword, OUT PUSER_SESSION_KEY UserSessionKey);
NTSTATUS RtlCalculateUserSessionKeyNt(IN PNT_RESPONSE NtResponse, IN PNT_OWF_PASSWORD NtOwfPassword, OUT PUSER_SESSION_KEY UserSessionKey);

// OWF password encryption
NTSTATUS RtlEncryptLmOwfPwdWithLmOwfPwd(IN PLM_OWF_PASSWORD DataLmOwfPassword, IN PLM_OWF_PASSWORD KeyLmOwfPassword, OUT PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword);
NTSTATUS RtlDecryptLmOwfPwdWithLmOwfPwd(IN PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword, IN PLM_OWF_PASSWORD KeyLmOwfPassword, OUT PLM_OWF_PASSWORD DataLmOwfPassword);
NTSTATUS RtlEncryptNtOwfPwdWithNtOwfPwd(IN PNT_OWF_PASSWORD DataNtOwfPassword, IN PNT_OWF_PASSWORD KeyNtOwfPassword, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword);
NTSTATUS RtlDecryptNtOwfPwdWithNtOwfPwd(IN PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword, IN PNT_OWF_PASSWORD KeyNtOwfPassword, OUT PNT_OWF_PASSWORD DataNtOwfPassword);

// OWF password encryption using a session key
NTSTATUS RtlEncryptLmOwfPwdWithLmSesKey(IN PLM_OWF_PASSWORD LmOwfPassword, IN PLM_SESSION_KEY LmSessionKey, OUT PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword);
NTSTATUS RtlDecryptLmOwfPwdWithLmSesKey(IN PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword, IN PLM_SESSION_KEY LmSessionKey, OUT PLM_OWF_PASSWORD LmOwfPassword);
NTSTATUS RtlEncryptNtOwfPwdWithNtSesKey(IN PNT_OWF_PASSWORD NtOwfPassword, IN PNT_SESSION_KEY NtSessionKey, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword);
NTSTATUS RtlDecryptNtOwfPwdWithNtSesKey(IN PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword, IN PNT_SESSION_KEY NtSessionKey, OUT PNT_OWF_PASSWORD NtOwfPassword);

// OWF password encryption using a user session key
NTSTATUS RtlEncryptLmOwfPwdWithUserKey(IN PLM_OWF_PASSWORD LmOwfPassword, IN PUSER_SESSION_KEY UserSessionKey, OUT PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword);
NTSTATUS RtlDecryptLmOwfPwdWithUserKey(IN PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword, IN PUSER_SESSION_KEY UserSessionKey, OUT PLM_OWF_PASSWORD LmOwfPassword);
NTSTATUS RtlEncryptNtOwfPwdWithUserKey(IN PNT_OWF_PASSWORD NtOwfPassword, IN PUSER_SESSION_KEY UserSessionKey, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword);
NTSTATUS RtlDecryptNtOwfPwdWithUserKey(IN PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword, IN PUSER_SESSION_KEY UserSessionKey, OUT PNT_OWF_PASSWORD NtOwfPassword);

// OWF password encryption using an index
NTSTATUS RtlEncryptLmOwfPwdWithIndex(IN PLM_OWF_PASSWORD LmOwfPassword, IN PCRYPT_INDEX Index, OUT PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword);
NTSTATUS RtlDecryptLmOwfPwdWithIndex(IN PENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword, IN PCRYPT_INDEX Index, OUT PLM_OWF_PASSWORD LmOwfPassword);
NTSTATUS RtlEncryptNtOwfPwdWithIndex(IN PNT_OWF_PASSWORD NtOwfPassword, IN PCRYPT_INDEX Index, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword);
NTSTATUS RtlDecryptNtOwfPwdWithIndex(IN PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword, IN PCRYPT_INDEX Index, OUT PNT_OWF_PASSWORD NtOwfPassword);

// Miscellaneous
// Functions that are already defined by ntsecapi.h are commented out
NTSTATUS RtlCheckSignatureInFile(IN PWSTR File); // Return type is actually ULONG, but MSVC raises E0311 when that definition is used
// BOOLEAN RtlGenRandom(OUT PVOID RandomBuffer, IN ULONG RandomBufferLength);
// NTSTATUS RtlEncryptMemory(IN OUT PVOID Memory, IN ULONG MemoryLength, IN ULONG OptionFlags);
// NTSTATUS RtlDecryptMemory(IN OUT PVOID Memory, IN ULONG MemoryLength, IN ULONG OptionFlags);

// User session key recovery for an RPC connection
NTSTATUS RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT PUSER_SESSION_KEY UserSessionKey);
NTSTATUS RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE* RedirHandle, OUT PUSER_SESSION_KEY UserSessionKey);
NTSTATUS RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT PUSER_SESSION_KEY UserSessionKey);

#ifdef __cplusplus
} // Closes extern "C" above
namespace Crypt {
    using BLOCK_KEY = _BLOCK_KEY;
    using CLEAR_BLOCK = _CLEAR_BLOCK;
    using CLEAR_DATA = ::CLEAR_DATA;
    using CRYPT_BUFFER = _CRYPT_BUFFER;
    using CRYPT_INDEX = ::CRYPT_INDEX;
    using CYPHER_BLOCK = _CYPHER_BLOCK;
    using CYPHER_DATA = ::CYPHER_DATA;
    using DATA_KEY = ::DATA_KEY;
    using ENCRYPTED_LM_OWF_PASSWORD = _ENCRYPTED_LM_OWF_PASSWORD;
    using ENCRYPTED_NT_OWF_PASSWORD = ::ENCRYPTED_NT_OWF_PASSWORD;
    using LM_CHALLENGE = ::LM_CHALLENGE;
    using LM_OWF_PASSWORD = _LM_OWF_PASSWORD;
    using LM_RESPONSE = _LM_RESPONSE;
    using LM_SESSION_KEY = ::LM_SESSION_KEY;
    using NT_CHALLENGE = ::NT_CHALLENGE;
    using NT_OWF_PASSWORD = ::NT_OWF_PASSWORD;
    using NT_PASSWORD = ::NT_PASSWORD;
    using NT_RESPONSE = ::NT_RESPONSE;
    using NT_SESSION_KEY = ::NT_SESSION_KEY;
    using SHA_OWF_PASSWORD = ::SHA_OWF_PASSWORD;
    using USER_SESSION_KEY = _USER_SESSION_KEY;
}
#endif