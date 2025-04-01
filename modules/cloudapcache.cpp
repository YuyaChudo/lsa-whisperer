#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "lazy.h"
#include "sspi.hpp"
#include <algorithm>
#include <clipp.h>
#include <codecvt>
#include <cppcodec/base64_url.hpp>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <nlohmann/json.hpp>
#include <sstream>
#include <wininet.h>
#include "..\source\boflib.cpp"
using base64 = cppcodec::base64_url;

/// Microsoft supports the following credential types for parsing
/// and unlocking the cloudap cache:
/// - 1: Password
/// - 3: ARSO/TBAL
/// - 4: Smart card
/// - 5: NGC (ex. PIN)
/// - 7: Passkey
///
/// The meaning of credential type 2 and 6 are unknown. Our code
/// currently only fully supports the password and pin credential
/// types. Our code also supports decrypting password protected
/// cloudap cache nodes when provided with a credential key. We
/// denote this in our code with a -1 to not conflict with the
/// positive values used by Microsoft's credential types.
///
/// An enumeration has not been seen identified which lists these
/// credential types and it is assumed that Microsoft internally
/// specifies them with macros. Equivalent macros are defined here,
/// but their naming scheme will be different than what Microsoft
/// internally uses.

#define CLOUDAPCACHE_CREDTYPE_CREDKEY   -1
#define CLOUDAPCACHE_CREDTYPE_PASSWORD  1
#define CLOUDAPCACHE_CREDTYPE_ARSO_TBAL 3
#define CLOUDAPCACHE_CREDTYPE_SMARTCARD 4
#define CLOUDAPCACHE_CREDTYPE_NGC       5
#define CLOUDAPCACHE_CREDTYPE_PASSKEY   7

auto ServiceError = "Please ensure that the \"Microsoft Passport\" service (e.g., ngcsvc) is installed and running.";

// We could manually enumerate provider GUIDs under the following registry key:
// HKLM\SOFTWARE\Microsoft\IdentityStore\Providers
// We currently hard code these GUIDs for brevity since they have not changed.

std::wstring AzureAdProviderGuid{ L"B16898C6-A148-4967-9171-64D755DA8520" };
std::wstring MicrosoftAccountProviderGuid{ L"D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F" };

typedef enum PKCredType {
    Smartcard_PKCredType = 0x0000,
    Ngc_PKCredType = 0x0001,
} PKCredType,
    *PPKCredType;

typedef struct _SCardCacheData {
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwEncodedCertOrPublicKeyOffset;
    DWORD dwEncodedCertOrPublicKeyLength;
    DWORD dwEncKeyIVOffset;
    DWORD dwEncKeyIVLength;
    DWORD dwSCardEncKeyOffset;
    DWORD dwSCardEncKeyLength;
    DWORD dwCredKeyEncKeyOffset;
    DWORD dwCredKeyEncKeyLength;
} SCardCacheData, *PSCardCacheData;

typedef struct _tagCacheNodeIdentifier {
    ULONG dwCredType;
    ULONG cbPublicKey;
    PUCHAR pPublicKey;
} CacheNodeIdentifier, *PCacheNodeIdentifier;

typedef struct _tagNGC_CONTEXTS_DATA {
    PWCHAR pDecryptionKeyName;
    ULONGLONG decryptionAuthTicket;
} NGC_CONTEXTS_DATA, *PNGC_CONTEXTS_DATA;

typedef struct _tagPK_CONTEXTS_DATA {
    PKCredType credType;
    union {
        PSEC_WINNT_AUTH_DATA_TYPE_SMARTCARD_CONTEXTS_DATA pSCardCtxts;
        PNGC_CONTEXTS_DATA pNgcCtxts;
    } cred;
} PK_CONTEXTS_DATA, *PPK_CONTEXTS_DATA;

[[maybe_unused]] NTSTATUS NgcDecryptWithUserIdKeySilent(LPWSTR pwszKeyName, LONGLONG AuthTicket, PBYTE pbInput, DWORD cbInput, PBYTE* ppbOutput, PDWORD pcbOutput);
[[maybe_unused]] NTSTATUS NgcGetLogonDecryptionKeyNameForFirstLogonAfterUpgradeFromThreshold(LPWSTR* ppDecryptionKeyName, LPWSTR* ppwszKeyName);
[[maybe_unused]] NTSTATUS NgcGetUserIdKeyPublicKey(LPWSTR pwszKeyName, PBYTE* ppbNgcUserIdKeyPub, PDWORD pcbNgcUserIdKeyPub);

NTSTATUS CreateBufferChecksum(const std::vector<BYTE>& buffer, std::vector<BYTE>& bufferChecksum);
NTSTATUS DecryptBufferWithKey(const std::vector<BYTE>& cipherText, const std::vector<BYTE>& derivedKey, std::vector<BYTE>& buffer);
NTSTATUS DecryptBufferWithSecret(const std::vector<BYTE>& cipherText, const std::vector<BYTE>& key, std::vector<BYTE>& buffer);
NTSTATUS DeriveKeyFromSecret(const std::vector<BYTE>& secret, std::vector<BYTE>& derivedKey);
NTSTATUS DeserializeCloudAPCache(const std::vector<BYTE>& serializedBuffer, PCloudAPCache pCloudAPCache);
NTSTATUS DeserializeLiveSSPCache(PLIVESSP_SERIALIZED_VALIDATION_INFO pSerializedLiveSSPBuffer, DWORD cbSerializedLiveSSPBuffer, PLiveSSPCache pLiveSSPCache);
NTSTATUS GetBufferChecksumSize(PDWORD pcbBufferChecksum);
NTSTATUS GetCloudAPCacheNode(PCloudAPCache pCloudAPCache, DWORD credType, const std::vector<BYTE>& ngcPublicKey, PCloudAPCacheNode* ppCloudAPCacheNode);
NTSTATUS GetSupportedKeyLengths(BCRYPT_KEY_LENGTHS_STRUCT* pSupportedKeyLengths, PDWORD pdwBlockSize);
NTSTATUS PKDecryptData(PPK_CONTEXTS_DATA pCtxts, const std::vector<BYTE>& cacheData, const std::vector<BYTE>& enc, std::vector<BYTE>& plain);
NTSTATUS PKGetPublicKey(const std::vector<BYTE>& cacheData, std::vector<BYTE>& pbKey);
NTSTATUS UnlockCloudAPCacheNodeData(PCloudAPCache pCloudAPCache, DWORD credType, const std::vector<BYTE>& credBuffer, std::vector<BYTE>& plain);
NTSTATUS ValidateCredType(DWORD credType);
NTSTATUS VerifyLiveSSPCache(PLIVESSP_SERIALIZED_VALIDATION_INFO pSerializedLiveSSPBuffer, DWORD cbSerializedLiveSSPBuffer);
void TriggerNgcTokenService();

/// <summary>
/// The start of the serialized object's memory must be aligned for the
/// function to succeed. That is guaranteed for C++'s vector container
/// but would not be if a pointer was used for input. If you need to
/// reimplement this function with the serialized object specified as a
/// pointer, you should add code to allocate memory to copy the input into
/// before calling RPC's serialization service APIs.
/// </summary>
template<typename Type>
NTSTATUS Deserialize(const std::vector<BYTE>& serializedObject, Type* pObject) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (serializedObject.data() && pObject) {
        handle_t hDecoding;
        if (MesDecodeBufferHandleCreate(reinterpret_cast<PCHAR>(const_cast<PBYTE>(serializedObject.data())), serializedObject.size(), &hDecoding) == RPC_S_OK) {
            if constexpr (std::is_same_v<Type, CloudAPCache>) {
                CloudAPCache_Decode(hDecoding, pObject);
            } else if constexpr (std::is_same_v<Type, LiveSSPCache> || std::is_same_v<Type, DPAPICloudKeyCache>) {
                LiveSSPCache_Decode(hDecoding, pObject);
            } else {
                ntStatus = STATUS_INVALID_PARAMETER;
            }
            MesHandleFree(hDecoding);
        } else {
            ntStatus = STATUS_INTERNAL_ERROR;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

NTSTATUS CreateBufferChecksum(const std::vector<BYTE>& buffer, std::vector<BYTE>& bufferChecksum) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (buffer.size()) {
        BCRYPT_ALG_HANDLE hAlgorithmProvider;
        if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithmProvider, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
            DWORD cbBufferChecksum;
            DWORD cbProperty;
            if (NT_SUCCESS(ntStatus = BCryptGetProperty(hAlgorithmProvider, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&cbBufferChecksum), sizeof(DWORD), &cbProperty, 0)) && cbProperty == sizeof(cbBufferChecksum)) {
                bufferChecksum.resize(cbBufferChecksum, '\0');
                BCRYPT_HASH_HANDLE hHash;
                if (NT_SUCCESS(ntStatus = BCryptCreateHash(hAlgorithmProvider, &hHash, nullptr, 0, nullptr, 0, 0))) {
                    if (NT_SUCCESS(ntStatus = BCryptHashData(hHash, const_cast<PUCHAR>(buffer.data()), buffer.size(), 0))) {
                        ntStatus = BCryptFinishHash(hHash, bufferChecksum.data(), bufferChecksum.size(), 0);
                    }
                    (void)BCryptDestroyHash(hHash);
                }
            }
        }
        (void)BCryptCloseAlgorithmProvider(hAlgorithmProvider, 0);
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

NTSTATUS DecryptBufferWithKey(const std::vector<BYTE>& cipherText, const std::vector<BYTE>& derivedKey, std::vector<BYTE>& buffer) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    DWORD blockSize;
    if (NT_SUCCESS(ntStatus = GetSupportedKeyLengths(nullptr, &blockSize))) {
        BCRYPT_ALG_HANDLE hAlgorithmProvider;
        if (NT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithmProvider, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
            BCRYPT_KEY_HANDLE hKey;
            if (NT_SUCCESS(ntStatus = BCryptGenerateSymmetricKey(hAlgorithmProvider, &hKey, nullptr, 0, const_cast<PUCHAR>(derivedKey.data()), derivedKey.size(), 0))) {
                ULONG cbOutput;
                if (NT_SUCCESS(ntStatus = BCryptDecrypt(hKey, const_cast<PUCHAR>(cipherText.data()), cipherText.size(), nullptr, nullptr, 0, nullptr, 0, &cbOutput, BCRYPT_BLOCK_PADDING))) {
                    buffer.resize(cbOutput, '\0');
                    ntStatus = BCryptDecrypt(hKey, const_cast<PUCHAR>(cipherText.data()), cipherText.size(), nullptr, nullptr, 0, buffer.data(), buffer.size(), &cbOutput, BCRYPT_BLOCK_PADDING);
                }
                (void)BCryptDestroyKey(hKey);
            }
            (void)BCryptCloseAlgorithmProvider(hAlgorithmProvider, 0);
        }
    }
    return ntStatus;
}

NTSTATUS DecryptBufferWithSecret(const std::vector<BYTE>& cipherText, const std::vector<BYTE>& key, std::vector<BYTE>& buffer) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    std::vector<BYTE> derivedKey;
    if (NT_SUCCESS(ntStatus = DeriveKeyFromSecret(key, derivedKey))) {
        ntStatus = DecryptBufferWithKey(cipherText, derivedKey, buffer);
    }
    return ntStatus;
}

NTSTATUS DeriveKeyFromSecret(const std::vector<BYTE>& secret, std::vector<BYTE>& derivedKey) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    BCRYPT_KEY_LENGTHS_STRUCT supportedKeyLengths;
    if (NT_SUCCESS(ntStatus = GetSupportedKeyLengths(&supportedKeyLengths, nullptr))) {
        derivedKey.resize(supportedKeyLengths.dwMaxLength / 8, '\0');
        BCRYPT_ALG_HANDLE hAlgorithmProvider;
        if (NT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithmProvider, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
            ntStatus = BCryptDeriveKeyPBKDF2(hAlgorithmProvider, const_cast<PBYTE>(secret.data()), secret.size(), nullptr, 0, 10000, derivedKey.data(), derivedKey.size(), 0);
            (void)BCryptCloseAlgorithmProvider(hAlgorithmProvider, 0);
        }
    }
    return ntStatus;
}

/// <summary>
/// Deserializes cloudap cache version 2. Cache version 1 was the original LiveSSP cache version
/// which is not used anymore on Windows hosts. If cloudap identifies cache version 1 when a user
/// logs on it will auto migrate it to cache version 2.
///
/// Cache version 2 was used as early as NT 10 1607 and is still the current version as of NT 10 24H2.
/// It is possible but unlikely that Microsoft will develop a new cache version. The format for cache
/// version 2 consists of a DWORD version number, followed by a checksum, and then the RPC serialized
/// contents of the cache.
/// </summary>
NTSTATUS DeserializeCloudAPCache(const std::vector<BYTE>& serializedBuffer, PCloudAPCache pCloudAPCache) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (serializedBuffer.size() && pCloudAPCache) {
        *pCloudAPCache = { 0 };
        // Check the size and version of the cache
        if (serializedBuffer.size() >= 4 && *reinterpret_cast<const DWORD*>(serializedBuffer.data()) == 2) {
            DWORD cbStoredCacheChecksum;
            if (NT_SUCCESS(ntStatus = GetBufferChecksumSize(&cbStoredCacheChecksum)) && serializedBuffer.size() >= cbStoredCacheChecksum + sizeof(DWORD)) {
                auto pStoredCacheChecksum{ serializedBuffer.data() + sizeof(DWORD) };
                std::vector<BYTE> serializedCache(serializedBuffer.size() - sizeof(DWORD) - cbStoredCacheChecksum, '\0');
                std::memcpy(serializedCache.data(), pStoredCacheChecksum + cbStoredCacheChecksum, serializedCache.size());
                std::vector<BYTE> cacheChecksum;
                if (NT_SUCCESS(ntStatus = CreateBufferChecksum(serializedCache, cacheChecksum))) {
                    if (!memcmp(cacheChecksum.data(), pStoredCacheChecksum, cacheChecksum.size())) {
                        if (!NT_SUCCESS(ntStatus = Deserialize<CloudAPCache>(serializedCache, pCloudAPCache))) {
                            *pCloudAPCache = { 0 };
                        }
                    } else {
                        ntStatus = STATUS_DATA_CHECKSUM_ERROR;
                    }
                }
            }
        } else {
            ntStatus = STATUS_INVALID_PARAMETER;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

/// <summary>
/// This method is based on cloudap!GetLiveSSPCacheFromBuffer but renamed to conform
/// with the other APIs within the cloudap module.
///
/// The LiveSSP cache was the original cache format for storing authentication data for
/// cloud based accounts. The format consisted of a header to validate the data, followed
/// by a DWORD version number, checksum, and then the RPC serialized contents of the cache.
/// The version number for a LiveSSP cache is 1, unlike the newer cloudap cache version
/// which is set to 2. If cloudap identifies cache version 1 when a user logs on it will
/// auto migrate it to cache version 2. Both the AzureAD and Microsoft Account plugins for
/// cloudap now use the same version 2 cache format.
/// </summary>
NTSTATUS DeserializeLiveSSPCache(PLIVESSP_SERIALIZED_VALIDATION_INFO pSerializedLiveSSPBuffer, DWORD cbSerializedLiveSSPBuffer, PLiveSSPCache pLiveSSPCache) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pSerializedLiveSSPBuffer && pLiveSSPCache && NT_SUCCESS(VerifyLiveSSPCache(pSerializedLiveSSPBuffer, cbSerializedLiveSSPBuffer))) {
        *pLiveSSPCache = { 0 };
        if (pSerializedLiveSSPBuffer->liveSSPCacheOffset && pSerializedLiveSSPBuffer->cbLiveSSPCache) {
            std::vector<BYTE> serializedBuffer(pSerializedLiveSSPBuffer->cbLiveSSPCache, '\0');
            std::memcpy(serializedBuffer.data(), reinterpret_cast<PBYTE>(pSerializedLiveSSPBuffer) + pSerializedLiveSSPBuffer->liveSSPCacheOffset, serializedBuffer.size());
            // Check the version of the cache
            if (*reinterpret_cast<const DWORD*>(serializedBuffer.data()) == 1) {
                DWORD cbStoredCacheChecksum;
                if (NT_SUCCESS(ntStatus = GetBufferChecksumSize(&cbStoredCacheChecksum)) && serializedBuffer.size() >= cbStoredCacheChecksum + sizeof(DWORD)) {
                    auto pStoredCacheChecksum{ serializedBuffer.data() + sizeof(DWORD) };
                    std::vector<BYTE> serializedCache(serializedBuffer.size() - sizeof(DWORD) - cbStoredCacheChecksum, '\0');
                    std::memcpy(serializedCache.data(), pStoredCacheChecksum + cbStoredCacheChecksum, serializedCache.size());
                    std::vector<BYTE> cacheChecksum;
                    if (NT_SUCCESS(ntStatus = CreateBufferChecksum(serializedCache, cacheChecksum))) {
                        if (!memcmp(cacheChecksum.data(), pStoredCacheChecksum, cacheChecksum.size())) {
                            if (!NT_SUCCESS(ntStatus = Deserialize<LiveSSPCache>(serializedCache, pLiveSSPCache))) {
                                *pLiveSSPCache = { 0 };
                            }
                        } else {
                            ntStatus = STATUS_DATA_CHECKSUM_ERROR;
                        }
                    }
                }
            } else {
                ntStatus = STATUS_INVALID_PARAMETER;
            }
        } else {
            ntStatus = STATUS_NOT_FOUND;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

NTSTATUS GetBufferChecksumSize(PDWORD pcbBufferChecksum) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pcbBufferChecksum) {
        *pcbBufferChecksum = 0;
        BCRYPT_ALG_HANDLE hAlgorithmProvider;
        if (NT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithmProvider, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
            DWORD cbProperty;
            if (!NT_SUCCESS(ntStatus = BCryptGetProperty(hAlgorithmProvider, BCRYPT_HASH_LENGTH, PUCHAR(pcbBufferChecksum), sizeof(DWORD), &cbProperty, 0)) || cbProperty != sizeof(*pcbBufferChecksum)) {
                ntStatus = STATUS_INTERNAL_ERROR;
            }
            (void)BCryptCloseAlgorithmProvider(hAlgorithmProvider, 0);
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

/// <summary>
/// Microsoft's code can locate cache nodes for credential types 1-7.
/// Our code currently only handles credential types 1-5. Please refer
/// to the documentation for ValidateCredType for a reference of what
/// each credential type means.
/// </summary>
NTSTATUS GetCloudAPCacheNode(PCloudAPCache pCloudAPCache, DWORD credType, const std::vector<BYTE>& ngcPublicKey, PCloudAPCacheNode* ppCloudAPCacheNode) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pCloudAPCache && pCloudAPCache->cCloudAPCacheNodes && ppCloudAPCacheNode) {
        *ppCloudAPCacheNode = nullptr;
        for (size_t index{ 0 }; index < pCloudAPCache->cCloudAPCacheNodes; index++) {
            auto pCacheNode{ reinterpret_cast<PCloudAPCacheNode>(pCloudAPCache->pCloudAPCacheNodes + index) };
            if (pCacheNode->credType == credType) {
                if (pCacheNode->credType == CLOUDAPCACHE_CREDTYPE_PASSWORD ||
                    pCacheNode->credType == CLOUDAPCACHE_CREDTYPE_ARSO_TBAL ||
                    pCacheNode->credType == CLOUDAPCACHE_CREDTYPE_SMARTCARD) {
                    *ppCloudAPCacheNode = pCacheNode;
                    break;
                } else if (pCacheNode->credType == 2 || pCacheNode->credType == CLOUDAPCACHE_CREDTYPE_NGC) {
                    if (!ngcPublicKey.size()) {
                        ntStatus = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    if (pCacheNode->credType == 2 &&
                        pCacheNode->pEncryptedCredHashOrPublicKey && pCacheNode->cbEncryptedCredHashOrPublicKey &&
                        pCacheNode->cbEncryptedCredHashOrPublicKey == ngcPublicKey.size() &&
                        !std::memcpy(pCacheNode->pEncryptedCredHashOrPublicKey, ngcPublicKey.data(), ngcPublicKey.size())) {
                        *ppCloudAPCacheNode = pCacheNode;
                        break;
                    } else if (pCacheNode->credType == CLOUDAPCACHE_CREDTYPE_NGC &&
                               pCacheNode->pEncryptedCredHashOrPublicKey && pCacheNode->cbEncryptedCredHashOrPublicKey) {
                        std::vector<BYTE> cacheData(pCacheNode->cbEncryptedCredHashOrPublicKey, '\0');
                        std::memcpy(cacheData.data(), pCacheNode->pEncryptedCredHashOrPublicKey, cacheData.size());
                        std::vector<BYTE> pbKey;
                        PKGetPublicKey(cacheData, pbKey);
                        // Microsoft additionally does a comparison of the public key modulus.
                        // Our code's reimplementation of this check is slightly off so we
                        // currently skip that check.
                        if (pbKey.size() == ngcPublicKey.size() /* &&
                            !std::memcpy(pbKey.data(), ngcPublicKey.data(), ngcPublicKey.size()) */
                        ) {
                            *ppCloudAPCacheNode = pCacheNode;
                            break;
                        }
                    }
                }
            }
        }
        if (!*ppCloudAPCacheNode) {
            ntStatus = STATUS_NOT_FOUND;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

NTSTATUS GetSupportedKeyLengths(BCRYPT_KEY_LENGTHS_STRUCT* pSupportedKeyLengths, PDWORD pdwBlockSize) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pSupportedKeyLengths || pdwBlockSize) {
        BCRYPT_ALG_HANDLE hAlgorithmProvider;
        if (NT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithmProvider, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
            ULONG cbProperty;
            if (pSupportedKeyLengths) {
                if (NT_SUCCESS(ntStatus = BCryptGetProperty(hAlgorithmProvider, BCRYPT_KEY_LENGTHS, reinterpret_cast<PUCHAR>(pSupportedKeyLengths), sizeof(BCRYPT_KEY_LENGTHS_STRUCT), &cbProperty, 0))) {
                    if (cbProperty != sizeof(BCRYPT_KEY_LENGTHS_STRUCT)) {
                        ntStatus = STATUS_INTERNAL_ERROR;
                    }
                }
            }
            if (pdwBlockSize) {
                if (NT_SUCCESS(ntStatus = BCryptGetProperty(hAlgorithmProvider, BCRYPT_BLOCK_LENGTH, reinterpret_cast<PUCHAR>(pdwBlockSize), sizeof(DWORD), &cbProperty, 0))) {
                    if (cbProperty != sizeof(DWORD)) {
                        ntStatus = STATUS_INTERNAL_ERROR;
                    }
                }
            }
            BCryptCloseAlgorithmProvider(hAlgorithmProvider, 0);
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

/// <summary>
/// Microsoft's code can decrypt both the Smartcard_PKCredType and Ngc_PKCredType
/// public key context types. Our code can currently only decrypt the Ngc_PKCredType
/// public key context type.
/// </summary>
NTSTATUS PKDecryptData(PPK_CONTEXTS_DATA pCtxts, const std::vector<BYTE>& cacheData, const std::vector<BYTE>& enc, std::vector<BYTE>& plain) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pCtxts && pCtxts->credType == Ngc_PKCredType) {
        PNGC_CONTEXTS_DATA pNgcCtxts{ pCtxts->cred.pNgcCtxts };
        if (pNgcCtxts && pNgcCtxts->pDecryptionKeyName) {
            LAZY_LOAD_LIBRARY_AND_PROC(CryptNgc, NgcDecryptWithUserIdKeySilent);
            if (LazyCryptNgc) {
                auto sCardCacheData{ reinterpret_cast<const SCardCacheData*>(cacheData.data()) };
                PBYTE pbAesKey;
                DWORD cbAesKey;
                if (NT_SUCCESS(ntStatus = LazyNgcDecryptWithUserIdKeySilent(pNgcCtxts->pDecryptionKeyName, pNgcCtxts->decryptionAuthTicket, const_cast<BYTE*>(cacheData.data()) + sCardCacheData->dwSCardEncKeyOffset, sCardCacheData->dwSCardEncKeyLength, &pbAesKey, &cbAesKey))) {
                    BCRYPT_KEY_HANDLE hAesKey;
                    if (NT_SUCCESS(ntStatus = BCryptGenerateSymmetricKey(BCRYPT_AES_CBC_ALG_HANDLE, &hAesKey, nullptr, 0, pbAesKey, cbAesKey, 0))) {
                        if (NT_SUCCESS(ntStatus = BCryptSetProperty(hAesKey, BCRYPT_INITIALIZATION_VECTOR, const_cast<BYTE*>(cacheData.data()) + sCardCacheData->dwEncKeyIVOffset, sCardCacheData->dwEncKeyIVLength, 0))) {
                            DWORD cbPlain;
                            if (NT_SUCCESS(ntStatus = BCryptDecrypt(hAesKey, const_cast<BYTE*>(enc.data()), enc.size(), nullptr, nullptr, 0, nullptr, 0, &cbPlain, BCRYPT_BLOCK_PADDING))) {
                                plain.resize(cbPlain, '\0');
                                ntStatus = BCryptDecrypt(hAesKey, const_cast<BYTE*>(enc.data()), enc.size(), nullptr, nullptr, 0, plain.data(), cbPlain, &cbPlain, BCRYPT_BLOCK_PADDING);
                            }
                        }
                        (void)BCryptDestroyKey(hAesKey);
                    }
                    (void)LocalFree(pbAesKey);
                }
                (void)FreeLibrary(LazyCryptNgc);
            }
        } else {
            ntStatus = STATUS_INVALID_PARAMETER;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

/// <summary>
/// Locates the public modulus inside a BCRYPT_RSAKEY_BLOB formatted cache data blob.
/// </summary>
NTSTATUS PKGetPublicKey(const std::vector<BYTE>& cacheData, std::vector<BYTE>& pbKey) {
    // Microsoft's code calls ValidateSCardCacheData before locating the public key.
    // Our code currently skips this call for brevity.
    auto rsaKey{ reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(cacheData.data()) };
    pbKey.resize(rsaKey->cbModulus, '\0');
    std::memcpy(pbKey.data(), cacheData.data() + rsaKey->cbPublicExp, rsaKey->cbModulus);
    return STATUS_SUCCESS;
}

/// <summary>
/// Microsoft's code can unlock cache nodes for credential types 1 and 3-7.
/// Our code currently only unlock cache nodes for credential types 1, 3,
/// and 5. Please refer to the documentation for ValidateCredType for a
/// reference of what each credential type means.
/// </summary>
NTSTATUS UnlockCloudAPCacheNodeData(PCloudAPCache pCloudAPCache, DWORD credType, const std::vector<BYTE>& credBuffer, std::vector<BYTE>& plain) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    PCloudAPCacheNode pCacheNode;
    if (pCloudAPCache && NT_SUCCESS(ntStatus = ValidateCredType(credType))) {
        if (credType == CLOUDAPCACHE_CREDTYPE_CREDKEY) {
            if (NT_SUCCESS(ntStatus = GetCloudAPCacheNode(pCloudAPCache, CLOUDAPCACHE_CREDTYPE_PASSWORD, {}, &pCacheNode))) {
                std::vector<BYTE> cipherText(pCacheNode->cbEncryptedCredHashOrPublicKey, 0);
                std::memcpy(cipherText.data(), pCacheNode->pEncryptedCredHashOrPublicKey, cipherText.size());
                std::vector<BYTE> decryptedDerivedKey;
                if (NT_SUCCESS(ntStatus = DecryptBufferWithSecret(cipherText, credBuffer, decryptedDerivedKey))) {
                    // The decrypted key will followed by extra data we don't care about so we resize it
                    // down to the actual size of the key, minus the extra data.
                    BCRYPT_KEY_LENGTHS_STRUCT supportedKeyLengths;
                    if (NT_SUCCESS(ntStatus = GetSupportedKeyLengths(&supportedKeyLengths, nullptr))) {
                        decryptedDerivedKey.resize(supportedKeyLengths.dwMaxLength / 8, '\0');
                        cipherText.resize(pCacheNode->cbEncryptedCacheNodeData, 0);
                        std::memcpy(cipherText.data(), pCacheNode->pEncryptedCacheNodeData, cipherText.size());
                        ntStatus = DecryptBufferWithKey(cipherText, decryptedDerivedKey, plain);
                    }
                }
            }
        } else if (credType == CLOUDAPCACHE_CREDTYPE_PASSWORD || credType == CLOUDAPCACHE_CREDTYPE_ARSO_TBAL) {
            if (NT_SUCCESS(ntStatus = GetCloudAPCacheNode(pCloudAPCache, credType, {}, &pCacheNode))) {
                std::vector<BYTE> cipherText(pCacheNode->cbEncryptedCacheNodeData, 0);
                std::memcpy(cipherText.data(), pCacheNode->pEncryptedCacheNodeData, cipherText.size());
                ntStatus = DecryptBufferWithSecret(cipherText, credBuffer, plain);
            }
        } else if (credType == CLOUDAPCACHE_CREDTYPE_NGC) {
            if (credBuffer.size() == sizeof(NGC_CONTEXTS_DATA)) {
                LAZY_LOAD_LIBRARY_AND_PROC(CryptNgc, NgcGetUserIdKeyPublicKey);
                if (LazyCryptNgc) {
                    PBYTE pEncryptionPublicKey;
                    DWORD cbEncryptionPublicKey;
                    if (NT_SUCCESS(LazyNgcGetUserIdKeyPublicKey(PNGC_CONTEXTS_DATA(credBuffer.data())->pDecryptionKeyName, &pEncryptionPublicKey, &cbEncryptionPublicKey))) {
                        std::vector<BYTE> pbKey(cbEncryptionPublicKey, '\0');
                        std::memcpy(pbKey.data(), pEncryptionPublicKey, cbEncryptionPublicKey);
                        if (NT_SUCCESS(ntStatus = GetCloudAPCacheNode(pCloudAPCache, credType, pbKey, &pCacheNode))) {
                            PK_CONTEXTS_DATA pkCtxts;
                            pkCtxts.credType = Ngc_PKCredType;
                            pkCtxts.cred.pNgcCtxts = PNGC_CONTEXTS_DATA(credBuffer.data());
                            std::vector<BYTE> cacheData(pCacheNode->cbEncryptedCredHashOrPublicKey, 0);
                            std::memcpy(cacheData.data(), pCacheNode->pEncryptedCredHashOrPublicKey, cacheData.size());
                            std::vector<BYTE> enc(pCacheNode->cbEncryptedCacheNodeData, 0);
                            std::memcpy(enc.data(), pCacheNode->pEncryptedCacheNodeData, enc.size());
                            ntStatus = PKDecryptData(&pkCtxts, cacheData, enc, plain);
                        }
                        LocalFree(pEncryptionPublicKey);
                    }
                    FreeLibrary(LazyCryptNgc);
                } else {
                    ntStatus = STATUS_INTERNAL_ERROR;
                }
            } else {
                ntStatus = STATUS_INVALID_PARAMETER_3;
            }
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

/// <summary>
/// Microsoft supports the following credential types:
/// - 1: Password
/// - 3: ARSO/TBAL
/// - 4: Smart card
/// - 5: NGC (ex. PIN)
/// - 6: Unknown
/// - 7: Passkey
/// The meaning of credential type 2 is also unknown. We currently
/// only support a subset of Microsoft's code (e.g., passwords,
/// ARSO/TBAL, and PINs) when unlocking cache nodes.
/// </summary>
NTSTATUS ValidateCredType(DWORD credType) {
    return (credType == CLOUDAPCACHE_CREDTYPE_CREDKEY ||
               credType == CLOUDAPCACHE_CREDTYPE_PASSWORD ||
               credType == CLOUDAPCACHE_CREDTYPE_ARSO_TBAL ||
               credType == CLOUDAPCACHE_CREDTYPE_NGC)
               ? STATUS_SUCCESS
               : STATUS_INVALID_PARAMETER;
}

/// <summary>
/// This method is based on cloudap!VerifyLiveSSPBufferIntegrity but renamed to conform
/// with the other APIs within the cloudap module.
/// </summary>
NTSTATUS VerifyLiveSSPCache(PLIVESSP_SERIALIZED_VALIDATION_INFO pSerializedLiveSSPBuffer, DWORD cbSerializedLiveSSPBuffer) {
    NTSTATUS ntStatus{ STATUS_SUCCESS };
    if (pSerializedLiveSSPBuffer &&
        cbSerializedLiveSSPBuffer >= sizeof(LIVESSP_SERIALIZED_VALIDATION_INFO) &&
        cbSerializedLiveSSPBuffer == pSerializedLiveSSPBuffer->cbStructureLength &&
        pSerializedLiveSSPBuffer->cbHeaderLength == sizeof(LIVESSP_SERIALIZED_VALIDATION_INFO) &&
        pSerializedLiveSSPBuffer->bufferVersion == 2 &&
        pSerializedLiveSSPBuffer->credType == CLOUDAPCACHE_CREDTYPE_PASSWORD) {
        if (pSerializedLiveSSPBuffer->uniqueIdOffset > pSerializedLiveSSPBuffer->cbStructureLength ||
            pSerializedLiveSSPBuffer->cbUniqueId > (pSerializedLiveSSPBuffer->cbStructureLength - pSerializedLiveSSPBuffer->uniqueIdOffset) ||
            pSerializedLiveSSPBuffer->credHashOffset > pSerializedLiveSSPBuffer->cbStructureLength ||
            pSerializedLiveSSPBuffer->cbCredHash > pSerializedLiveSSPBuffer->cbStructureLength - pSerializedLiveSSPBuffer->credHashOffset ||
            pSerializedLiveSSPBuffer->liveSSPCacheOffset > pSerializedLiveSSPBuffer->cbStructureLength ||
            pSerializedLiveSSPBuffer->cbLiveSSPCache > (pSerializedLiveSSPBuffer->cbStructureLength - pSerializedLiveSSPBuffer->liveSSPCacheOffset) ||
            pSerializedLiveSSPBuffer->daTokenOffset > pSerializedLiveSSPBuffer->cbStructureLength ||
            pSerializedLiveSSPBuffer->cbDAToken > (pSerializedLiveSSPBuffer->cbStructureLength - pSerializedLiveSSPBuffer->daTokenOffset) ||
            pSerializedLiveSSPBuffer->sessionKeyOffset > pSerializedLiveSSPBuffer->cbStructureLength ||
            pSerializedLiveSSPBuffer->cbSessionKey > (pSerializedLiveSSPBuffer->cbStructureLength - pSerializedLiveSSPBuffer->sessionKeyOffset)) {
            ntStatus = STATUS_DATA_OVERRUN;
        }
    } else {
        ntStatus = STATUS_INVALID_PARAMETER;
    }
    return ntStatus;
}

// clang-format off
/// <summary>
/// Start the NGC service by triggering one of the NetworkEndpoint
/// service triggers that are set for the LiveIdSvc RPC interface.
/// </summary>
void TriggerNgcTokenService() {
    RpcTryExcept
        RPC_BINDING_HANDLE binding;
        if (RpcBindingFromStringBindingW(RPC_WSTR(L"ncalrpc:"), &binding) == RPC_S_OK) {
            (void)RpcEpResolveBinding(binding, NgcTicket_v1_0_c_ifspec);
            (void)RpcBindingFree(&binding);
        }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    RpcEndExcept
}
// clang-format on

void ShowCache(PCloudAPCache cloudApCache) {
    std::cout << "CloudAPCache" << std::endl;
    std::cout << "    Flags      : " << cloudApCache->flags << std::endl;
    RPC_CSTR guidString;
    UuidToStringA(&cloudApCache->credKeyVersion, &guidString);
    std::cout << "    Cred key id: " << reinterpret_cast<char*>(guidString) << std::endl;
    RpcStringFreeA(&guidString);
    std::cout << "    Cache nodes: " << cloudApCache->cCloudAPCacheNodes << std::endl;
    for (size_t index{ 0 }; index < cloudApCache->cCloudAPCacheNodes; index++) {
        auto pCacheNode{ cloudApCache->pCloudAPCacheNodes + index };
        std::cout << "        Type: " << pCacheNode->credType
                  << std::hex << std::setfill('0') << std::setw(4) << std::uppercase
                  << " (cred-hash/pub-key size: 0x" << pCacheNode->cbEncryptedCredHashOrPublicKey
                  << ") (data size: 0x" << pCacheNode->cbEncryptedCacheNodeData << ")" << std::endl;
    }
}

void ShowCacheNode(PCloudAPCache cloudApCache, DWORD credType, std::vector<BYTE>& credBuffer) {
    std::vector<BYTE> plain;
    if (NT_SUCCESS(UnlockCloudAPCacheNodeData(cloudApCache, credType, credBuffer, plain)) && plain.size()) {
        std::cout << "    Unlocked node: (cred type: " << credType << ")" << std::endl;
        // The cache node header conforms to the first 0x10 bytes of PCloudAPCacheNodeData2
        auto nodeData2{ reinterpret_cast<PCloudAPCacheNodeData2>(plain.data()) };
        // name but follows the following format:
        //   0x0 - hardcoded to 0
        //   0x4 - hardcoded to 1
        //   0x8 - dwFlags
        //   0xc - cbCredKey
        // Please refer to cloudap!CreateCacheNodeDataBuffer for more information.
        std::cout << "        Magic    : " << nodeData2->dwMagic << std::endl;
        std::cout << "        Version  : " << nodeData2->dwVersion << std::endl;
        std::cout << "        Flags    : " << nodeData2->dwFlags << std::endl;
        std::cout << "        CredKey  : (size: 0x"
                  << std::hex << std::setfill('0') << std::setw(2) << std::uppercase
                  << nodeData2->cbCredKey << ")" << std::endl;
        auto credKey{ reinterpret_cast<PCREDENTIAL_KEY>(plain.data() + offsetof(CloudAPCacheNodeData2, pCredKey)) };
        std::cout << "            Type  : " << credKey->KeyType << std::endl;
        RPC_CSTR guidString;
        UuidToStringA(&credKey->KeyId, &guidString);
        std::cout << "            Id    : " << reinterpret_cast<char*>(guidString) << std::endl;
        RpcStringFreeA(&guidString);
        std::vector<uint8_t> credKeyData(nodeData2->cbCredKey, '\0');
        std::memcpy(credKeyData.data(), reinterpret_cast<char*>(credKey) + credKey->KeyOffset, credKeyData.size());
        // Lsa maintians a larger buffer for the credential key than what's actually needed.
        // We first output the entire buffer which has been shown to leak data, albeit unuseful.
        // We then output the actual portion of the buffer that consists of the credential key.
        std::cout << "            Buffer: " << base64::encode(credKeyData) << std::endl;
        credKeyData.resize(0x40, '\0');
        std::cout << "            Value : " << base64::encode(credKeyData) << std::endl;
        std::cout << "        CacheBlob: " << (reinterpret_cast<PCHAR>(credKey) + nodeData2->cbCredKey) << std::endl;
    }
}

extern "C" {
int azuread(int argc, char** argv) {
    bool showHelp{ false };
    std::string cacheDataPath;
    std::string credKey;
    std::string password;
    std::string pin;
    std::string sid;
    // clang-format off
     auto args = (
         clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
         clipp::option("--cache-data").doc("Path to an AzureAD CacheData file.") & clipp::value("path", cacheDataPath),
         clipp::option("--cred-key").doc("Account credential key.") & clipp::value("cred key", credKey),
         clipp::option("--password").doc("Account password.") & clipp::value("password", password),
         clipp::option("--pin").doc("Account pin.") & clipp::value("pin", pin),
         clipp::option("--sid").doc("Account sid for locating the CacheData file if one was not specified and/or for pin decryption.") & clipp::value("sid", sid)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (!(cacheDataPath.size() || sid.size()) || !(credKey.size() || password.size() || (pin.size() && sid.size())) || showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return (showHelp) ? 0 : -1;
    }
    if ((((credKey.empty()) ? 0 : 1) + ((password.empty()) ? 0 : 1) + ((pin.empty()) ? 0 : 1)) == 1) {
        bool succeeded{ false };
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        if (!cacheDataPath.size()) {
            auto logonCachePath{ std::wstring(L"SOFTWARE\\Microsoft\\IdentityStore\\LogonCache\\") + AzureAdProviderGuid };
            auto regKeyPath{ logonCachePath + L"\\Sid2Name\\" + converter.from_bytes(sid) };
            std::string identityName;
            HKEY regKey;
            if (RegOpenKeyW(HKEY_LOCAL_MACHINE, regKeyPath.data(), &regKey) == ERROR_SUCCESS) {
                std::vector<BYTE> value;
                DWORD cbValue{ 0 };
                if (RegGetValueA(regKey, nullptr, "IdentityName", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                    value.resize(cbValue, '\0');
                    if (RegGetValueA(regKey, nullptr, "IdentityName", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                        identityName = std::string(reinterpret_cast<char*>(value.data()));
                    }
                }
                RegCloseKey(regKey);
            } else {
                std::cout << "Could not access the Sid2Name LogonCache registry key for the user. Please ensure that the sid is correct and the user has previously logged into this host." << std::endl;
            }
            std::string identityHash;
            if (identityName.data()) {
                auto regKeyPath{ logonCachePath + L"\\Name2Sid\\" };
                if (RegOpenKeyW(HKEY_LOCAL_MACHINE, regKeyPath.data(), &regKey) == ERROR_SUCCESS) {
                    DWORD subKeyCount;
                    DWORD maxSubKeyLength;
                    if (RegQueryInfoKeyA(regKey, nullptr, 0, nullptr, &subKeyCount, &maxSubKeyLength, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        maxSubKeyLength += 1; // Account for the null that RegEnumKeyExW copies in
                        for (size_t index{ 0 }; index < subKeyCount; index++) {
                            std::vector<char> subKeyName(maxSubKeyLength, '\0');
                            if (RegEnumKeyA(regKey, index, subKeyName.data(), subKeyName.size()) == ERROR_SUCCESS) {
                                std::vector<BYTE> value;
                                DWORD cbValue{ 0 };
                                if (RegGetValueA(regKey, subKeyName.data(), "IdentityName", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                                    value.resize(cbValue, '\0');
                                    if (RegGetValueA(regKey, subKeyName.data(), "IdentityName", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                                        if (!std::memcmp(identityName.data(), value.data(), cbValue)) {
                                            identityHash = std::string(subKeyName.data());
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    RegCloseKey(regKey);
                }
            } else {
                std::cout << "Could not find the user's identity name under the LogonCache registry key." << std::endl;
            }
            if (identityHash.size()) {
                std::string cachePath{ "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAPCache" };
                cacheDataPath = cachePath + "\\AzureAd\\" + identityHash + "\\Cache\\CacheData";
            } else {
                std::cout << "Could find the Name2Sid LogonCache registry key for the user." << std::endl;
            }
        }
        if (!cacheDataPath.empty()) {
            std::error_code errorCode;
            if (cacheDataPath.size() && std::filesystem::exists(cacheDataPath, errorCode)) {
                std::string buffer(std::istreambuf_iterator<char>{ std::ifstream(cacheDataPath.data(), std::ios_base::binary) }, {});
                if (buffer.size()) {
                    CloudAPCache cloudApCache;
                    std::vector<BYTE> serializedBuffer(buffer.size(), '\0');
                    std::memcpy(serializedBuffer.data(), buffer.data(), serializedBuffer.size());
                    if (NT_SUCCESS(DeserializeCloudAPCache(serializedBuffer, &cloudApCache))) {
                        ShowCache(&cloudApCache);
                        if (credKey.size()) {
                            auto credKeyData{ base64::decode(credKey) };
                            std::vector<BYTE> credBuffer(credKeyData.size(), '\0');
                            std::memcpy(credBuffer.data(), credKeyData.data(), credKeyData.size());
                            ShowCacheNode(&cloudApCache, CLOUDAPCACHE_CREDTYPE_CREDKEY, credBuffer);
                        }
                        if (password.size()) {
                            auto utf16Password{ converter.from_bytes(password) };
                            std::vector<BYTE> credBuffer(utf16Password.size() * sizeof(wchar_t), '\0');
                            std::memcpy(credBuffer.data(), utf16Password.data(), credBuffer.size());
                            ShowCacheNode(&cloudApCache, CLOUDAPCACHE_CREDTYPE_PASSWORD, credBuffer);
                        }
                        if (pin.size()) {
                            NGC_CONTEXTS_DATA ngcCtxts = { 0 };
                            std::wstring whfbDeviceGuid{ L"924a382a-a956-4267-bef6-408fd5efed72" };
                            std::wstring microsoftSoftwareKeyStorageProvider{ L"CA00CFA8-EB0F-42BA-A707-A3A43CDA5BD9" };
                            auto decryptionKeyName{ converter.from_bytes(sid) + L"/" + whfbDeviceGuid + L"///" + microsoftSoftwareKeyStorageProvider };
                            ngcCtxts.pDecryptionKeyName = decryptionKeyName.data();
                            Rpc::Client rpcClient;
                            if (!rpcClient.Bind(NgcTicket_v1_0_c_ifspec)) {
                                TriggerNgcTokenService();
                                rpcClient.Bind(NgcTicket_v1_0_c_ifspec);
                            }
                            if (rpcClient.IsBound()) {
                                NGC_RPC_GESTURE_INFO gestureInfo;
                                std::memset(&gestureInfo, '\0', sizeof(gestureInfo));
                                gestureInfo.gestureType = NgcGestureType::NgcGestureTypePIN;
                                std::vector<BYTE> gestureData(pin.size(), '\0');
                                std::memcpy(gestureData.data(), pin.data(), gestureData.size());
                                gestureInfo.gestureData = gestureData.data();
                                gestureInfo.gestureDataByteCount = gestureData.size();
                                if (NT_SUCCESS(rpcClient.CallWithBinding(s_NgcTicketCreateForKeyOperations,
                                        &gestureInfo, ngcCtxts.pDecryptionKeyName, &ngcCtxts.decryptionAuthTicket, nullptr, nullptr, false))) {
                                    std::vector<BYTE> credBuffer(sizeof(ngcCtxts));
                                    std::memcpy(credBuffer.data(), &ngcCtxts, sizeof(ngcCtxts));
                                    ShowCacheNode(&cloudApCache, CLOUDAPCACHE_CREDTYPE_NGC, credBuffer);
                                } else {
                                    std::cout << "Could not get an NGC decryption ticket. Please ensure the pin is correct and the user has previously logged into this host." << std::endl;
                                }
                            } else {
                                std::cout << "Could not connect the the NGC Token RPC server. Please ensure that the \"Microsoft Passport\" service (e.g., ngcsvc) is installed and running." << std::endl;
                            }
                        }
                    } else {
                        std::cout << "Could not deserialize the CacheData file. Please ensure the CacheData file is correct." << std::endl;
                    }
                } else {
                    std::cout << "Could not read the CacheData file. Please ensure you have the correct permissions to access it." << std::endl;
                }
            } else {
                std::cout << "Could not locate the CacheData file. Please specify a path to the file and ensure that the path exists." << std::endl;
            }
        }
    } else {
        std::cout << "Please specify only one credential key, password, or pin to attempt decryption." << std::endl;
    }
    return 0;
}

int config(int argc, char** argv) {
    bool showHelp{ false };
    std::string cacheDir{ "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAPCache" };
    // clang-format off
     auto args = (
         clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
         clipp::option("--cache").doc("Path to an CloudAPCache directory.") & clipp::value("path", cacheDir)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return 0;
    }
    bool succeeded{ false };
    std::error_code errorCode;
    if (std::filesystem::exists(cacheDir, errorCode) && std::filesystem::is_directory(cacheDir)) {
        bool firstPlugin{ true };
        for (auto const& pluginDir : std::filesystem::directory_iterator{ cacheDir, std::filesystem::directory_options::skip_permission_denied }) {
            if (firstPlugin) {
                firstPlugin = false;
            } else {
                std::cout << std::endl;
            }
            auto pluginDirString{ pluginDir.path().filename().string() };
            std::cout << pluginDirString << ":" << std::endl;
            std::wstring regKeyPath{ L"SOFTWARE\\Microsoft\\IdentityStore\\LogonCache\\" };
            if (!pluginDirString.compare("AzureAD")) {
                regKeyPath += AzureAdProviderGuid;
            } else if (!pluginDirString.compare("MicrosoftAccount")) {
                regKeyPath += MicrosoftAccountProviderGuid;
            } else {
                std::cout << "    An unsupported cloudap provider was found. Please report this issue to the LSA Whisperer project." << std::endl;
                continue;
            }
            for (auto const& name : std::filesystem::directory_iterator{ pluginDir, std::filesystem::directory_options::skip_permission_denied }) {
                auto nameString{ name.path().filename().string() };
                std::cout << "    " << nameString << ":" << std::endl;
                regKeyPath += L"\\Name2Sid\\" + std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(nameString);
                HKEY regKey;
                if (RegOpenKeyW(HKEY_LOCAL_MACHINE, regKeyPath.data(), &regKey) == ERROR_SUCCESS) {
                    std::vector<BYTE> value;
                    DWORD cbValue{ 0 };
                    if (RegGetValueW(regKey, nullptr, L"DisplayName", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                        value.resize(cbValue, '\0');
                        if (RegGetValueW(regKey, nullptr, L"DisplayName", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                            std::wcout << L"        Name     : " << reinterpret_cast<wchar_t*>(value.data()) << std::endl;
                        }
                    }
                    cbValue = 0;
                    if (RegGetValueW(regKey, nullptr, L"IdentityName", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                        value.resize(cbValue, '\0');
                        if (RegGetValueW(regKey, nullptr, L"IdentityName", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                            std::wcout << L"        Id       : " << reinterpret_cast<wchar_t*>(value.data()) << std::endl;
                        }
                    }
                    cbValue = 0;
                    if (RegGetValueW(regKey, nullptr, L"SAMName", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                        value.resize(cbValue, '\0');
                        if (RegGetValueW(regKey, nullptr, L"SAMName", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                            std::wcout << L"        SAM name : " << reinterpret_cast<wchar_t*>(value.data()) << std::endl;
                        }
                    }
                    cbValue = 0;
                    if (RegGetValueW(regKey, nullptr, L"Sid", RRF_RT_REG_SZ, nullptr, nullptr, &cbValue) == ERROR_SUCCESS) {
                        value.resize(cbValue, '\0');
                        if (RegGetValueW(regKey, nullptr, L"Sid", RRF_RT_REG_SZ, nullptr, value.data(), &cbValue) == ERROR_SUCCESS) {
                            std::wcout << L"        Sid      : " << reinterpret_cast<wchar_t*>(value.data()) << std::endl;
                        }
                    }
                    RegCloseKey(regKey);
                } else {
                    std::cout << "        Error    : Could not open the Name2Sid key to resolve the account information." << std::endl;
                }
                std::cout << "        Files    : ";
                bool firstFile{ true };
                for (auto const& subPath : std::filesystem::directory_iterator{ name, std::filesystem::directory_options::skip_permission_denied }) {
                    std::cout << (firstFile ? "" : ", ") << "\"" << subPath.path().filename().string() << (subPath.is_directory() ? "/" : "") << "\"";
                    if (firstFile) {
                        firstFile = false;
                    }
                }
                std::cout << std::endl;
                std::cout << "        CacheData: " << (std::filesystem::exists(name.path() / "Cache\\CacheData") ? "present" : "not present") << std::endl;
                auto keysPath{ name.path() / "Keys" };
                size_t keyCount{ 0 };
                if (std::filesystem::exists(keysPath)) {
                    std::filesystem::directory_iterator iter{ keysPath, std::filesystem::directory_options::skip_permission_denied };
                    keyCount = std::count_if(iter, {}, [](auto& subPath) {
                        return subPath.is_regular_file();
                    });
                }
                std::cout << "        Key count: " << keyCount << std::endl;
            }
        }
    } else {
        std::cout << "Could not enumerate the CloudAPCache directory. Please ensure that it exists and you have the correct permissions to access it." << std::endl;
    }
    return 0;
}

int decrypt_popkey(int argc, char** argv) {
    bool showHelp{ false };
    std::string popKey;
    // clang-format off
     auto args = (
         clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
         clipp::option("--data").doc("Base64 encoded Proof of Possession (PoP) key data to decrypt.") & clipp::value("value", popKey)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (!popKey.size() || showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return (showHelp) ? 0 : -1;
    }
    bool succeeded{ false };
    std::vector<uint8_t> decodedData;
    // The reported PoP key in the cloudap cache will have its padding stripped
    // so we check here for if any padding needs to be appended.
    for (size_t paddingSize{ 0 }; paddingSize < 3; paddingSize++) {
        try {
            decodedData = base64::decode(popKey);
            break;
        } catch (cppcodec::padding_error) {
            popKey.append("=");
            continue;
        }
    }
    std::cout << "Version: " << *reinterpret_cast<DWORD*>(decodedData.data()) << std::endl;
    auto dataType{ *(reinterpret_cast<DWORD*>(decodedData.data()) + 1) };
    std::cout << "Type   : " << dataType << std::endl;
    DATA_BLOB dataIn;
    dataIn.cbData = decodedData.size() - (sizeof(DWORD) * 2);
    dataIn.pbData = reinterpret_cast<BYTE*>((reinterpret_cast<DWORD*>(decodedData.data()) + 2));
    DATA_BLOB dataOut;
    if (dataType == 1) {
        if (CryptUnprotectData(&dataOut, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &dataOut)) {
            std::vector<uint8_t> decryptedData(dataOut.pbData, dataOut.pbData + dataOut.cbData);
            std::cout << "Data   : " << base64::encode(decryptedData) << std::endl;
            succeeded = true;
        } else {
            std::cout << "Failed to decrypt the PoP key." << std::endl;
        }
    } else {
        std::cout << "The current code can only decrypt data type 1 (e.g., software encrypted data)." << std::endl;
    }
    return (succeeded) ? 0 : -1;
}
}