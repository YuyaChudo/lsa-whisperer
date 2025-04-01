// Copyright (C) 2024 Evan McBroom
//
// Windows comes with a bdechangepin.exe utility in System32 for changing the
// PIN for a bitlocker encrypted drive. On NT 10 22H2, and likely other versions
// of NT, an internal Microsoft header file for full volume encryption (FVE -
// a.k.a bitlocker) was accidently included in a UIFILE in the utility's resources.
// 
// Athough UIFILEs are only intended to UI styling information, the <stylesheets>
// tag of the file included the fully preprocessed internal C header for FVE.
// Preprocessing removed the original comments of the file any preprocessing
// directive that is not needed by a compiler (ex. define statements) but it
// did cause the content to contain any additional header that was included.
//
// That file is included here with only the following changes:
// - The formatting style was updated to align with LWDK
// - Removed content generated from the original file's inclusion of wincrypt.h
//   with that original include statement.
// - Content was placed before and after the file for its use in LWDK
// Comments are added to denote when the original content starts and ends.
//
#pragma once
#include <phnt_windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Start of the original file content.

#include <wincrypt.h>

typedef const BYTE* PCBYTE;

typedef struct _FVE_UEFI_VARIABLE_INFO {
    PBYTE UEFIVariableValue;
    ULONG UEFIVariableSizeBytes;
} FVE_UEFI_VARIABLE_INFO, *PFVE_UEFI_VARIABLE_INFO;

typedef struct _FVE_TPM_PCR7_INFO {
    PFVE_UEFI_VARIABLE_INFO PlatformKeyVariableInfo;
    PFVE_UEFI_VARIABLE_INFO KekDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO AllowedDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO ForbiddenDatabaseVariableInfo;
    PBYTE OsLoaderAuthoritySignature;
    ULONG OsLoaderAuthoritySignatureSizeBytes;
    ULONG CountSeparatorEvents;
} FVE_TPM_PCR7_INFO, *PFVE_TPM_PCR7_INFO;

typedef struct _FVE_TPM_PCR4_INFO {
    WCHAR BootMgrFilePath[MAX_PATH];
} FVE_TPM_PCR4_INFO, *PFVE_TPM_PCR4_INFO;

typedef struct _FVE_TPM_PROTECTOR_INFO {
    UINT32 TpmPcrIndex;
    union {
        PFVE_TPM_PCR7_INFO FveTpmPcr7Info;
        PFVE_TPM_PCR4_INFO FveTpmPcr4Info;
    } PredictiveSealInfo;
} FVE_TPM_PROTECTOR_INFO, *PFVE_TPM_PROTECTOR_INFO;

typedef struct _FVE_TPM_STATE_ {
    PVOID TpmContext;
    ULONG FveTpmProtectorInfoCount;
    PFVE_TPM_PROTECTOR_INFO FveTpmProtectorInfo;
} FVE_TPM_STATE, *PFVE_TPM_STATE;

typedef struct _FVE_TPM_INFO_ {
    ULONG FveTpmInfoVersion;
    PFVE_TPM_STATE TpmStateInfo;
} FVE_TPM_INFO, *PFVE_TPM_INFO;

typedef HRESULT(__stdcall* PFVE_TPM_API_CALLBACK)(PVOID hContext, UINT32 cbCmd, PCBYTE pabCmd, PUINT32 pcbResult, PBYTE pabResult);

STDAPI FveAddPredictiveTpmProtector(PCWSTR FveVolumePath, PFVE_TPM_INFO FveTpmInfo);
STDAPI FveSetupTpmCallback(PFVE_TPM_API_CALLBACK TpmCallback, UINT32 TpmVersion);

typedef enum _FVE_DEVICE_TYPE {
    FVE_DEVICE_UNKNOWN = -1,
    FVE_DEVICE_UNSUPPORTED = 0,
    FVE_DEVICE_VOLUME,
    FVE_DEVICE_CSV_VOLUME,
    FVE_DEVICE_MAX
} FVE_DEVICE_TYPE,
    *PFVE_DEVICE_TYPE;

typedef enum _FVE_INTERFACE_TYPE {
    FVE_INTERFACE_UNKNOWN = -1,
    FVE_INTERFACE_SEI = 0,
    FVE_INTERFACE_SYS,
    FVE_INTERFACE_HEI,
    FVE_INTERFACE_MAX
} FVE_INTERFACE_TYPE,
    *PFVE_INTERFACE_TYPE;

typedef enum _FVE_HANDLE_TYPE {
    FVE_HANDLE_UNKNOWN = -1,
    FVE_HANDLE_FVE = 0,
    FVE_HANDLE_NONFVE,
    FVE_HANDLE_MAX
} FVE_HANDLE_TYPE,
    *PFVE_HANDLE_TYPE;

typedef enum _FVE_SCENARIO_TYPE {
    FVE_SCENARIO_UNKNOWN = -1,
    FVE_SCENARIO_DEFAULT = 0,
    FVE_SCENARIO_KEY_ROLL = 1,
    FVE_SCENARIO_BOOT_COMPONENT_UPDATE = 2,
    FVE_SCENARIO_UNDEFINED_SKIP_CHECKS = 3
} FVE_SCENARIO_TYPE,
    *PFVE_SCENARIO_TYPE;

typedef struct _FVE_STATUS_V1 {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
} FVE_STATUS_V1, *PFVE_STATUS_V1;
typedef const FVE_STATUS_V1* PCFVE_STATUS_V1;

typedef struct _FVE_STATUS_V2 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
} FVE_STATUS_V2, *PFVE_STATUS_V2;
typedef const FVE_STATUS_V2* PCFVE_STATUS_V2;

typedef struct _FVE_STATUS_V3 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
} FVE_STATUS_V3, *PFVE_STATUS_V3;
typedef const FVE_STATUS_V3* PCFVE_STATUS_V3;

typedef struct _FVE_STATUS_V4 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
} FVE_STATUS_V4, *PFVE_STATUS_V4;

typedef const FVE_STATUS_V4* PCFVE_STATUS_V4;

#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef struct _FVE_STATUS_V5 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union {
        ULONGLONG ExtendedFlags2;
        struct {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
        };
    };
} FVE_STATUS_V5, *PFVE_STATUS_V5;
typedef const FVE_STATUS_V5* PCFVE_STATUS_V5;
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef struct _FVE_STATUS_V6 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union {
        ULONGLONG ExtendedFlags2;
        struct {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
} FVE_STATUS_V6, *PFVE_STATUS_V6;
typedef const FVE_STATUS_V6* PCFVE_STATUS_V6;
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef struct _FVE_STATUS_V7 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union {
        ULONGLONG ExtendedFlags2;
        struct {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
            BOOLEAN WcosWsp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
} FVE_STATUS_V7, *PFVE_STATUS_V7;
typedef const FVE_STATUS_V7* PCFVE_STATUS_V7;
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef struct _FVE_STATUS_V8 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union {
        ULONGLONG ExtendedFlags2;
        struct {
            BOOLEAN WimBootVolume : 1;
            BOOLEAN WimBootHashCompleted : 1;
            BOOLEAN IceIsUsedForFve : 1;
            BOOLEAN IsEfiEsp : 1;
            BOOLEAN IsRecovery : 1;
            BOOLEAN WcosDePolicy : 1;
            BOOLEAN WcosOsData : 1;
            BOOLEAN WcosPreInstalled : 1;
            BOOLEAN WcosUserData : 1;
            BOOLEAN WcosMainOs : 1;
            BOOLEAN WcosEfiEsp : 1;
            BOOLEAN WcosBsp : 1;
            BOOLEAN WcosWsp : 1;
            BOOLEAN WcosDpp : 1;
        };
    };
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
    ULONG WcosDppProtectLevel;
} FVE_STATUS_V8, *PFVE_STATUS_V8;
typedef const FVE_STATUS_V8* PCFVE_STATUS_V8;
#pragma warning(pop)

typedef enum _FVE_WIPING_STATE {
    FVE_WIPING_STATE_UNSPECIFIED = 0,
    FVE_WIPING_STATE_INACTIVE = 1,
    FVE_WIPING_STATE_PENDING = 2,
    FVE_WIPING_STATE_STOPPED = 3,
    FVE_WIPING_STATE_INPROGRESS = 4,
} FVE_WIPING_STATE,
    *PFVE_WIPING_STATE;

typedef struct _FVE_TPM_CAPS {
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT TpmStatus;
    ULONG Flags;
} FVE_TPM_CAPS, *PFVE_TPM_CAPS;
typedef const FVE_TPM_CAPS* PCFVE_TPM_CAPS;

typedef struct _FVE_TPM_CAPS_TPM_PRESENCE {
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT NotUsed;
    ULONG NotUsed2;
    BOOL TpmPresent;
} FVE_TPM_CAPS_TPM_PRESENCE, *PFVE_TPM_CAPS_TPM_PRESENCE;
typedef const FVE_TPM_CAPS_TPM_PRESENCE* PCFVE_TPM_CAPS_TPM_PRESENCE;

typedef struct _FVE_AUTH_RECOVERY_PASSWORD {
    USHORT Block[(8)];
} FVE_AUTH_RECOVERY_PASSWORD, *PFVE_AUTH_RECOVERY_PASSWORD;
typedef const FVE_AUTH_RECOVERY_PASSWORD* PCFVE_AUTH_RECOVERY_PASSWORD;

typedef struct _FVE_AUTH_PIN {
    BYTE HashedPin[32];
} FVE_AUTH_PIN, *PFVE_AUTH_PIN;
typedef const FVE_AUTH_PIN* PCFVE_AUTH_PIN;

typedef struct _FVE_AUTH_TPM {
    ULONG PcrBitmap;
} FVE_AUTH_TPM, *PFVE_AUTH_TPM;
typedef const FVE_AUTH_TPM* PCFVE_AUTH_TPM;

typedef struct _FVE_AUTH_PREDICTED_TPM_INFO {
    PFVE_TPM_STATE FveTpmState;
} FVE_AUTH_PREDICTED_TPM_INFO, *PFVE_AUTH_PREDICTED_TPM_INFO;
typedef const FVE_AUTH_PREDICTED_TPM_INFO* PCFVE_AUTH_PREDICTED_TPM_INFO;

typedef struct _FVE_AUTH_EXTERNAL_KEY {
    BYTE Key[32];
} FVE_AUTH_EXTERNAL_KEY, *PFVE_AUTH_EXTERNAL_KEY;
typedef const FVE_AUTH_EXTERNAL_KEY* PCFVE_AUTH_EXTERNAL_KEY;

typedef struct _FVE_AUTH_PUBLIC_KEY {
    BCRYPT_KEY_HANDLE Handle;
    ULONG BlobSize;
    PBYTE Blob;
} FVE_AUTH_PUBLIC_KEY, *PFVE_AUTH_PUBLIC_KEY;
typedef const FVE_AUTH_PUBLIC_KEY* PCFVE_AUTH_PUBLIC_KEY;

typedef struct _FVE_AUTH_PRIVATE_KEY {
    NCRYPT_KEY_HANDLE KspKeyHandle;
    HCRYPTPROV CspProviderHandle;
    HCRYPTKEY CspKeyHandle;
    DWORD KeySpec;
} FVE_AUTH_PRIVATE_KEY, *PFVE_AUTH_PRIVATE_KEY;
typedef const FVE_AUTH_PRIVATE_KEY* PCFVE_AUTH_PRIVATE_KEY;

typedef struct _FVE_AUTH_INFO_PUBLIC_KEY {
    ULONG ExportedPublicKeySize;
    ULONG ExportedPublicKeyOffset;
    ULONG BlobSize;
    ULONG BlobOffset;
} FVE_AUTH_INFO_PUBLIC_KEY, *PFVE_AUTH_INFO_PUBLIC_KEY;
typedef const FVE_AUTH_INFO_PUBLIC_KEY* PCFVE_AUTH_INFO_PUBLIC_KEY;

typedef struct _FVE_AUTH_PASSPHRASE {
    WCHAR ClearPassPhrase[256 + 1];
    BYTE HashedPassPhrase[32];
    BYTE Salt[16];
} FVE_AUTH_PASSPHRASE, *PFVE_AUTH_PASSPHRASE;
typedef const FVE_AUTH_PASSPHRASE* PCFVE_AUTH_PASSPHRASE;

typedef struct _FVE_AUTH_INFO_CLEAR_KEY {
    UCHAR Count;
} FVE_AUTH_INFO_CLEAR_KEY, *PFVE_AUTH_INFO_CLEAR_KEY;

typedef struct _FVE_AUTH_DPAPI_NG {
    USHORT DpapiNgFlags;
    USHORT DescriptorLength;
    WCHAR DpapiNgDescriptor[ANYSIZE_ARRAY];
} FVE_AUTH_DPAPI_NG, *PFVE_AUTH_DPAPI_NG;
typedef const FVE_AUTH_DPAPI_NG* PCFVE_AUTH_DPAPI_NG;

typedef struct _FVE_AUTH_ELEMENT {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG ElementFlags;
    ULONG ElementType;
    union {
        BYTE Nothing[1];
        FVE_AUTH_RECOVERY_PASSWORD RecoveryPassword;
        FVE_AUTH_PIN Pin;
        FVE_AUTH_TPM Tpm;
        FVE_AUTH_EXTERNAL_KEY ExternalKey;
        FVE_AUTH_PUBLIC_KEY PublicKey;
        FVE_AUTH_PRIVATE_KEY PrivateKey;
        FVE_AUTH_INFO_PUBLIC_KEY PublicKeyInfo;
        FVE_AUTH_PASSPHRASE PassPhrase;
        FVE_AUTH_INFO_CLEAR_KEY ClearKeyInfo;
        FVE_AUTH_DPAPI_NG DpapiNgInfo;
        FVE_AUTH_PREDICTED_TPM_INFO PredictedTpmInfo;
    } Data;
} FVE_AUTH_ELEMENT, *PFVE_AUTH_ELEMENT;

typedef const FVE_AUTH_ELEMENT* PCFVE_AUTH_ELEMENT;

typedef struct _FVE_AUTH_INFORMATION {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG AuthFlags;
    ULONG ElementsCount;
    PFVE_AUTH_ELEMENT* Elements;
    PCWSTR Description;
    FILETIME CreationTime;
    GUID Identifier;
} FVE_AUTH_INFORMATION, *PFVE_AUTH_INFORMATION;
typedef const FVE_AUTH_INFORMATION* PCFVE_AUTH_INFORMATION;

typedef struct _ADA_GP_OPTIONS {
    BOOL BackupEnabled;
    BOOL BackupKeyPackage;
    BOOL BackupRequired;
} ADA_GP_OPTIONS, *PADA_GP_OPTIONS;

typedef enum _FVE_PROTECTOR_TYPE {
    FveKeyProtTypeUnknown = 0,
    FveKeyProtTypeTpm,
    FveKeyProtTypeKey,
    FveKeyProtTypePassword,
    FveKeyProtTypeTpmAndPin,
    FveKeyProtTypeTpmAndKey,
    FveKeyProtTypeTpmAndPinAndKey,
    FveKeyProtTypeCertificate,
    FveKeyProtTypePassPhrase,
    FveKeyProtTypeTpmAndCertificate,
    FveKeyProtTypeDpapiNg,
} FVE_PROTECTOR_TYPE,
    *PFVE_PROTECTOR_TYPE;

FORCEINLINE BOOL FveIsTpmProtectorType(FVE_PROTECTOR_TYPE ProtectorType) {
    return ProtectorType == FveKeyProtTypeTpm ||
           ProtectorType == FveKeyProtTypeTpmAndPin ||
           ProtectorType == FveKeyProtTypeTpmAndKey ||
           ProtectorType == FveKeyProtTypeTpmAndPinAndKey ||
           ProtectorType == FveKeyProtTypeTpmAndCertificate;
}

NTSYSAPI HRESULT NTAPI FveOpenVolumeW(PCWSTR VolumeName, BOOL bNeedWriteAccess, HANDLE* phVolume);
NTSYSAPI HRESULT NTAPI FveOpenVolumeExW(PCWSTR VolumeName, ULONG NameFlags, BOOL bNeedWriteAccess, FVE_INTERFACE_TYPE IfcType, ULONG HandleFlags, HANDLE* phVolume);
NTSYSAPI HRESULT NTAPI FveOpenVolumeByHandle(HANDLE Handle, FVE_HANDLE_TYPE HandleType, BOOL bNeedWriteAccess, FVE_INTERFACE_TYPE IfcType, ULONG HandleFlags, HANDLE* phVolume);
NTSYSAPI HRESULT NTAPI FveCloseHandle(HANDLE FveHandle);
NTSYSAPI HRESULT NTAPI FveCloseVolume(HANDLE FveVolumeHandle);
HRESULT NTAPI FveApplyGroupPolicy(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveCommitChanges(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveDiscardChanges(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveGetStatus(HANDLE FveVolumeHandle, PFVE_STATUS_V8 Status);
NTSYSAPI HRESULT NTAPI FveGetStatusW(PCWSTR VolumeName, PFVE_STATUS_V8 Status);
NTSYSAPI HRESULT NTAPI FveGetUserFlags(HANDLE FveVolumeHandle, PULONG UserFlags);
NTSYSAPI HRESULT NTAPI FveSetUserFlags(HANDLE FveVolumeHandle, ULONG UserFlags);
NTSYSAPI HRESULT NTAPI FveClearUserFlags(HANDLE FveVolumeHandle, ULONG UserFlags);
NTSYSAPI HRESULT NTAPI FveGetAuthMethodGuids(HANDLE FveVolumeHandle, LPGUID AuthMethodGuids, UINT MaxNumGuids, PUINT NumGuids);
NTSYSAPI HRESULT NTAPI FveGetAuthMethodInformation(HANDLE FveVolumeHandle, PFVE_AUTH_INFORMATION Information, SIZE_T BufferSize, SIZE_T* RequiredSize);
NTSYSAPI HRESULT NTAPI FveProtectorTypeToFlags(FVE_PROTECTOR_TYPE ProtectorType, PULONG TypeFlags);
NTSYSAPI HRESULT NTAPI FveFlagsToProtectorType(ULONG TypeFlags, PFVE_PROTECTOR_TYPE ProtectorType);
NTSYSAPI HRESULT NTAPI FveDeleteAuthMethod(HANDLE FveVolumeHandle, LPCGUID AuthMethodGuid);
NTSYSAPI HRESULT NTAPI FveAddAuthMethodInformation(HANDLE FveVolumeHandle, PCFVE_AUTH_INFORMATION Information, LPGUID AuthMethodGuid);
NTSYSAPI HRESULT NTAPI FveUpdatePinW(HANDLE hFveVolume, LPCWSTR NewPin, LPCGUID ProtectorGuid);
NTSYSAPI HRESULT NTAPI FveValidateExistingPinW(HANDLE hFveVolume, PCWSTR ExistingPin, PBOOL ExistingPinValidates, LPGUID GUIDProtector);
NTSYSAPI HRESULT NTAPI FveValidateExistingPassphraseW(HANDLE hFveVolume, PCWSTR ExistingPassphrase, PBOOL ExistingPassphraseValidates, LPGUID ProtectorGuid);
NTSYSAPI HRESULT NTAPI FveEraseDrive(HANDLE FveVolumeHandle, BOOL ForceDismount);
NTSYSAPI HRESULT NTAPI FveUpgradeVolume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveEraseDriveExW(PCWSTR VolumeName, BOOL ForceDismount);
NTSYSAPI HRESULT NTAPI FveUnlockVolume(HANDLE FveVolumeHandle, PCFVE_AUTH_INFORMATION Information);
HRESULT NTAPI FveUnlockVolumeWithAccessMode(HANDLE hFveVolume, PCFVE_AUTH_INFORMATION Information, PBOOL ReadOnly);
NTSYSAPI HRESULT NTAPI FveAttemptAutoUnlock(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveLockVolume(HANDLE FveVolumeHandle, BOOLEAN ForceDismount);
NTSYSAPI HRESULT NTAPI FveCheckBootFileW(PCWSTR Path);
NTSYSAPI HRESULT NTAPI FveGetIdentity(HANDLE FveVolumeHandle, LPGUID IdentityGuid);
NTSYSAPI HRESULT NTAPI FveGetRecoveryPasswordBackupInformation(HANDLE FveVolumeHandle, LPCGUID ProtectorGuid, PUSHORT BackupInfoTypeMask);
NTSYSAPI HRESULT NTAPI FveSetRecoveryPasswordBackupInformation(HANDLE FveVolumeHandle, LPCGUID ProtectorGuid, USHORT BackupInfoType, USHORT SetFlags, USHORT ClearFlags, PBOOLEAN DatasetWasUpdated);
NTSYSAPI HRESULT NTAPI FveSelectBestRecoveryPasswordByBackupInformation(HANDLE FveVolumeHandle, LPGUID ProtectorGuid);
NTSYSAPI HRESULT NTAPI FveAuthElementToRecoveryPasswordW(PCFVE_AUTH_ELEMENT AuthElement, PWSTR Passphrase, SIZE_T PassphraseLength);
NTSYSAPI HRESULT NTAPI FveAuthElementFromPinW(PCWSTR Pin, PFVE_AUTH_ELEMENT AuthElement);
NTSYSAPI HRESULT NTAPI FveAuthElementFromPassPhraseW(PCWSTR PassPhrase, PFVE_AUTH_ELEMENT AuthElement);
NTSYSAPI HRESULT NTAPI FveAuthElementFromRecoveryPasswordW(PCWSTR Passphrase, PFVE_AUTH_ELEMENT AuthElement);
NTSYSAPI HRESULT NTAPI FveIsRecoveryPasswordGroupValidW(PCWSTR PassphraseGroup, BOOLEAN* IsValid);
NTSYSAPI HRESULT NTAPI FveIsRecoveryPasswordValidW(PCWSTR Passphrase, BOOLEAN* IsValid);
NTSYSAPI HRESULT NTAPI FveIsPassphraseCompatibleW(PCWSTR Passphrase, BOOL* IsCompatible);
NTSYSAPI HRESULT NTAPI FveAuthElementReadExternalKeyW(PCWSTR KeyFullFilePath, PFVE_AUTH_INFORMATION Information, SIZE_T BufferSize, SIZE_T* RequiredSize);
NTSYSAPI HRESULT NTAPI FveAuthElementWriteExternalKeyW(PCWSTR KeyFullFilePath, PCFVE_AUTH_INFORMATION Information);
NTSYSAPI HRESULT NTAPI FveAuthElementGetKeyFileNameW(PCFVE_AUTH_INFORMATION Information, PWSTR KeyFileName, SIZE_T BufferLength);
NTSYSAPI HRESULT NTAPI FveInitVolumeEx(HANDLE hFveVolume, PCWSTR pcwszDiscoveryVolumeType, ULONG InitializationFlags);
NTSYSAPI HRESULT NTAPI FveInitVolume(HANDLE FveVolumeHandle, PCWSTR DiscoveryVolumeType);
NTSYSAPI HRESULT NTAPI FveInitializeDeviceEncryption(VOID);
NTSYSAPI HRESULT NTAPI FveInitializeDeviceEncryption2(HANDLE FveVolumeHandle, ULONG DEInitializationFlags);

typedef struct _FVE_DE_SUPPORT {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG QueryFlags;
    HRESULT SupportStatus;
    ULONG SupportFlags;
} FVE_DE_SUPPORT, *PFVE_DE_SUPPORT;

typedef const FVE_DE_SUPPORT* PCFVE_DE_SUPPORT;

NTSYSAPI HRESULT NTAPI FveQueryDeviceEncryptionSupport(PFVE_DE_SUPPORT DeviceEncryptionSupport);
NTSYSAPI HRESULT NTAPI FveRevertVolume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveKeyManagement(HANDLE FveVolumeHandle, ULONG FlagsIn, PULONG FlagsOut);
NTSYSAPI HRESULT NTAPI FveConversionDecrypt(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveConversionDecryptEx(HANDLE FveVolumeHandle, ULONG ConversionFlags);
NTSYSAPI HRESULT NTAPI FveConversionEncrypt(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveConversionEncryptEx(HANDLE FveVolumeHandle, ULONG ConversionFlags);
NTSYSAPI HRESULT NTAPI FveConversionEncryptPendingReboot(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveConversionEncryptPendingRebootEx(HANDLE FveVolumeHandle, ULONG ConversionFlags);
NTSYSAPI HRESULT NTAPI FveConversionStop(HANDLE FveVolumeHandle);
HRESULT NTAPI FveConversionStopEx(HANDLE FveVolumeHandle, BOOLEAN AutoStartOnReinsertion);
NTSYSAPI HRESULT NTAPI FveConversionPause(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveConversionResume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveIsVolumeEncryptable(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveGetFveMethod(HANDLE FveVolumeHandle, PINT FveMethod);
NTSYSAPI HRESULT NTAPI FveGetFveMethodEDrv(HANDLE FveVolumeHandle, PINT FveMethod, LPWSTR SelfEncryptionDriveEncryptionMethod);
NTSYSAPI HRESULT NTAPI FveGetFveMethodEx(HANDLE hFveVolume, PINT FveMethod, LPWSTR eDriveMethod, PULONG FveMethodFlags);
NTSYSAPI HRESULT NTAPI FveSetFveMethod(HANDLE FveVolumeHandle, INT FveMethod);
NTSYSAPI HRESULT NTAPI FveCheckTpmCapability(PFVE_TPM_CAPS Capability);
NTSYSAPI HRESULT NTAPI FveBindDataVolume(HANDLE FveVolumeHandle, LPCGUID AuthMethodGUID);
NTSYSAPI HRESULT NTAPI FveUnbindDataVolume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveIsBoundDataVolume(HANDLE FveVolumeHandle, PBOOL IsAutoUnlockEnabled, LPGUID UnlockGUID);
NTSYSAPI HRESULT NTAPI FveIsBoundDataVolumeToOSVolume(HANDLE FveVolumeHandle, PBOOL IsAutoUnlockEnabled, LPGUID UnlockGUID);
NTSYSAPI HRESULT NTAPI FveIsAnyDataVolumeBoundToOSVolume(HANDLE FveVolumeHandle, PULONG Count);
NTSYSAPI HRESULT NTAPI FveUnbindAllDataVolumeFromOSVolume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveSetDescriptionW(HANDLE FveVolumeHandle, PCWSTR VolumeDescription);
NTSYSAPI HRESULT NTAPI FveGetDescriptionW(HANDLE FveVolumeHandle, PWSTR VolumeDescription, SIZE_T BufferLength, SIZE_T* RequiredSize);
NTSYSAPI HRESULT NTAPI FveSetIdentificationFieldW(HANDLE FveVolumeHandle, PCWSTR IdentificationField);
NTSYSAPI HRESULT NTAPI FveGetIdentificationFieldW(HANDLE FveVolumeHandle, PWSTR IdentificationField, SIZE_T BufferLength, SIZE_T* RequiredSize);
NTSYSAPI HRESULT NTAPI FveSetAllowKeyExport(BOOL Allow);
NTSYSAPI HRESULT NTAPI FveGetAllowKeyExport(BOOL* Allow);
NTSYSAPI HRESULT NTAPI FveSetFipsAllowDisabled(BOOL Allow);
NTSYSAPI HRESULT NTAPI FveGetFipsAllowDisabled(BOOL* Allow);
NTSYSAPI HRESULT NTAPI FveIsHardwareReadyForConversion(VOID);
NTSYSAPI HRESULT NTAPI FveGetKeyPackage(HANDLE FveVolumeHandle, LPCGUID Identifier, PUCHAR Buffer, SIZE_T BufferSize, SIZE_T* DataSize);
NTSYSAPI HRESULT NTAPI FveEnableRawAccessW(PCWSTR VolumeName, BOOL Enabled);
NTSYSAPI HRESULT NTAPI FveEnableRawAccess(HANDLE FveVolumeHandle, BOOL Enabled);
NTSYSAPI HRESULT NTAPI FveEnableRawAccessEx(HANDLE FveVolumeHandle, BOOL Enabled, BOOL ForceDismount);
NTSYSAPI HRESULT NTAPI FveBackupRecoveryInformationToAD(HANDLE FveVolumeHandle, LPCGUID AuthMethodGUID);
NTSYSAPI HRESULT NTAPI FveBackupRecoveryInformationToADEx(HANDLE hFveVolume, LPCGUID AuthMethodGUID, ULONG FveBackupFlags);
NTSYSAPI HRESULT NTAPI FveCheckADRecoveryInfoBackupPolicy(HANDLE hFveVolume, ADA_GP_OPTIONS* ADPolicy);
NTSYSAPI HRESULT NTAPI FveCheckADRecoveryInfoBackupPolicyEx(ADA_GP_OPTIONS* ADPolicyOs, ADA_GP_OPTIONS* ADPolicyFdv, ADA_GP_OPTIONS* ADPolicyRdv);
NTSYSAPI HRESULT NTAPI FveGetDataSet(HANDLE FveVolumeHandle, PUCHAR DataSetBuffer, SIZE_T DataSetBufferSize, SIZE_T* ActualDataSetBufferSize);
NTSYSAPI HRESULT NTAPI FveIsHybridVolume(HANDLE FveVolumeHandle, PBOOL IsHybrid);
NTSYSAPI HRESULT NTAPI FveIsHybridVolumeW(PCWSTR VolumeName, PBOOL IsHybrid);
NTSYSAPI HRESULT NTAPI FveNeedsDiscoveryVolumeUpdate(HANDLE FveVolumeHandle, PBOOL NeedsUpdate);
NTSYSAPI HRESULT NTAPI FveServiceDiscoveryVolume(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveNotifyVolumeAfterFormat(HANDLE FveVolumeHandle);
NTSYSAPI HRESULT NTAPI FveSaveRecoveryPasswordBackupFlag(HANDLE FveVolumeHandle, LPCGUID pRecoveryPasswordGuid, PCFVE_AUTH_ELEMENT pRecoveryPassword);
NTSYSAPI HRESULT NTAPI FveDraCertPresentInRegistry(PBOOL ptCertPresent);
NTSYSAPI HRESULT NTAPI FveSysOpenVolumeW(PCWSTR VolumeName, HANDLE* phFveSys);
NTSYSAPI HRESULT NTAPI FveSysCloseVolume(HANDLE FveSys);
NTSYSAPI HRESULT NTAPI FveSysGetUserFlags(HANDLE FveSysHandle, PULONG UserFlags);
NTSYSAPI HRESULT NTAPI FveSysSetUserFlags(HANDLE FveSysHandle, ULONG UserFlags);
NTSYSAPI HRESULT NTAPI FveSysClearUserFlags(HANDLE FveSysHandle, ULONG UserFlags);

typedef enum _FVE_QUERY_TYPE {
    FVE_QUERY_UNKNOWN = 0,
    FVE_QUERY_UNSUPPORTED,
    FVE_QUERY_VOLUMES,
    FVE_QUERY_CSV_VOLUMES,
    FVE_QUERY_DE_NOT_INITIALIZED,
    FVE_QUERY_WCOS_SECURITY_INFO,
    FVE_QUERY_MAX
} FVE_QUERY_TYPE,
    *PFVE_QUERY_TYPE;

typedef struct _FVE_WCOS_SEQURITY_INFO_REQUEST {
    USHORT Version;
    USHORT Size;
    ULONG CompletionWaitTime;
} FVE_WCOS_SEQURITY_INFO_REQUEST, *PFVE_WCOS_SEQURITY_INFO_REQUEST;

typedef struct _FVE_WCOS_SEQURITY_INFO_RESPONSE {
    USHORT Version;
    USHORT Size;
    UCHAR Secure;
    UCHAR SecureBootBinding;
    UCHAR ProvisioningStarted;
    UCHAR ProvisioningComplete;
    ULONGLONG EncryptionRequiredMask;
    ULONGLONG EncryptionEnabledMask;
    ULONGLONG EncryptionCompleteMask;
    ULONGLONG ProtectionArmedMask;
    ULONGLONG RecoveryPasswordAbsentMask;
    ULONGLONG ReadOnlyRequiredMask;
    ULONGLONG ReadOnlyEnabledMask;
} FVE_WCOS_SEQURITY_INFO_RESPONSE, *PFVE_WCOS_SEQURITY_INFO_RESPONSE;

NTSYSAPI HRESULT NTAPI FveQuery(FVE_QUERY_TYPE FveQueryType, PBYTE InputBuffer, ULONG InputSize, PBYTE OutputBuffer, ULONG* OutputSize);
HRESULT NTAPI FveApplyNkpCertChanges(HANDLE FveVolumeHandle);
HRESULT NTAPI FveGenerateNkpSessionKeys(HANDLE FveVolumeHandle);
HRESULT NTAPI FveGenerateNbp(HANDLE FveVolumeHandle, DWORD CertThumbprintSize, BYTE* CertThumbprint);
HRESULT NTAPI FveRegenerateNbpSessionKey(HANDLE FveVolumeHandle);
HRESULT NTAPI FveCanStandardUsersChangePin(PBOOL ptStandardUsersCanChangePin);
HRESULT NTAPI FveCanStandardUsersChangePassphraseByProxy(HANDLE FveVolumeHandle, PBOOL ptStandardUsersCanChangePassphraseByProxy);
HRESULT NTAPI FveCheckPassphrasePolicy(HANDLE FveVolumeHandle, PCWSTR Passphrase);
HRESULT NTAPI FveDecrementClearKeyCounter(HANDLE FveVolumeHandle);
HRESULT NTAPI FveGetClearKeyCounter(HANDLE FveVolumeHandle, PULONG ClearKeyCounter);
NTSYSAPI HRESULT NTAPI FveAddAuthMethodSid(HANDLE FveVolumeHandle, PCWSTR FriendlyName, PSID Sid, USHORT Flags, LPGUID AuthMethodGuid);
NTSYSAPI HRESULT NTAPI FveGetAuthMethodSid(HANDLE FveVolumeHandle, PSID Sid, LPGUID AuthMethodGuidArray, PULONG AuthMethodCount);
NTSYSAPI HRESULT NTAPI FveUnlockVolumeAuthMethodSid(HANDLE FveVolumeHandle, LPCGUID AuthMethodGuid);
NTSYSAPI HRESULT NTAPI FveGetAuthMethodSidInformation(HANDLE FveVolumeHandle, LPCGUID AuthMethodGuid, PUSHORT Flags, PSID Sid, PULONG SidBufferSize);

typedef struct _FVE_FIND_DATA_V1 {
    ULONG FveFindVersion;
    FVE_DEVICE_TYPE DevType;
} FVE_FIND_DATA_V1, *PFVE_FIND_DATA_V1;

NTSYSAPI HRESULT NTAPI FveFindFirstVolume(PHANDLE FveFindHandle, PFVE_FIND_DATA_V1 FindData);
NTSYSAPI HRESULT NTAPI FveFindNextVolume(HANDLE FveFindHandle, PFVE_FIND_DATA_V1 FindData);
NTSYSAPI HRESULT NTAPI FveGetVolumeNameW(HANDLE FveHandle, PULONG VolumeNameBufferCchLen, LPWSTR VolumeName);
HRESULT NTAPI FveUpdateBandIdBcd(HANDLE FveVolumeHandle);
HRESULT NTAPI FveLogRecoveryReason(HANDLE FveVolumeHandle, DWORD RecoveryReason, PCWSTR ApplicationPath, DWORD ChangedBcd);
HRESULT NTAPI FveIsSchemaExtInstalled(PBOOL SchemExtInstalled);

typedef enum _FVE_SECUREBOOT_BINDING_STATE {
    FVE_SECUREBOOT_BINDING_UNKNOWN = -1,
    FVE_SECUREBOOT_BINDING_NOT_POSSIBLE = 0,
    FVE_SECUREBOOT_BINDING_DISABLED_BY_POLICY,
    FVE_SECUREBOOT_BINDING_POSSIBLE,
    FVE_SECUREBOOT_BINDING_BOUND
} FVE_SECUREBOOT_BINDING_STATE,
    *PFVE_SECUREBOOT_BINDING_STATE;

HRESULT NTAPI FveGetSecureBootBindingState(PFVE_SECUREBOOT_BINDING_STATE SecureBootBindingState);
HRESULT NTAPI FveIsDeviceLockable(HANDLE hFveVolume);
HRESULT NTAPI FveLockDevice(HANDLE hFveVolume);
HRESULT NTAPI FveIsDeviceLockedOut(HANDLE hFveVolume, BOOL* IsDeviceLocked);
HRESULT NTAPI FveValidateDeviceLockoutState(HANDLE hFveVolume);
HRESULT NTAPI FveGetDeviceLockoutData(HANDLE hFveVolume, PBYTE PerUserData, ULONG* PerUserSize);
HRESULT NTAPI FveUpdateDeviceLockoutState(HANDLE hFveVolume, PBYTE PerUserData, ULONG PerUserSize);
HRESULT NTAPI FveUpdateDeviceLockoutStateEx(HANDLE hFveVolume, PBYTE PerUserData, ULONG PerUserSize, ULONG Flags);
HRESULT NTAPI FveDisableDeviceLockoutState(HANDLE hFveVolume);
HRESULT NTAPI FveRecalculateOffsetsAndMoveMetadata(HANDLE hFveVolume);
HRESULT NTAPI FveDeleteDeviceEncryptionOptOutForVolumeW(PCWSTR VolumePath);
NTSYSAPI HRESULT NTAPI FveGetExternalKeyBlob(PBYTE* Buffer, DWORD* BufferSize);
NTSYSAPI HRESULT NTAPI FveEscrowEncryptedRecoveryKeyForRetailUnlock(PBYTE Buffer, DWORD BufferSize);
HRESULT NTAPI FvepCanPinExceptionPolicyBeApplied(PBOOL Result);
NTSYSAPI HRESULT NTAPI FveCanPinExceptionPolicyBeApplied(PBOOL Result);
NTSYSAPI HRESULT NTAPI FveResetTpmDictionaryAttackParameters();
NTSYSAPI HRESULT NTAPI FveCommitChangesEx(HANDLE FveVolumeHandle, FVE_SCENARIO_TYPE FveScenario);

// End of the original file content.

#ifdef __cplusplus
} // Closes extern "C" above
namespace Fve {
    // Enumerations
    using DEVICE_TYPE = _FVE_DEVICE_TYPE;
    using HANDLE_TYPE = _FVE_HANDLE_TYPE;
    using INTERFACE_TYPE = _FVE_INTERFACE_TYPE;
    using PROTECTOR_TYPE = _FVE_PROTECTOR_TYPE;
    using QUERY_TYPE = _FVE_QUERY_TYPE;
    using SCENARIO_TYPE = _FVE_SCENARIO_TYPE;
    using SECUREBOOT_BINDING_STATE = _FVE_SECUREBOOT_BINDING_STATE;
    using WIPING_STATE = _FVE_WIPING_STATE;

    using ADA_GP_OPTIONS = _ADA_GP_OPTIONS;

    using AUTH_DPAPI_NG = _FVE_AUTH_DPAPI_NG;
    using AUTH_ELEMENT = _FVE_AUTH_ELEMENT;
    using AUTH_EXTERNAL_KEY = _FVE_AUTH_EXTERNAL_KEY;
    using AUTH_INFO_CLEAR_KEY = _FVE_AUTH_INFO_CLEAR_KEY;
    using AUTH_INFO_PUBLIC_KEY = _FVE_AUTH_INFO_PUBLIC_KEY;
    using AUTH_INFORMATION = _FVE_AUTH_INFORMATION;
    using AUTH_PASSPHRASE = _FVE_AUTH_PASSPHRASE;
    using AUTH_PIN = _FVE_AUTH_PIN;
    using AUTH_PREDICTED_TPM_INFO = _FVE_AUTH_PREDICTED_TPM_INFO;
    using AUTH_PRIVATE_KEY = _FVE_AUTH_PRIVATE_KEY;
    using AUTH_PUBLIC_KEY = _FVE_AUTH_PUBLIC_KEY;
    using AUTH_RECOVERY_PASSWORD = _FVE_AUTH_RECOVERY_PASSWORD;
    using AUTH_TPM = _FVE_AUTH_TPM;
    using DE_SUPPORT = _FVE_DE_SUPPORT;
    using FIND_DATA_V1 = _FVE_FIND_DATA_V1;
    using PCAUTH_DPAPI_NG = ::PCFVE_AUTH_DPAPI_NG;
    using PCAUTH_ELEMENT = ::PCFVE_AUTH_ELEMENT;
    using PCAUTH_EXTERNAL_KEY = ::PCFVE_AUTH_EXTERNAL_KEY;
    using PCAUTH_INFO_PUBLIC_KEY = ::PCFVE_AUTH_INFO_PUBLIC_KEY;
    using PCAUTH_INFORMATION = ::PCFVE_AUTH_INFORMATION;
    using PCAUTH_PASSPHRASE = ::PCFVE_AUTH_PASSPHRASE;
    using PCAUTH_PIN = ::PCFVE_AUTH_PIN;
    using PCAUTH_PREDICTED_TPM_INFO = ::PCFVE_AUTH_PREDICTED_TPM_INFO;
    using PCAUTH_PRIVATE_KEY = ::PCFVE_AUTH_PRIVATE_KEY;
    using PCAUTH_PUBLIC_KEY = ::PCFVE_AUTH_PUBLIC_KEY;
    using PCAUTH_RECOVERY_PASSWORD = ::PCFVE_AUTH_RECOVERY_PASSWORD;
    using PCAUTH_TPM = ::PCFVE_AUTH_TPM;
    using PCDE_SUPPORT = ::PCFVE_DE_SUPPORT;
    using PCSTATUS_V1 = ::PCFVE_STATUS_V1;
    using PCSTATUS_V2 = ::PCFVE_STATUS_V2;
    using PCSTATUS_V3 = ::PCFVE_STATUS_V3;
    using PCSTATUS_V4 = ::PCFVE_STATUS_V4;
    using PCSTATUS_V5 = ::PCFVE_STATUS_V5;
    using PCSTATUS_V6 = ::PCFVE_STATUS_V6;
    using PCSTATUS_V7 = ::PCFVE_STATUS_V7;
    using PCSTATUS_V8 = ::PCFVE_STATUS_V8;
    using PCTPM_CAPS = ::PCFVE_TPM_CAPS;
    using PCTPM_CAPS_TPM_PRESENCE = ::PCFVE_TPM_CAPS_TPM_PRESENCE;
    using PTPM_API_CALLBACK = ::PFVE_TPM_API_CALLBACK;
    using STATUS_V1 = _FVE_STATUS_V1;
    using STATUS_V2 = _FVE_STATUS_V2;
    using STATUS_V3 = _FVE_STATUS_V3;
    using STATUS_V4 = _FVE_STATUS_V4;
    using STATUS_V5 = _FVE_STATUS_V5;
    using STATUS_V6 = _FVE_STATUS_V6;
    using STATUS_V7 = _FVE_STATUS_V7;
    using STATUS_V8 = _FVE_STATUS_V8;
    using TPM_CAPS = _FVE_TPM_CAPS;
    using TPM_CAPS_TPM_PRESENCE = _FVE_TPM_CAPS_TPM_PRESENCE;
    using TPM_INFO_ = _FVE_TPM_INFO_;
    using TPM_PCR4_INFO = _FVE_TPM_PCR4_INFO;
    using TPM_PCR7_INFO = _FVE_TPM_PCR7_INFO;
    using TPM_PROTECTOR_INFO = _FVE_TPM_PROTECTOR_INFO;
    using TPM_STATE_ = _FVE_TPM_STATE_;
    using UEFI_VARIABLE_INFO = _FVE_UEFI_VARIABLE_INFO;
    using WCOS_SEQURITY_INFO_REQUEST = _FVE_WCOS_SEQURITY_INFO_REQUEST;
    using WCOS_SEQURITY_INFO_RESPONSE = _FVE_WCOS_SEQURITY_INFO_RESPONSE;
}
#endif