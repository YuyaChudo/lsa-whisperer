// Copyright (C) 2024 Evan McBroom
//
// Beacon object file library (boflib)
//
// This file should be included as if it where a header file
// at the top of each single compilation unit that requires it.
//
#pragma optimize("", off)
#include "lwdk.h"
#undef ERROR

#if defined(_M_IX86)
    #define CURRENT_TEB() (reinterpret_cast<PTEB>((ULONG_PTR)__readfsdword(0x18)))
#elif defined(_M_AMD64) && !defined(_M_ARM64EC)
    #define CURRENT_TEB() (reinterpret_cast<PTEB>(__readgsqword(offsetof(NT_TIB, Self))))
#else
    #error LSA Whisperer is only supported for x86 and x64 processors.
#endif

#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    static auto Lazy##PROC{ reinterpret_cast<decltype(PROC)*>(Lazy::GetProcAddress(LIBRARY, #PROC)) };

// PIC and String Literals Part 2:
// https://gist.github.com/EvanMcBroom/d7f6a8fe3b4d8f511b132518b9cf80d7
#define PIC_STRING(NAME, STRING) \
    constexpr char NAME[] {      \
        STRING                   \
    }
#define PIC_WSTRING(NAME, STRING) \
    constexpr wchar_t NAME[] {    \
        STRING                    \
    }

/// <summary>
/// Minimal declarations for the beacon API.
/// Import decorators are added because boflib is
/// intended to be used when compiling a static.
/// Static libraries will not add these decorators,
/// but bof tooling will expect them.
/// </summary>
extern "C" {
enum class CallbackType : int {
    OUTPUT = 0x0,
    ERROR = 0xd
};

typedef struct _BeaconData {
    char* original;
    char* buffer;
    int length;
    int size;
} BeaconData;

[[maybe_unused]] DECLSPEC_IMPORT char* BeaconDataExtract(BeaconData* parser, int* size);
[[maybe_unused]] DECLSPEC_IMPORT int BeaconDataInt(BeaconData* parser);
[[maybe_unused]] DECLSPEC_IMPORT int BeaconDataLength(BeaconData* parser);
[[maybe_unused]] DECLSPEC_IMPORT short BeaconDataShort(BeaconData* parser);
[[maybe_unused]] DECLSPEC_IMPORT void BeaconDataParse(BeaconData* parser, char* buffer, int size);
[[maybe_unused]] DECLSPEC_IMPORT void BeaconPrintf(CallbackType type, const char* fmt, ...);
}

/// <summary>
/// Bof library declerations
///
/// These declerations are in an unnamed namespace so that each
/// function name will be uniquely mangled for each single
/// compilation unit (SCU) that includes boflib.cpp (and ultimately
/// boflib.hpp).
///
/// Without unique functions names for each SCU, the linker tools
/// for MSVC will emit warning LNK4006:
/// "symbol already defined in object; second definition ignored"
///
/// The warning is relevant for normal software because boflib.cpp
/// will be included in each SCU causing multiple definitions of
/// the same library function which the linker would need to choose
/// from. The warning is not relevant to our use case because we
/// do not intend to directly use the static library but instead
/// intend to extract the library's objects to use as BOFs.
/// </summary>
namespace {

    // Native type declerations. These are declared within the unnamed
    // namespace to not conflict with SDK definitions.

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        // ...
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        // ...
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union {
            UCHAR BitField;
            struct
            {
                UCHAR ImageUsesLargePages : 1;
                UCHAR IsProtectedProcess : 1;
                UCHAR IsImageDynamicallyRelocated : 1;
                UCHAR SkipPatchingUser32Forwarders : 1;
                UCHAR IsPackagedProcess : 1;
                UCHAR IsAppContainer : 1;
                UCHAR IsProtectedProcessLight : 1;
                UCHAR SpareBits : 1;
            };
        };
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        // ...
    } PEB, *PPEB;

    namespace Lazy {
        static HMODULE GetLibrary(const wchar_t* libraryName);
        static FARPROC GetProcAddress(const wchar_t* libraryName, const char* procName);
    }

    namespace Libc {
        // C alternative for std::span<char, N>
        typedef struct _CHAR_SPAN {
            int count;
            char* data;
        } CHAR_SPAN, *PCHAR_SPAN;

        // C alternative for std::span<wchar_t, N>
        typedef struct _WCHAR_SPAN {
            int count;
            wchar_t* data;
        } WCHAR_SPAN, *PWCHAR_SPAN;

        static void __cdecl free(void* ptr);
        static void* __cdecl malloc(size_t size);
        static int __cdecl memcmp(void const* ptr1, void const* ptr2, size_t num);
        static void* __cdecl memcpy(void* destination, void const* source, size_t num);
        static void* __cdecl memset(void* ptr, int value, size_t num);
        static void* __cdecl realloc(void* ptr, size_t size);
        static int __cdecl stricmp(const char* str1, const char* str2);
        static size_t __cdecl strlen(char const* str);
        static int __cdecl wcsicmp(wchar_t const* str1, wchar_t const* str2);
        static size_t __cdecl wcslen(wchar_t const* str);
    }

    namespace LsaApi {
        static bool CallPackage(ULONG packageId, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer, HANDLE lsa = nullptr);
        static bool CallPackage(const char* package, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer);

        /// <typeparam name="Package">Any type that's convertable to a ULONG or const char*.</typeparam>
        template<typename Package>
        static bool CallPackage(Package package, Libc::PCHAR_SPAN submitBuffer) {
            Libc::CHAR_SPAN returnBuffer;
            return CallPackage(package, submitBuffer, &returnBuffer);
        }

        bool CallCloudapPlugin(const GUID* plugin, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer);
    }
}

/// <summary>
/// Bof library definitions
/// </summary>
namespace {
    namespace Lazy {
        static HMODULE GetLibrary(const wchar_t* libraryName) {
            auto ldr{ reinterpret_cast<PPEB>(CURRENT_TEB()->ProcessEnvironmentBlock)->Ldr };
            auto ldrDataTableEntry{ reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldr->InLoadOrderModuleList.Flink) };
            while (ldrDataTableEntry->DllBase) {
                if (!Libc::wcsicmp(libraryName, ldrDataTableEntry->BaseDllName.Buffer)) {
                    return reinterpret_cast<HMODULE>(ldrDataTableEntry->DllBase);
                }
                ldrDataTableEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldrDataTableEntry->InLoadOrderLinks.Flink);
            }
            // If the library was not found then it has not been loaded yet.
            // In that case, explicitly load the library to return to the user.
            PIC_WSTRING(ntdll, L"NTDLL.DLL");
            LAZY_LOAD_PROC(ntdll, LdrLoadDll);
            HMODULE library{ nullptr };
            auto libraryNameLength{ static_cast<USHORT>(Libc::wcslen(libraryName) * sizeof(wchar_t)) };
            UNICODE_STRING unicodeLibraryName = { libraryNameLength, libraryNameLength + sizeof(UNICODE_NULL), const_cast<wchar_t*>(libraryName) };
            return (NT_SUCCESS(LazyLdrLoadDll(nullptr, 0, &unicodeLibraryName, reinterpret_cast<PVOID*>(&library)))) ? library : nullptr;
        }

        /// <summary>
        /// Retrieves the address of an exported function from a specified module.
        /// The module will be implicitly loaded if it is not in the current process.
        /// </summary>
        static FARPROC GetProcAddress(const wchar_t* libraryName, const char* procName) {
            auto pe{ reinterpret_cast<char*>(GetLibrary(libraryName)) };
            if (pe) {
                auto dosHeader{ reinterpret_cast<IMAGE_DOS_HEADER*>(pe) };
                auto ntHeaders{ reinterpret_cast<IMAGE_NT_HEADERS*>(pe + dosHeader->e_lfanew) };
                auto optionalHeader{ ntHeaders->OptionalHeader };
                auto exportDirectory{ reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pe + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };
                auto exportCount{ exportDirectory->NumberOfNames };
                auto exportNameTableEntry{ reinterpret_cast<PDWORD>(pe + exportDirectory->AddressOfNames) };
                for (size_t index = 0; index < exportCount; index++, exportNameTableEntry++) {
                    auto exportName{ reinterpret_cast<PCSTR>(pe + *exportNameTableEntry) };
                    if (!Libc::stricmp(procName, exportName)) {
                        auto ordinal{ reinterpret_cast<PWORD>(pe + exportDirectory->AddressOfNameOrdinals)[index] };
                        return reinterpret_cast<FARPROC>(pe + reinterpret_cast<PDWORD>(pe + exportDirectory->AddressOfFunctions)[ordinal]);
                    }
                }
            }
            return nullptr;
        }
    }

    namespace Libc {
        static void __cdecl free(void* ptr) {
            PIC_WSTRING(ntdll, L"NTDLL.DLL");
            LAZY_LOAD_PROC(ntdll, RtlFreeHeap);
            LazyRtlFreeHeap(reinterpret_cast<PPEB>(CURRENT_TEB()->ProcessEnvironmentBlock)->ProcessHeap, 0, ptr);
        }

        static void* __cdecl malloc(size_t size) {
            PIC_WSTRING(ntdll, L"NTDLL.DLL");
            LAZY_LOAD_PROC(ntdll, RtlAllocateHeap);
            return LazyRtlAllocateHeap(reinterpret_cast<PPEB>(CURRENT_TEB()->ProcessEnvironmentBlock)->ProcessHeap, HEAP_ZERO_MEMORY, size);
        }

        static int __cdecl memcmp(void const* ptr1, void const* ptr2, size_t num) {
            auto lhs = reinterpret_cast<unsigned char const*>(ptr1);
            auto rhs = reinterpret_cast<unsigned char const*>(ptr2);
            for (size_t index{ 0 }; index < num; index++) {
                if (lhs[index] < rhs[index]) {
                    return -1;
                } else if (lhs[index] > rhs[index]) {
                    return 1;
                }
            }
            return 0;
        }

        static void* __cdecl memcpy(void* destination, void const* source, size_t num) {
            auto lhs{ reinterpret_cast<unsigned char*>(destination) };
            auto rhs{ reinterpret_cast<unsigned char const*>(source) };
            for (size_t index = 0; index < num; index++) {
                lhs[index] = rhs[index];
            }
            return destination;
        }

        static void* __cdecl memset(void* ptr, int value, size_t num) {
            auto p{ reinterpret_cast<unsigned char*>(ptr) };
            while (num-- > 0) {
                *p++ = (unsigned char)(value);
            }
            return ptr;
        }

        static void* __cdecl realloc(void* ptr, size_t size) {
            PIC_WSTRING(ntdll, L"NTDLL.DLL");
            LAZY_LOAD_PROC(ntdll, RtlReAllocateHeap);
            return LazyRtlReAllocateHeap(reinterpret_cast<PPEB>(CURRENT_TEB()->ProcessEnvironmentBlock)->ProcessHeap, HEAP_ZERO_MEMORY, ptr, size);
        }

        static int __cdecl stricmp(const char* str1, const char* str2) {
            size_t index;
            for (index = 0; str1[index] && str2[index]; index++) {
                auto lhc{ str1[index] };
                auto rhc{ str2[index] };
                lhc = (lhc > 0x40 && lhc < 0x5B) ? lhc | 0x20 : lhc;
                rhc = (rhc > 0x40 && rhc < 0x5B) ? rhc | 0x20 : rhc;
                if (lhc < rhc) {
                    return -1;
                } else if (lhc > rhc) {
                    return 1;
                }
            }
            return (!str1[index] && !str2[index]) ? 0 : (!str1[index]) ? -1
                                                                       : 1;
        }

        static size_t __cdecl strlen(char const* str) {
            char const* ptr{ str };
            while (*ptr)
                ptr++;
            return ptr - str;
        }

        // Only supports utf-16le values within the ascii range
        static int __cdecl wcsicmp(wchar_t const* str1, wchar_t const* str2) {
            auto lhs{ reinterpret_cast<unsigned char const*>(str1) };
            auto rhs{ reinterpret_cast<unsigned char const*>(str2) };
            size_t size1{ wcslen(str1) };
            size_t size2{ wcslen(str2) };
            for (size_t index{ 0 }; index < size1 && index < size2; index++) {
                auto lhc{ lhs[index] };
                auto rhc{ rhs[index] };
                lhc = (lhc > 0x40 && lhc < 0x5B) ? lhc | 0x20 : lhc;
                rhc = (rhc > 0x40 && rhc < 0x5B) ? rhc | 0x20 : rhc;
                if (lhc < rhc) {
                    return -1;
                } else if (lhc > rhc) {
                    return 1;
                }
            }
            return (size1 == size2) ? 0 : (size1 < size2) ? -1
                                                          : 1;
        }

        static size_t __cdecl wcslen(wchar_t const* str) {
            wchar_t const* ptr = str;
            while (*ptr)
                ptr++;
            return ptr - str;
        }
    }

    namespace LsaApi {
        static bool CallPackage(ULONG packageId, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer, HANDLE lsa) {
            bool succeeded{ false };
            returnBuffer->count = 0;
            returnBuffer->data = nullptr;
            NTSTATUS status{ STATUS_SUCCESS };
            HANDLE lsaHandle{ nullptr };
            PIC_WSTRING(sspicli, L"SSPICLI.DLL");
            if (lsa) {
                lsaHandle = lsa;
            } else {
                LAZY_LOAD_PROC(sspicli, LsaConnectUntrusted);
                status = LazyLsaConnectUntrusted(&lsaHandle);
            }
            if (lsaHandle && NT_SUCCESS(status)) {
                LAZY_LOAD_PROC(sspicli, LsaCallAuthenticationPackage);
                NTSTATUS protocolStatus;
                if (NT_SUCCESS(status = LazyLsaCallAuthenticationPackage(lsaHandle, packageId, submitBuffer->data, submitBuffer->count, reinterpret_cast<void**>(&returnBuffer->data), reinterpret_cast<PULONG>(&returnBuffer->count), &protocolStatus))) {
                    if (protocolStatus >= 0) {
                        succeeded = true;
                    } else {
                        returnBuffer->count = 0;
                        returnBuffer->data = nullptr;
                        PIC_STRING(error, "The package call succeeded but received a protocol error: 0x%lx\n");
                        BeaconPrintf(CallbackType::ERROR, error, protocolStatus);
                    }
                } else {
                    PIC_STRING(error, "Could not call authentication package.\n");
                    BeaconPrintf(CallbackType::ERROR, error);
                }
                if (!lsa) {
                    LAZY_LOAD_PROC(sspicli, LsaDeregisterLogonProcess);
                    (void)LazyLsaDeregisterLogonProcess(lsaHandle);
                }
            } else {
                PIC_STRING(error, "Could not connect to LSA.\n");
                BeaconPrintf(CallbackType::ERROR, error);
            }
            if (status != STATUS_SUCCESS) {
                PIC_STRING(error, "Last error: 0x%lx\n");
                BeaconPrintf(CallbackType::ERROR, error, status);
            }
            return succeeded;
        }

        static bool CallPackage(const char* package, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer) {
            bool succeeded{ false };
            returnBuffer->count = 0;
            returnBuffer->data = nullptr;
            NTSTATUS status{ STATUS_SUCCESS };
            HANDLE lsaHandle;
            PIC_WSTRING(sspicli, L"SSPICLI.DLL");
            LAZY_LOAD_PROC(sspicli, LsaConnectUntrusted);
            if (NT_SUCCESS(status = LazyLsaConnectUntrusted(&lsaHandle))) {
                LSA_STRING packageName = { (USHORT)Libc::strlen(package), (USHORT)(Libc::strlen(package) + sizeof(char)), const_cast<char*>(package) };
                ULONG packageId;
                LAZY_LOAD_PROC(sspicli, LsaLookupAuthenticationPackage);
                if (NT_SUCCESS(status = LazyLsaLookupAuthenticationPackage(lsaHandle, &packageName, &packageId))) {
                    return CallPackage(packageId, submitBuffer, returnBuffer, lsaHandle);
                } else {
                    PIC_STRING(error, "Could not find authentication package.\n");
                    BeaconPrintf(CallbackType::ERROR, error);
                }
                LAZY_LOAD_PROC(sspicli, LsaDeregisterLogonProcess);
                (void)LazyLsaDeregisterLogonProcess(lsaHandle);
            } else {
                PIC_STRING(error, "Could not connect to LSA.\n");
                BeaconPrintf(CallbackType::ERROR, error);
            }
            if (status != STATUS_SUCCESS) {
                PIC_STRING(error, "Last error: 0x%lx\n");
                BeaconPrintf(CallbackType::ERROR, error, status);
            }
            return succeeded;
        }
        
        static bool CallCloudapPlugin(const GUID* plugin, Libc::PCHAR_SPAN submitBuffer, Libc::PCHAR_SPAN returnBuffer) {
            Libc::CHAR_SPAN packageSubmitBuffer;
            packageSubmitBuffer.count = sizeof(CloudAPGenericCallPkgInput) + submitBuffer->count + 1;
            packageSubmitBuffer.data = reinterpret_cast<char*>(Libc::malloc(packageSubmitBuffer.count));
            Libc::memset(packageSubmitBuffer.data, '\0', packageSubmitBuffer.count);
            auto request{ reinterpret_cast<PCloudAPGenericCallPkgInput>(packageSubmitBuffer.data) };
            request->ulMessageType = 2; // CallPluginGeneric
            Libc::memcpy(&request->ProviderGuid, plugin, sizeof(GUID));
            request->ulInputSize = submitBuffer->count + 1;
            Libc::memcpy(request->abInput, submitBuffer->data, submitBuffer->count);
            PIC_STRING(cloudap, CLOUDAP_NAME_A);
            auto succeeded{ CallPackage(cloudap, &packageSubmitBuffer, returnBuffer) };
            Libc::free(packageSubmitBuffer.data);
            return succeeded;
        }
    }

    static LPSTR Hexlify(Libc::PCHAR_SPAN span) {
        static char key[] = "0123456789ABCDEF";
        auto buffer{ reinterpret_cast<LPSTR>(Libc::malloc((span->count * 2) + 1)) };
        for (size_t index = 0; index < span->count; index++) {
            buffer[index * 2] = key[(unsigned char)(span->data[index]) >> 4];
            buffer[(index * 2) + 1] = key[span->data[index] & 0xf];
        }
        buffer[span->count * 2] = '\0';
        return buffer;
    }

    static Libc::PCHAR_SPAN UnHexlify(LPSTR hex) {
        Libc::PCHAR_SPAN span{ nullptr };
        auto hexLength{ Libc::strlen(hex) };
        if (hexLength % 2) {
            span = reinterpret_cast<Libc::PCHAR_SPAN>(Libc::malloc(hexLength));
            span->count = hexLength / 2;
            span->data = reinterpret_cast<char*>(Libc::malloc(span->count));
            Libc::memset(span->data, '\0', span->count);
            for (size_t index = 0; index < span->count; index++) {
                auto c1 = hex[index / 2];
                auto c2 = hex[(index / 2) + 1];
                auto nibble1{ (c1 <= 0x39) ? c1 - 0x30 : (((c1 <= 0x46) ? (c1 - 0x41) : (c1 - 0x61)) + 10) };
                auto nibble2{ (c2 <= 0x39) ? c2 - 0x30 : (((c2 <= 0x46) ? (c2 - 0x41) : (c2 - 0x61)) + 10) };
                if (nibble1 < 0 || nibble1 > 15 || nibble2 < 0 || nibble2 > 15) {
                    Libc::free(span->data);
                    Libc::free(span);
                    break;
                }
                span->data[index] = nibble1 + (nibble2 << 4);
            }
        }
        return span;
    }
}

// RPC shims

size_t RPC_ENTRY NdrMesTypeAlignSize2Shim(handle_t Handle, const MIDL_TYPE_PICKLING_INFO* pPicklingInfo, const MIDL_STUB_DESC* pStubDesc, PFORMAT_STRING pFormatString, const void* pObject) {
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, NdrMesTypeAlignSize2);
    return LazyNdrMesTypeAlignSize2(Handle, pPicklingInfo, pStubDesc, pFormatString, pObject);
}

void RPC_ENTRY NdrMesTypeEncode2Shim(handle_t Handle, const MIDL_TYPE_PICKLING_INFO* pPicklingInfo, const MIDL_STUB_DESC* pStubDesc, PFORMAT_STRING pFormatString, const void* pObject) {
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, NdrMesTypeEncode2);
    LazyNdrMesTypeEncode2(Handle, pPicklingInfo, pStubDesc, pFormatString, pObject);
}

void RPC_ENTRY NdrMesTypeDecode2Shim(handle_t Handle, const MIDL_TYPE_PICKLING_INFO* pPicklingInfo, const MIDL_STUB_DESC* pStubDesc, PFORMAT_STRING pFormatString, void* pObject) {
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, NdrMesTypeDecode2);
    LazyNdrMesTypeDecode2(Handle, pPicklingInfo, pStubDesc, pFormatString, pObject);
}

void RPC_ENTRY NdrMesTypeFree2Shim(handle_t Handle, const MIDL_TYPE_PICKLING_INFO* pPicklingInfo, const MIDL_STUB_DESC* pStubDesc, PFORMAT_STRING pFormatString, void* pObject) {
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, NdrMesTypeFree2);
    LazyNdrMesTypeFree2(Handle, pPicklingInfo, pStubDesc, pFormatString, pObject);
}

#define NdrMesTypeAlignSize2 NdrMesTypeAlignSize2Shim
#define NdrMesTypeEncode2    NdrMesTypeEncode2Shim
#define NdrMesTypeDecode2    NdrMesTypeDecode2Shim
#define NdrMesTypeFree2      NdrMesTypeFree2Shim