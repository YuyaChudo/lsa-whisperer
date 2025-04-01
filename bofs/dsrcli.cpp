// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include <fcntl.h>
#include <io.h>
#include <ktmw32.h>
#include <shellapi.h>
#include <stdio.h>

#undef stdout
#undef stderr
#define stdout (Lazy__acrt_iob_func(1))
#define stderr (Lazy__acrt_iob_func(2))

typedef struct __crt_stdio_stream_data {
    union {
        _iobuf _public_file;
        PCHAR _ptr;
    };
    PCHAR _base;
    LONG _cnt;
    LONG _flags;
    LONG _file;
    LONG _charbuf;
    LONG _bufsiz;
    PCHAR _tmpfname;
    RTL_CRITICAL_SECTION _lock;
} crt_stdio_stream_data;

using GetTokenLogCallback = HRESULT (*)(DWORD, LPWSTR);

HRESULT GetTokenForDJPP(LPWSTR, LPWSTR, LPWSTR, LPWSTR, DSR_INSTANCE, LPWSTR, LPGUID, GetTokenLogCallback, LPWSTR*) {
    return S_OK;
}

[[maybe_unused]] HRESULT NET_API_FUNCTION DsrCLI(int argc, wchar_t** argv, decltype(GetTokenForDJPP) callback);

void CaptureOutput(HANDLE file) {
    PIC_WSTRING(kernel32, L"KERNEL32.DLL");
    LAZY_LOAD_PROC(kernel32, GetFileSize);
    auto outputSize{ LazyGetFileSize(file, nullptr) };
    if (outputSize) {
        LAZY_LOAD_PROC(kernel32, CreateFileMappingW);
        auto mapping{ LazyCreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, 0) };
        LAZY_LOAD_PROC(kernel32, MapViewOfFile);
        auto output{ reinterpret_cast<char*>(LazyMapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)) };
        auto outputWithTermination{ reinterpret_cast<char*>(Libc::malloc(outputSize + sizeof(wchar_t))) };
        Libc::memcpy(outputWithTermination, output, outputSize);
        // Output can occur as ascii or utf16 depending on the hosting process.
        // Two nulls are added to account for if the output is utf16.
        outputWithTermination[outputSize] = '\0';
        outputWithTermination[outputSize + 1] = '\0';
        // Detect and use the correct format string for the output encoding (e.g., ascii or utf16)
        if (outputWithTermination[1]) {
            PIC_STRING(formatString, "%s\n");
            BeaconPrintf(CallbackType::OUTPUT, formatString, outputWithTermination);
        } else {
            PIC_STRING(formatString, "%S\n");
            BeaconPrintf(CallbackType::OUTPUT, formatString, outputWithTermination);
        }
        Libc::free(outputWithTermination);
        LAZY_LOAD_PROC(kernel32, UnmapViewOfFile);
        LazyUnmapViewOfFile(output);
        LAZY_LOAD_PROC(kernel32, CloseHandle);
        LazyCloseHandle(mapping);
    } else {
        PIC_STRING(error, "No output was captured when calling dsreg!DsrCLI.\n");
        BeaconPrintf(CallbackType::ERROR, error);
    }
}

LPWSTR FindWriteableFile() {
    PIC_WSTRING(kernel32, L"KERNEL32.DLL");
    LAZY_LOAD_PROC(kernel32, CloseHandle);
    LAZY_LOAD_PROC(kernel32, CreateFileW);
    LAZY_LOAD_PROC(kernel32, FindClose);
    LAZY_LOAD_PROC(kernel32, FindFirstFileW);
    LAZY_LOAD_PROC(kernel32, FindNextFileW);
    LAZY_LOAD_PROC(kernel32, GetTempFileNameW);
    LAZY_LOAD_PROC(kernel32, GetTempPathW);
    PIC_WSTRING(fileGlob, L"*.*");
    WCHAR filePathPrefix[MAX_PATH];
    Libc::memset(filePathPrefix, '\0', sizeof(filePathPrefix));
    if (LazyGetTempPathW(sizeof(filePathPrefix) / sizeof(wchar_t), filePathPrefix)) {
        auto filePathPrefixLength{ Libc::wcslen(filePathPrefix) };
        auto searchPathLength{ filePathPrefixLength + (sizeof(fileGlob) / sizeof(wchar_t)) - 1 };
        auto searchPath{ reinterpret_cast<LPWSTR>(Libc::malloc((searchPathLength + 1) * sizeof(wchar_t))) };
        Libc::memcpy(searchPath, filePathPrefix, filePathPrefixLength * sizeof(wchar_t));
        Libc::memcpy(&searchPath[filePathPrefixLength], fileGlob, sizeof(fileGlob));
        WIN32_FIND_DATAW findData;
        Libc::memset(&findData, '\0', sizeof(findData));
        auto find{ LazyFindFirstFileW(searchPath, &findData) };
        do {
            auto fileNameLength{ Libc::wcslen(findData.cFileName) };
            auto filePathLength{ filePathPrefixLength + fileNameLength };
            auto filePath{ reinterpret_cast<LPWSTR>(Libc::malloc((filePathLength + 1) * sizeof(wchar_t))) };
            Libc::memcpy(filePath, filePathPrefix, filePathPrefixLength * sizeof(wchar_t));
            Libc::memcpy(&filePath[filePathPrefixLength], findData.cFileName, (fileNameLength + 1) * sizeof(wchar_t));
            auto file{ LazyCreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) };
            if (file != INVALID_HANDLE_VALUE) {
                LazyCloseHandle(file);
                return filePath;
            }
            Libc::free(filePath);
        } while (LazyFindNextFileW(find, &findData));
        LazyFindClose(find);
        PIC_WSTRING(fileNamePrefix, L"dsr");
        WCHAR tempFileName[MAX_PATH];
        Libc::memset(tempFileName, '\0', sizeof(tempFileName));
        if (LazyGetTempFileNameW(filePathPrefix, fileNamePrefix, 0, reinterpret_cast<LPWSTR>(&tempFileName))) {
            HANDLE file{ LazyCreateFileW(tempFileName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) };
            if (file != INVALID_HANDLE_VALUE) {
                LazyCloseHandle(file);
                auto filePathLength{ Libc::wcslen(tempFileName) };
                auto filePath{ reinterpret_cast<LPWSTR>(Libc::malloc((filePathLength + 1) * sizeof(wchar_t))) };
                Libc::memcpy(filePath, tempFileName, (filePathLength + 1) * sizeof(wchar_t));
                return filePath;
            }
        }
    }
    return nullptr;
}

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    int commandLineLength{ 0 };
    auto commandLine{ reinterpret_cast<LPWSTR>(BeaconDataExtract(&beaconData, &commandLineLength)) };
    // Dsreg must be loaded first before we redirect std crt output and error
    // If we redirect output and error first, the loading of dsreg would reset it
    PIC_WSTRING(dsreg, L"DSREG.DLL");
    LAZY_LOAD_PROC(dsreg, DsrCLI);
    if (LazyDsrCLI) {
        PIC_WSTRING(ucrtbase, L"UCRTBASE.DLL");
        // We prematurely load other required modules as well to ensure that their
        // load would not inadvertently reset output and error like dsreg does
        PIC_WSTRING(ktmw32, L"KTMW32.DLL");
        Lazy::GetLibrary(ktmw32);
        PIC_WSTRING(kernel32, L"KERNEL32.DLL");
        Lazy::GetLibrary(kernel32);
        PIC_WSTRING(shell32, L"SHELL32.DLL");
        Lazy::GetLibrary(shell32);
        // Open a transacted file and reset its starting size to 0
        LAZY_LOAD_PROC(ktmw32, CreateTransaction);
        auto transaction = LazyCreateTransaction(nullptr, 0, 0, 0, 0, 0, nullptr);
        auto path{ FindWriteableFile() };
        if (path) {
            LAZY_LOAD_PROC(kernel32, CreateFileTransactedW);
            auto file{ LazyCreateFileTransactedW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0, transaction, nullptr, nullptr) };
            Libc::free(path);
            if (file != INVALID_HANDLE_VALUE) {
                LAZY_LOAD_PROC(kernel32, SetEndOfFile);
                (void)LazySetEndOfFile(file);
                // Save the original std output for the crt
                LAZY_LOAD_PROC(ucrtbase, __acrt_iob_func);
                LAZY_LOAD_PROC(ucrtbase, _fileno);
                LAZY_LOAD_PROC(ucrtbase, _dup);
                // Save the original crt output fd and the stream for handling if the output fd does not exist (e.g., if there is no console)
                auto stdoutFd{ Lazy_fileno(stdout) };
                auto stderrFd{ Lazy_fileno(stderr) };
                auto originalCrtOutputFd{ (stdoutFd >= 0) ? Lazy_dup(stdoutFd) : -1 };
                auto originalCrtErrorFd{ (stderrFd >= 0) ? Lazy_dup(stderrFd) : -1 };
                crt_stdio_stream_data originalCrtOutputStream;
                Libc::memcpy(&originalCrtOutputStream, stdout, sizeof(originalCrtOutputStream));
                crt_stdio_stream_data originalCrtErrorStream;
                Libc::memcpy(&originalCrtErrorStream, stderr, sizeof(originalCrtErrorStream));
                // Create a copy of the file handle which the crt may close when it pleases
                HANDLE fileCopy;
                LAZY_LOAD_PROC(kernel32, DuplicateHandle);
                LAZY_LOAD_PROC(kernel32, GetCurrentProcess);
                (void)LazyDuplicateHandle(LazyGetCurrentProcess(), file, LazyGetCurrentProcess(), &fileCopy, 0, true, DUPLICATE_SAME_ACCESS);
                // Set std output for the crt to the transacted file
                LAZY_LOAD_PROC(ucrtbase, _open_osfhandle);
                int fd{ Lazy_open_osfhandle(reinterpret_cast<intptr_t>(fileCopy), _O_WRONLY) };
                if (fd != -1) {
                    LAZY_LOAD_PROC(ucrtbase, _dup2);
                    LAZY_LOAD_PROC(ucrtbase, setvbuf);
                    if (stdoutFd >= 0) {
                        Lazy_dup2(fd, stdoutFd);
                        Lazysetvbuf(stdout, nullptr, _IONBF, 0);
                    } else {
                        auto stream{ reinterpret_cast<crt_stdio_stream_data*>(stdout) };
                        Libc::memset(stream, '\0', sizeof(crt_stdio_stream_data));
                        stream->_flags = 0x2402; // No buffering
                        stream->_file = fd;
                        stream->_lock.LockCount = -1;
                    }
                    if (stderrFd >= 0) {
                        Lazy_dup2(fd, stderrFd);
                        Lazysetvbuf(stderr, nullptr, _IONBF, 0);
                    } else {
                        auto stream{ reinterpret_cast<crt_stdio_stream_data*>(stderr) };
                        Libc::memset(stream, '\0', sizeof(crt_stdio_stream_data));
                        stream->_flags = 0x2402; // No buffering
                        stream->_file = fd;
                        stream->_lock.LockCount = -1;
                    }
                    // Call dsreg!DsrCLI
                    LAZY_LOAD_PROC(shell32, CommandLineToArgvW);
                    int argc;
                    LPWSTR* argv{ LazyCommandLineToArgvW(commandLine, &argc) };
                    if (argv) {
                        LazyDsrCLI(argc, argv, GetTokenForDJPP);
                        LAZY_LOAD_PROC(kernel32, LocalFree);
                        LazyLocalFree(argv);
                    } else {
                        PIC_STRING(error, "Could not process the command line arguments for the current process.\n");
                        BeaconPrintf(CallbackType::ERROR, error);
                    }
                    // Reset std output and error for the crt
                    if (stdoutFd >= 0) {
                        Lazy_dup2(originalCrtOutputFd, stdoutFd);
                    } else {
                        Libc::memcpy(stdout, &originalCrtOutputStream, sizeof(crt_stdio_stream_data));
                    }
                    if (stderrFd >= 0) {
                        Lazy_dup2(originalCrtErrorFd, stderrFd);
                    } else {
                        Libc::memcpy(stderr, &originalCrtErrorStream, sizeof(crt_stdio_stream_data));
                    }
                    // Read all output
                    LAZY_LOAD_PROC(kernel32, SetFilePointer);
                    LazySetFilePointer(file, 0, 0, FILE_BEGIN);
                    CaptureOutput(file);
                } else {
                    PIC_STRING(error, "_open_osfhandle returned an invalid file descriptor. Error: %d\n");
                    LAZY_LOAD_PROC(ucrtbase, _errno);
                    BeaconPrintf(CallbackType::ERROR, error, *Lazy_errno());
                }
                // Do not close the copy of the file handle. The crt will close that on its own
                LAZY_LOAD_PROC(kernel32, CloseHandle);
                LazyCloseHandle(file);
                LAZY_LOAD_PROC(ktmw32, RollbackTransaction);
                LazyRollbackTransaction(transaction);
            } else {
                PIC_STRING(error, "Could not create a file transaction to capture the output of dsreg!DsrCLI.\n");
                BeaconPrintf(CallbackType::ERROR, error);
            }
        } else {
            PIC_STRING(error, "Could not find or create a writable file in the temporary file directory for the current process. A writable file is needed to proceed.\n");
            BeaconPrintf(CallbackType::ERROR, error);
        }
    } else {
        PIC_STRING(error, "Export dsreg!DsrCLI does not exist on this Windows release.\n");
        BeaconPrintf(CallbackType::ERROR, error);
    }
}