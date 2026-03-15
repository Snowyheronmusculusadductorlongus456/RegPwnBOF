#pragma once
#include <windows.h>
#include <winternl.h>
#include <winreg.h>
#include <stdio.h>

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

#ifdef BOF

/* ========== KERNEL32 ========== */
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCWSTR lpName);
WINBASEAPI WINBOOL WINAPI KERNEL32$DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

/* ========== ADVAPI32 ========== */
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE *lpData, DWORD cbData);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName);

/* ========== SHELL32 ========== */
WINBASEAPI WINBOOL WINAPI SHELL32$ShellExecuteExW(void *lpExecInfo);

/* ========== USER32 ========== */
WINUSERAPI WINBOOL WINAPI USER32$LockWorkStation(void);

/* ========== NTDLL ========== */
WINBASEAPI NTSTATUS NTAPI NTDLL$NtDeleteKey(HANDLE KeyHandle);

/* ========== MSVCRT ========== */
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst, const void * __restrict__ _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, va_list arg);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$_snwprintf(wchar_t * __restrict__ _Dest, size_t _Count, const wchar_t * __restrict__ _Format, ...);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t *_Str1, const wchar_t *_Str2);

#else

/* ========== KERNEL32 ========== */
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$GetLastError GetLastError
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$Sleep Sleep
#define KERNEL32$WaitForSingleObject WaitForSingleObject
#define KERNEL32$CreateFileW CreateFileW
#define KERNEL32$CreateEventW CreateEventW
#define KERNEL32$DeviceIoControl DeviceIoControl

/* ========== ADVAPI32 ========== */
#define ADVAPI32$GetTokenInformation GetTokenInformation
#define ADVAPI32$RegOpenKeyExW RegOpenKeyExW
#define ADVAPI32$RegCreateKeyExW RegCreateKeyExW
#define ADVAPI32$RegSetValueExW RegSetValueExW
#define ADVAPI32$RegQueryValueExW RegQueryValueExW
#define ADVAPI32$RegCloseKey RegCloseKey
#define ADVAPI32$RegDeleteKeyW RegDeleteKeyW
#define ADVAPI32$RegDeleteValueW RegDeleteValueW

/* ========== SHELL32 ========== */
#define SHELL32$ShellExecuteExW ShellExecuteExW

/* ========== USER32 ========== */
#define USER32$LockWorkStation LockWorkStation

/* ========== NTDLL ========== */
__declspec(dllimport) NTSTATUS NTAPI NtDeleteKey(HANDLE KeyHandle);
#define NTDLL$NtDeleteKey NtDeleteKey

/* ========== MSVCRT ========== */
#define MSVCRT$calloc calloc
#define MSVCRT$free free
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$wcslen wcslen
#define MSVCRT$_snwprintf _snwprintf
#define MSVCRT$wcscmp wcscmp

/* ========== BEACON ========== */
#define BeaconPrintf(x, y, ...) printf(y, ##__VA_ARGS__)

#endif
