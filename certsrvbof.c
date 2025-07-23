#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

// Helper: Append to output buffer safely
static void append_buf(char *buf, int *pos, int max, const char *fmt, ...) {
    if (*pos >= max - 1) return;
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf + *pos, max - *pos, fmt, args);
    va_end(args);
    if (n > 0 && *pos + n < max) {
        *pos += n;
    } else {
        *pos = max - 1;
        buf[max - 1] = '\0';
    }
}

void go(char *args, int len) {
    char *output = args;
    int outpos = 0;
    int outmax = len > 0 ? len : 4096;
    if (!output) {
        // fallback to local buffer if args is NULL
        static char fallback[4096];
        output = fallback;
        outmax = sizeof(fallback);
    }
    output[0] = '\0';

    // Example: parse URL from args (assume null-terminated)
    char url_buf[512] = {0};
    if (args && args[0]) {
        strncpy(url_buf, args, sizeof(url_buf) - 1);
        url_buf[sizeof(url_buf) - 1] = '\0';
    }
    if (!url_buf[0]) {
        append_buf(output, &outpos, outmax, "Missing or invalid URL argument.\n");
        goto done;
    }
    append_buf(output, &outpos, outmax, "[*] Connecting to: %s\n", url_buf);

    // Dynamically resolve WinINet
    HMODULE hWininet = GetModuleHandleA("wininet.dll");
    if (!hWininet) hWininet = LoadLibraryA("wininet.dll");
    if (!hWininet) {
        append_buf(output, &outpos, outmax, "Failed to load wininet.dll\n");
        goto done;
    }
    typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);
    pInternetOpenA _InternetOpenA = (pInternetOpenA)GetProcAddress(hWininet, "InternetOpenA");
    pInternetOpenUrlA _InternetOpenUrlA = (pInternetOpenUrlA)GetProcAddress(hWininet, "InternetOpenUrlA");
    pInternetReadFile _InternetReadFile = (pInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    pInternetCloseHandle _InternetCloseHandle = (pInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");
    if (!_InternetOpenA || !_InternetOpenUrlA || !_InternetReadFile || !_InternetCloseHandle) {
        append_buf(output, &outpos, outmax, "Failed to resolve WinINet APIs\n");
        goto done;
    }

    // Try to connect to CA
    char url[512];
    snprintf(url, sizeof(url), "%s/certrqbi.asp", url_buf);
    HINTERNET hInternet = _InternetOpenA("certenum", 1, NULL, NULL, 0);
    if (!hInternet) {
        append_buf(output, &outpos, outmax, "CA could not be reached (InternetOpen failed)\n");
        goto done;
    }
    HINTERNET hConnect = _InternetOpenUrlA(hInternet, url, NULL, 0, 0x80000000, 0);
    if (!hConnect) {
        append_buf(output, &outpos, outmax, "CA could not be reached (InternetOpenUrl failed)\n");
        _InternetCloseHandle(hInternet);
        goto done;
    }
    BYTE buffer[1024] = {0};
    DWORD bytesRead = 0;
    if (!_InternetReadFile(hConnect, buffer, sizeof(buffer)-1, &bytesRead)) {
        append_buf(output, &outpos, outmax, "CA could not be reached (InternetReadFile failed)\n");
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        goto done;
    }
    buffer[bytesRead] = '\0';
    append_buf(output, &outpos, outmax, "Successfully fetched certrqbi.asp (%u bytes)\n", (unsigned int)bytesRead);
    _InternetCloseHandle(hConnect);
    _InternetCloseHandle(hInternet);
    // You can continue parsing and appending to output here...

done:
    output[outmax-1] = '\0';
}

