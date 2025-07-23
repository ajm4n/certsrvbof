#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "beacon.h"
#include <tlhelp32.h>

// Remove the SAFE_STR macro and add a static inline function
static const char *safe_str(const char *x) {
    return (x && x[0]) ? x : "(empty)";
}

// Dynamically resolve WinINet functions
typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);

static pInternetOpenA _InternetOpenA = NULL;
static pInternetOpenUrlA _InternetOpenUrlA = NULL;
static pInternetReadFile _InternetReadFile = NULL;
static pInternetCloseHandle _InternetCloseHandle = NULL;

int resolve_wininet() {
    HMODULE hWininet = GetModuleHandleA("wininet.dll");
    if (!hWininet) {
        hWininet = LoadLibraryA("wininet.dll");
        if (!hWininet) return 0;
    }
    _InternetOpenA = (pInternetOpenA)GetProcAddress(hWininet, "InternetOpenA");
    _InternetOpenUrlA = (pInternetOpenUrlA)GetProcAddress(hWininet, "InternetOpenUrlA");
    _InternetReadFile = (pInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    _InternetCloseHandle = (pInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");
    if (!_InternetOpenA || !_InternetOpenUrlA || !_InternetReadFile || !_InternetCloseHandle) return 0;
    return 1;
}

#define MAX_BUF 8192
#define MAX_TEMPLATE_COUNT 128

// Nighthawk-safe case-insensitive string compare (ASCII only)
int nh_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

// Nighthawk-safe case-insensitive substring search (ASCII only)
int nh_strcasestr(const char *haystack, const char *needle) {
    int hlen = (int)strlen(haystack);
    int nlen = (int)strlen(needle);
    if (nlen == 0 || nlen > hlen) return 0;
    for (int i = 0; i <= hlen - nlen; i++) {
        int match = 1;
        for (int j = 0; j < nlen; j++) {
            char ca = haystack[i + j], cb = needle[j];
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

// Helper: Check if a string matches any in a list (Nighthawk-safe)
int nh_matches_any(const char *str, const char *list[], int count) {
    for (int i = 0; i < count; i++) {
        if (nh_strcasestr(str, list[i])) return 1;
    }
    return 0;
}

// Fetch and parse /certsrv/certrqbi.asp for templates the current user can enroll in
int nh_get_enrollable_templates(char *base_url, char enrollable_templates[][128], int max_templates) {
    char url[512];
    snprintf(url, sizeof(url), "%s/certrqbi.asp", base_url);

    HINTERNET hInternet = _InternetOpenA("certenum", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpen failed: %u", (unsigned int)GetLastError());
        return 0;
    }

    HINTERNET hConnect = _InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpenUrl failed: %u", (unsigned int)GetLastError());
        _InternetCloseHandle(hInternet);
        return 0;
    }

    BYTE buffer[4096] = {0};
    DWORD bytesRead = 0;
    if (!_InternetReadFile(hConnect, buffer, sizeof(buffer)-1, &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "InternetReadFile failed: %u", (unsigned int)GetLastError());
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        return 0;
    }
    buffer[bytesRead] = '\0';
    int enrollable_count = 0;
    char *start = strstr((char*)buffer, "<select name=\"CertTemplate\"");
    if (!start) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find template select box");
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        return 0;
    }
    char *end = strstr(start, "</select>");
    if (!end) {
        BeaconPrintf(CALLBACK_ERROR, "Malformed HTML");
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        return 0;
    }
    char *p = start;
    while ((p = strstr(p, "<option value=\"")) && p < end && enrollable_count < max_templates) {
        p += strlen("<option value=\"");
        char *q = strchr(p, '"');
        if (!q || q > end) break;
        int len = q - p;
        if (len > 0 && len < 128) {
            memset(enrollable_templates[enrollable_count], 0, 128);
            memcpy(enrollable_templates[enrollable_count], p, len);
            enrollable_templates[enrollable_count][len] = '\0';
            enrollable_count++;
        }
    }
    _InternetCloseHandle(hConnect);
    _InternetCloseHandle(hInternet);
    return enrollable_count;
}

// Helper: Check if template is in enrollable list (Nighthawk-safe)
int nh_is_enrollable(const char *template_name, char enrollable_templates[][128], int enrollable_count) {
    for (int i = 0; i < enrollable_count; i++) {
        if (nh_stricmp(template_name, enrollable_templates[i]) == 0) return 1;
    }
    return 0;
}

// Fetch and parse /certsrv/certtmpl.asp for template details (Nighthawk-safe)
void nh_get_template_details(char *base_url, char enrollable_templates[][128], int enrollable_count) {
    char url[512];
    snprintf(url, sizeof(url), "%s/certtmpl.asp", base_url);

    HINTERNET hInternet = _InternetOpenA("certenum", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpen failed: %u", (unsigned int)GetLastError());
        return;
    }

    HINTERNET hConnect = _InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpenUrl failed: %u", (unsigned int)GetLastError());
        _InternetCloseHandle(hInternet);
        return;
    }

    BYTE buffer[4096] = {0};
    DWORD bytesRead = 0;
    if (!_InternetReadFile(hConnect, buffer, sizeof(buffer)-1, &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "InternetReadFile failed: %u", (unsigned int)GetLastError());
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        return;
    }
    buffer[bytesRead] = '\0';
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing certificate template details...");
    char *p = strstr((char*)buffer, "<table");
    if (!p) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find template table");
        _InternetCloseHandle(hConnect);
        _InternetCloseHandle(hInternet);
        return;
    }
    int template_count = 0;
    char *row = p;
    while ((row = strstr(row, "<tr>")) && template_count < 64) {
        char *row_end = strstr(row, "</tr>");
        if (!row_end) break;
        char *cell = row;
        char fields[8][256];
        int field_idx = 0;
        while ((cell = strstr(cell, "<td>")) && cell < row_end && field_idx < 8) {
            cell += 4;
            char *cell_end = strstr(cell, "</td>");
            if (!cell_end || cell_end > row_end) break;
            int len = cell_end - cell;
            if (len > 0 && len < 256) {
                memset(fields[field_idx], 0, 256);
                memcpy(fields[field_idx], cell, len);
                fields[field_idx][len] = '\0';
                field_idx++;
            }
            cell = cell_end + 5;
        }
        if (field_idx >= 3) {
            const char *template_name = fields[0];
            const char *display_name = fields[1];
            const char *purpose = fields[2];
            const char *eku = (field_idx > 3) ? fields[3] : "";
            const char *manager_approval = (field_idx > 4) ? fields[4] : "";
            const char *subject_supply = (field_idx > 5) ? fields[5] : "";
            const char *key_usage = (field_idx > 6) ? fields[6] : "";
            const char *archival = (field_idx > 7) ? fields[7] : "";
            int esc1 = 0, esc2 = 0, esc3 = 0, esc6 = 0, esc7 = 0, esc8 = 0;
            if (nh_strcasestr(purpose, "Client Authentication") &&
                !nh_strcasestr(manager_approval, "Yes") &&
                nh_strcasestr(subject_supply, "Supply")) {
                esc1 = 1;
            }
            const char *dangerous_ekus[] = {"Enrollment Agent", "Smartcard Logon", "Domain Controller", "Any Purpose"};
            if (nh_matches_any(purpose, dangerous_ekus, 4) || nh_matches_any(eku, dangerous_ekus, 4)) {
                esc2 = 1;
            }
            if (nh_strcasestr(purpose, "Enrollment Agent") || nh_strcasestr(eku, "Enrollment Agent")) {
                esc3 = 1;
            }
            if (nh_strcasestr(subject_supply, "Supply")) {
                esc6 = 1;
            }
            if (nh_strcasestr(archival, "Yes") || nh_strcasestr(key_usage, "export")) {
                esc7 = 1;
            }
            if (nh_strcasestr(key_usage, "512") || nh_strcasestr(key_usage, "1024")) {
                esc8 = 1;
            }
            const char *risky_names[] = {"User", "WebServer", "DomainController", "EnrollmentAgent"};
            int risky = nh_matches_any(template_name, risky_names, 4) || nh_matches_any(display_name, risky_names, 4);
            int can_enroll = nh_is_enrollable(template_name, enrollable_templates, enrollable_count);
            if (esc1 || esc2 || esc3 || esc6 || esc7 || esc8 || risky) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Potentially vulnerable template: %s (%s)", display_name, template_name);
                if (esc1) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC1: ClientAuth, no approval, subject supply");
                if (esc2) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC2: Dangerous EKU");
                if (esc3) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC3: Enrollment Agent");
                if (esc6) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC6: Subject name supply allowed");
                if (esc7) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC7: Key archival/export allowed");
                if (esc8) BeaconPrintf(CALLBACK_OUTPUT, "    - ESC8: Weak key size");
                if (risky) BeaconPrintf(CALLBACK_OUTPUT, "    - Name matches risky default");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Template: %s (%s)", display_name, template_name);
            }
            const char *safe_purpose = safe_str(purpose);
            const char *safe_eku = safe_str(eku);
            const char *safe_manager_approval = safe_str(manager_approval);
            const char *safe_subject_supply = safe_str(subject_supply);
            const char *safe_key_usage = safe_str(key_usage);
            const char *safe_archival = safe_str(archival);
            // Print each field and its first 8 bytes as hex for debugging
            const char *field_names[] = {"Purpose", "EKU", "Approval", "Subject", "KeyUsage", "Archival"};
            const char *field_ptrs[] = {purpose, eku, manager_approval, subject_supply, key_usage, archival};
            for (int f = 0; f < 6; f++) {
                const char *val = field_ptrs[f];
                int vlen = (val ? (int)strlen(val) : 0);
                char hexbuf[32] = {0};
                if (val) {
                    snprintf(hexbuf, sizeof(hexbuf), "%02x %02x %02x %02x %02x %02x %02x %02x", 
                        (unsigned char)val[0], (unsigned char)val[1], (unsigned char)val[2], (unsigned char)val[3],
                        (unsigned char)val[4], (unsigned char)val[5], (unsigned char)val[6], (unsigned char)val[7]);
                } else {
                    snprintf(hexbuf, sizeof(hexbuf), "(null)");
                }
                BeaconPrintf(CALLBACK_OUTPUT, "%s length: %d", field_names[f], vlen);
                BeaconPrintf(CALLBACK_OUTPUT, "%s hex: %s", field_names[f], hexbuf);
                if (vlen > 0 && vlen < 256) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s: %s", field_names[f], val);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s: (not printable, skipped)", field_names[f]);
                }
            }
            BeaconPrintf(CALLBACK_OUTPUT, "Current user can enroll: %s", can_enroll ? "YES" : "NO");
            template_count++;
        }
        row = row_end + 5;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsed %d templates from certtmpl.asp", template_count);
    _InternetCloseHandle(hConnect);
    _InternetCloseHandle(hInternet);
}

void go(char *args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "BOF started");
    // Comment out all other code for now
    // if (!resolve_wininet()) {
    //     BeaconPrintf(CALLBACK_ERROR, "Failed to resolve WinINet APIs. wininet.dll may not be present.");
    //     return;
    // }
    // datap parser;
    // char *base_url;
    // BeaconDataParse(&parser, args, len);
    // base_url = BeaconDataExtract(&parser, NULL);
    // char url_buf[512] = {0};
    // if (base_url) {
    //     strncpy(url_buf, base_url, sizeof(url_buf) - 1);
    //     url_buf[sizeof(url_buf) - 1] = '\0';
    // }
    // if (!base_url || url_buf[0] == '\0') {
    //     BeaconPrintf(CALLBACK_ERROR, "Missing or invalid URL argument.");
    //     return;
    // }
    // BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to: %s", url_buf);
    // char enrollable_templates[64][128];
    // int enrollable_count = nh_get_enrollable_templates(url_buf, enrollable_templates, 64);
    // nh_get_template_details(url_buf, enrollable_templates, enrollable_count);
}

