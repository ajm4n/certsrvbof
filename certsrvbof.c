#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "beacon.h"

#define MAX_BUF 8192
#define MAX_TEMPLATE_COUNT 128

// Helper: Check if a string contains a substring (case-insensitive)
int strcasestr_simple(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    char *h = _strlwr(_strdup(haystack));
    char *n = _strlwr(_strdup(needle));
    int found = strstr(h, n) != NULL;
    free(h); free(n);
    return found;
}

// Helper: Check if a string matches any in a list
int matches_any(const char *str, const char *list[], int count) {
    for (int i = 0; i < count; i++) {
        if (strcasestr_simple(str, list[i])) return 1;
    }
    return 0;
}

// Store templates the current user can enroll in
static char enrollable_templates[MAX_TEMPLATE_COUNT][128];
static int enrollable_count = 0;

void http_get_templates(char *base_url) {
    char url[512];
    snprintf(url, sizeof(url), "%s/certrqbi.asp", base_url);

    HINTERNET hInternet = InternetOpenA("certenum", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpen failed: %lu", GetLastError());
        return;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpenUrl failed: %lu", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }

    BYTE buffer[MAX_BUF] = {0};
    DWORD bytesRead = 0;
    if (!InternetReadFile(hConnect, buffer, sizeof(buffer)-1, &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "InternetReadFile failed: %lu", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    buffer[bytesRead] = '\0';
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing certificate templates...");

    // Very basic HTML parsing
    char *start = strstr((char*)buffer, "<select name=\"CertTemplate\"");
    if (!start) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find template select box");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    char *end = strstr(start, "</select>");
    if (!end) {
        BeaconPrintf(CALLBACK_ERROR, "Malformed HTML");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    char *p = start;
    int count = 0;
    while ((p = strstr(p, "<option value=\"")) && p < end) {
        p += strlen("<option value=\"");
        char *q = strchr(p, '"');
        if (!q || q > end) break;

        char templateName[128] = {0};
        int len = q - p;
        if (len > 0 && len < sizeof(templateName)) {
            memcpy(templateName, p, len);
            templateName[len] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, " - %s", templateName);
            // Store for cross-reference
            if (enrollable_count < MAX_TEMPLATE_COUNT) {
                strncpy(enrollable_templates[enrollable_count], templateName, sizeof(enrollable_templates[0])-1);
                enrollable_templates[enrollable_count][sizeof(enrollable_templates[0])-1] = '\0';
                enrollable_count++;
            }
            count++;
        }
    }

    if (count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No templates found or parsed.");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d template(s).", count);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Helper: Check if template is in enrollable list
int is_enrollable(const char *template_name) {
    for (int i = 0; i < enrollable_count; i++) {
        if (_stricmp(template_name, enrollable_templates[i]) == 0) return 1;
    }
    return 0;
}

// Fetch and parse /certsrv/certtmpl.asp for template details
void http_get_template_details(char *base_url) {
    char url[512];
    snprintf(url, sizeof(url), "%s/certtmpl.asp", base_url);

    HINTERNET hInternet = InternetOpenA("certenum", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpen failed: %lu", GetLastError());
        return;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpenUrl failed: %lu", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }

    BYTE buffer[MAX_BUF] = {0};
    DWORD bytesRead = 0;
    if (!InternetReadFile(hConnect, buffer, sizeof(buffer)-1, &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "InternetReadFile failed: %lu", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }
    buffer[bytesRead] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing certificate template details...");

    // Parse HTML table rows for templates
    char *p = strstr((char*)buffer, "<table");
    if (!p) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find template table");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }
    int template_count = 0;
    char *row = p;
    while ((row = strstr(row, "<tr>")) && template_count < MAX_TEMPLATE_COUNT) {
        char *row_end = strstr(row, "</tr>");
        if (!row_end) break;
        char *cell = row;
        char *fields[8] = {0};
        int field_idx = 0;
        while ((cell = strstr(cell, "<td>")) && cell < row_end && field_idx < 8) {
            cell += 4;
            char *cell_end = strstr(cell, "</td>");
            if (!cell_end || cell_end > row_end) break;
            int len = cell_end - cell;
            if (len > 0 && len < 256) {
                static char val[8][256];
                memset(val[field_idx], 0, 256);
                memcpy(val[field_idx], cell, len);
                val[field_idx][len] = '\0';
                fields[field_idx] = val[field_idx];
                field_idx++;
            }
            cell = cell_end + 5;
        }
        if (field_idx >= 3) { // At least name, display name, purpose
            const char *template_name = fields[0];
            const char *display_name = fields[1];
            const char *purpose = fields[2];
            const char *eku = (field_idx > 3) ? fields[3] : "";
            const char *manager_approval = (field_idx > 4) ? fields[4] : "";
            const char *subject_supply = (field_idx > 5) ? fields[5] : "";
            const char *key_usage = (field_idx > 6) ? fields[6] : "";
            const char *archival = (field_idx > 7) ? fields[7] : "";

            // ESC checks
            int esc1 = 0, esc2 = 0, esc3 = 0, esc6 = 0, esc7 = 0, esc8 = 0;
            // ESC1: Client Auth, no manager approval, subject supply
            if (strcasestr_simple(purpose, "Client Authentication") &&
                !strcasestr_simple(manager_approval, "Yes") &&
                strcasestr_simple(subject_supply, "Supply")) {
                esc1 = 1;
            }
            // ESC2: Dangerous EKUs
            const char *dangerous_ekus[] = {"Enrollment Agent", "Smartcard Logon", "Domain Controller", "Any Purpose"};
            if (matches_any(purpose, dangerous_ekus, 4) || matches_any(eku, dangerous_ekus, 4)) {
                esc2 = 1;
            }
            // ESC3: Enrollment Agent
            if (strcasestr_simple(purpose, "Enrollment Agent") || strcasestr_simple(eku, "Enrollment Agent")) {
                esc3 = 1;
            }
            // ESC6: Subject supply
            if (strcasestr_simple(subject_supply, "Supply")) {
                esc6 = 1;
            }
            // ESC7: Key archival/export
            if (strcasestr_simple(archival, "Yes") || strcasestr_simple(key_usage, "export")) {
                esc7 = 1;
            }
            // ESC8: Weak key size (if key_usage or another field shows key size)
            if (strcasestr_simple(key_usage, "512") || strcasestr_simple(key_usage, "1024")) {
                esc8 = 1;
            }
            // Flag risky template names
            const char *risky_names[] = {"User", "WebServer", "DomainController", "EnrollmentAgent"};
            int risky = matches_any(template_name, risky_names, 4) || matches_any(display_name, risky_names, 4);

            // Check if current user can enroll
            int can_enroll = is_enrollable(template_name);

            // Print findings
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
            BeaconPrintf(CALLBACK_OUTPUT, "    Purpose: %s | EKU: %s | Approval: %s | Subject: %s | KeyUsage: %s | Archival: %s | Current user can enroll: %s",
                purpose, eku, manager_approval, subject_supply, key_usage, archival, can_enroll ? "YES" : "NO");
            template_count++;
        }
        row = row_end + 5;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsed %d templates from certtmpl.asp", template_count);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

void go(char *args, int len) {
    datap parser;
    char *base_url;

    BeaconDataParse(&parser, args, len);
    base_url = BeaconDataExtract(&parser, NULL);

    if (!base_url) {
        BeaconPrintf(CALLBACK_ERROR, "Missing URL argument.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to: %s", base_url);
    http_get_templates(base_url);
    http_get_template_details(base_url);
}

