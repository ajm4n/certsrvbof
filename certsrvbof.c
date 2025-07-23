#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "beacon.h"

#define MAX_BUF 8192

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
}

