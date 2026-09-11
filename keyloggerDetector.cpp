// keyloggerDetector - a suspicion-scoring keylogger detector for Windows
// Copyright (C) 2026 g0nchy
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <windowsx.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <unordered_set>
#include <commctrl.h>
#include <objbase.h>
#include <unordered_map>
#include <mutex>
#include <cstdlib>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")

struct ProcessInfo {
    DWORD pid = 0;
    std::wstring name;
    std::wstring path;
    int score = 0;
    std::vector<std::wstring> reasons;
    HICON icon = nullptr;
    bool expanded = false;
};

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static bool Contains(const std::wstring& haystack, const std::wstring& needle) {
    return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

// 1. Proccess enumeration

static std::vector<ProcessInfo> EnumerateProcesses() {
    std::vector<ProcessInfo> result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.name = pe.szExeFile;

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
            if (hProc) {
                wchar_t buf[MAX_PATH] = {0};
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, buf, &size)) {
                    info.path = buf;
                }
                CloseHandle(hProc);
            }

            result.push_back(info);
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

// 2. Search suspicious imports

struct ImportFlags {
    bool hasSetWindowsHookEx = false;
    bool hasKeyStatePolling  = false;
    bool hasRawInput         = false;
};

static ImportFlags CheckSuspiciousImports(const std::wstring& path) {
    ImportFlags flags;
    if (path.empty()) return flags;

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return flags;

    LARGE_INTEGER fileSizeLI{};
    if (!GetFileSizeEx(hFile, &fileSizeLI) || fileSizeLI.QuadPart <= 0 ||
        fileSizeLI.QuadPart > 200 * 1024 * 1024) {
        CloseHandle(hFile);
        return flags;
    }
    size_t fileSize = (size_t)fileSizeLI.QuadPart;

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return flags; }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return flags; }

    auto InBounds = [&](const void* ptr, size_t needed) {
        const BYTE* p = (const BYTE*)ptr;
        const BYTE* start = (const BYTE*)base;
        if (p < start) return false;
        size_t offset = (size_t)(p - start);
        return offset <= fileSize && needed <= fileSize - offset;
    };

    auto parseImports = [&]() {
        if (!InBounds(base, sizeof(IMAGE_DOS_HEADER))) return;
        auto dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto ntPtr = (BYTE*)base + dos->e_lfanew;
        if (!InBounds(ntPtr, sizeof(IMAGE_NT_HEADERS))) return;
        auto nt = (PIMAGE_NT_HEADERS)ntPtr;
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        if (nt->FileHeader.NumberOfSections == 0 ||
            nt->FileHeader.NumberOfSections > 96) return;

        auto& dataDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dataDir.VirtualAddress == 0) return;

        auto section = IMAGE_FIRST_SECTION(nt);
        if (!InBounds(section, sizeof(IMAGE_SECTION_HEADER) * nt->FileHeader.NumberOfSections))
            return;

        auto RvaToPtr = [&](DWORD rva, size_t needed) -> BYTE* {
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                DWORD start = section[i].VirtualAddress;
                DWORD end = start + section[i].Misc.VirtualSize;
                if (rva >= start && rva < end) {
                    BYTE* ptr = (BYTE*)base + section[i].PointerToRawData + (rva - start);
                    return InBounds(ptr, needed) ? ptr : nullptr;
                }
            }
            return nullptr;
        };

        auto importDesc = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPtr(dataDir.VirtualAddress,
                                                                sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!importDesc) return;

        const int MAX_IMPORT_DESCRIPTORS = 500;
        const int MAX_THUNKS_PER_DLL = 5000;

        for (int d = 0; d < MAX_IMPORT_DESCRIPTORS; d++, importDesc++) {
            if (!InBounds(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;
            if (importDesc->Name == 0) break;

            auto thunk = (PIMAGE_THUNK_DATA)RvaToPtr(
                importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk
                                                : importDesc->FirstThunk,
                sizeof(IMAGE_THUNK_DATA));
            if (!thunk) continue;

            for (int t = 0; t < MAX_THUNKS_PER_DLL; t++, thunk++) {
                if (!InBounds(thunk, sizeof(IMAGE_THUNK_DATA))) break;
                if (thunk->u1.AddressOfData == 0) break;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

                auto importByName = (PIMAGE_IMPORT_BY_NAME)RvaToPtr(
                    (DWORD)thunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME));
                if (!importByName) continue;

                // El nombre es un string de largo variable: acotamos la
                // busqueda del terminador nulo a lo que queda de archivo
                // mapeado, en vez de confiar ciegamente en que exista.
                size_t offset = (size_t)((BYTE*)importByName->Name - (BYTE*)base);
                size_t maxLen = (offset <= fileSize) ? fileSize - offset : 0;
                size_t len = strnlen((char*)importByName->Name, maxLen);
                std::string fn((char*)importByName->Name, len);

                if (fn == "SetWindowsHookExA" || fn == "SetWindowsHookExW")
                    flags.hasSetWindowsHookEx = true;
                else if (fn == "GetAsyncKeyState" || fn == "GetKeyState" ||
                         fn == "GetKeyboardState")
                    flags.hasKeyStatePolling = true;
                else if (fn == "RegisterRawInputDevices" || fn == "GetRawInputData")
                    flags.hasRawInput = true;
            }
        }
    };

    parseImports();

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return flags;
}

// 3. Digital signature

static bool IsDigitallySigned(const std::wstring& path) {
    if (path.empty()) return false;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.pFile = &fileInfo;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}

static HICON LoadProcessIcon(const std::wstring& path) {
    SHFILEINFOW shfi{};

    // Try 1:Real icon
    if (!path.empty()) {
        if (SHGetFileInfoW(path.c_str(), 0, &shfi, sizeof(shfi), SHGFI_ICON) && shfi.hIcon) {
            return shfi.hIcon;
        }
    }

    // Try 2: Generic icon
    if (SHGetFileInfoW(L"generic.exe", FILE_ATTRIBUTE_NORMAL, &shfi, sizeof(shfi),
                        SHGFI_ICON | SHGFI_USEFILEATTRIBUTES) && shfi.hIcon) {
        return shfi.hIcon;
    }

    return nullptr;
}

// Cache: Processes with same route don't repeat load
struct PathScanResult {
    ImportFlags imports;
    bool signedOk = false;
    HICON icon = nullptr;
};

struct PathCache {
    std::mutex mutex;
    std::unordered_map<std::wstring, PathScanResult> map;
};

struct ScopedBrush {
    HBRUSH h;
    explicit ScopedBrush(COLORREF c) : h(CreateSolidBrush(c)) {}
    ~ScopedBrush() { if (h) DeleteObject(h); }
    ScopedBrush(const ScopedBrush&) = delete;
    ScopedBrush& operator=(const ScopedBrush&) = delete;
    operator HBRUSH() const { return h; }
};

struct ScopedPen {
    HPEN h;
    ScopedPen(int style, int width, COLORREF c) : h(CreatePen(style, width, c)) {}
    ~ScopedPen() { if (h) DeleteObject(h); }
    ScopedPen(const ScopedPen&) = delete;
    ScopedPen& operator=(const ScopedPen&) = delete;
    operator HPEN() const { return h; }
};

static PathScanResult GetPathScanResult(const std::wstring& path, PathCache& cache) {
    {
        std::lock_guard<std::mutex> lock(cache.mutex);
        auto it = cache.map.find(path);
        if (it != cache.map.end()) {
            PathScanResult r = it->second;
            r.icon = r.icon ? CopyIcon(r.icon) : nullptr;
            return r;
        }
    }

    PathScanResult r;
    r.imports = CheckSuspiciousImports(path);
    r.signedOk = IsDigitallySigned(path);
    r.icon = LoadProcessIcon(path);

    {
        std::lock_guard<std::mutex> lock(cache.mutex);
        PathScanResult cached = r;
        cached.icon = r.icon ? CopyIcon(r.icon) : nullptr;
        cache.map[path] = cached;
    }

    return r;
}

static void DrawCopyIcon(HDC hdc, int x, int y, int size) {
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(90, 90, 90));
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

    int back = size - 4;
    Rectangle(hdc, x + 4, y, x + 4 + back, y + back);
    Rectangle(hdc, x, y + 4, x + back, y + 4 + back);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
}

static void DrawFolderIcon(HDC hdc, int x, int y, int size) {
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(90, 90, 90));
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    HBRUSH brush = CreateSolidBrush(RGB(230, 200, 120));
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);

    POINT pts[6] = {
        { x, y + size / 4 },
        { x + size / 3, y + size / 4 },
        { x + size / 3 + 3, y },
        { x + size, y },
        { x + size, y + size },
        { x, y + size }
    };
    Polygon(hdc, pts, 6);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(brush);
}

static void CopyTextToClipboard(HWND hwnd, const std::wstring& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();

    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem) {
        void* ptr = GlobalLock(hMem);
        memcpy(ptr, text.c_str(), bytes);
        GlobalUnlock(hMem);
        SetClipboardData(CF_UNICODETEXT, hMem);
    }
    CloseClipboard();
}

static void OpenFileLocation(const std::wstring& path) {
    if (path.empty()) return;
    std::wstring param = L"/select,\"" + path + L"\"";
    ShellExecuteW(nullptr, L"open", L"explorer.exe", param.c_str(), nullptr, SW_SHOWNORMAL);
}

// 4. Inivisible windows

static BOOL CALLBACK CollectVisibleWindowPidsProc(HWND hwnd, LPARAM lParam) {
    auto* pids = (std::unordered_set<DWORD>*)lParam;
    if (IsWindowVisible(hwnd) && GetWindowTextLengthW(hwnd) > 0) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        pids->insert(pid);
    }
    return TRUE;
}

static std::unordered_set<DWORD> GetPidsWithVisibleWindow() {
    std::unordered_set<DWORD> pids;
    EnumWindows(CollectVisibleWindowPidsProc, (LPARAM)&pids);
    return pids;
}

// 5. Suspicious routes

static bool IsInSuspiciousPath(const std::wstring& path) {
    return Contains(path, L"\\AppData\\Local\\Temp") ||
           Contains(path, L"\\AppData\\Roaming") ||
           Contains(path, L"\\Downloads\\") ||
           Contains(path, L"\\Windows\\Temp");
}

// 6. Typical filesystem names
static bool ImpersonatesSystemProcess(const std::wstring& name, const std::wstring& path) {
    if (path.empty()) return false;

    static const std::vector<std::wstring> systemNames = {
        L"svchost.exe", L"explorer.exe", L"csrss.exe", L"lsass.exe",
        L"winlogon.exe", L"services.exe", L"conhost.exe"
    };
    std::wstring lname = ToLower(name);
    for (auto& sysName : systemNames) {
        if (lname == sysName) {
            if (!Contains(path, L"\\Windows\\System32") &&
                !Contains(path, L"\\Windows\\SysWOW64")) {
                return true;
            }
        }
    }
    return false;
}

// 7. Persistence in the Registry

static std::vector<std::wstring> GetAutostartTargets() {
    std::vector<std::wstring> targets;

    const wchar_t* keys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    const HKEY roots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    for (HKEY root : roots) {
        for (auto keyPath : keys) {
            HKEY hKey;
            if (RegOpenKeyExW(root, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            wchar_t valueName[256];
            wchar_t valueData[MAX_PATH];
            DWORD index = 0;

            while (true) {
                DWORD nameLen = 256, dataLen = sizeof(valueData);
                DWORD type;
                LONG res = RegEnumValueW(hKey, index, valueName, &nameLen,
                                          nullptr, &type, (BYTE*)valueData, &dataLen);
                if (res != ERROR_SUCCESS) break;

                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    targets.push_back(valueData);
                }
                index++;
            }
            RegCloseKey(hKey);
        }
    }
    return targets;
}

static bool IsAutostartPath(const std::wstring& path,
                             const std::vector<std::wstring>& targets) {
    if (path.empty()) return false;
    for (auto& t : targets) {
        if (Contains(path, t) || Contains(t, path)) return true;
    }
    return false;
}

// 8. Final score

struct ScanContext {
    const std::unordered_set<DWORD>* visibleWindowPids;
    const std::vector<std::wstring>* autostartTargets;
};

static void ComputeScore(ProcessInfo& info, const ScanContext& ctx,
                          const ImportFlags& imports,
                          bool digitallySigned) {
    if (imports.hasSetWindowsHookEx) {
        info.score += 30;
        info.reasons.push_back(L"Uses SetWindowsHookEx (hook global)");
    }
    if (imports.hasKeyStatePolling) {
        info.score += 20;
        info.reasons.push_back(L"Uses GetAsyncKeyState/GetKeyState");
    }
    if (imports.hasRawInput) {
        info.score += 20;
        info.reasons.push_back(L"Uses Raw Input API");
    }
    if (!info.path.empty() && !digitallySigned) {
        info.score += 10;
        info.reasons.push_back(L"No valid digital signature");
    }
    if (ctx.visibleWindowPids->find(info.pid) == ctx.visibleWindowPids->end()) {
        info.score += 15;
        info.reasons.push_back(L"No visible window");
    }
    if (IsInSuspiciousPath(info.path)) {
        info.score += 15;
        info.reasons.push_back(L"Located in sketchy folder");
    }
    if (ImpersonatesSystemProcess(info.name, info.path)) {
        info.score += 10;
        info.reasons.push_back(L"System name path mismatch");
    }
    if (IsAutostartPath(info.path, *ctx.autostartTargets)) {
        info.score += 10;
        info.reasons.push_back(L"Has an auto-start");
    }
}

// 9. GUI

#define MAINICON 101
#define WM_REFRESH_DONE (WM_APP + 1)
#define IDC_PROCESS_LIST 100
#define IDC_REFRESH_BTN  2
#define IDC_FILTER_EDIT  3
#define IDC_THEMES_BTN   4
#define ID_THEME_BASE    2000

const wchar_t* PROCESS_LIST_CLASS = L"ProcessListCtrl";

const int ROW_HEIGHT       = 56;
const int PATH_ROW_HEIGHT  = 30;
const int ICON_SIZE        = 32;

HWND g_hListView = nullptr;
HWND g_hMainWnd = nullptr;
HWND g_hTooltip = nullptr;
DWORD g_hoveredPid = 0;

#define TOOLTIP_TOOL_ID 1

std::atomic<bool> g_isRefreshing{false};
std::vector<ProcessInfo> g_processes;
int g_scrollPos = 0;

std::wstring g_filterText;

PathCache g_pathCache;

// Themes

struct Theme {
    std::wstring name;
    COLORREF background;
    COLORREF separator;
    COLORREF textPrimary;
    COLORREF textSecondary;
};

static Theme DefaultTheme() {
    Theme t;
    t.name = L"Default";
    t.background = RGB(240, 240, 240);
    t.separator = RGB(200, 200, 200);
    t.textPrimary = RGB(30, 30, 30);
    t.textSecondary = RGB(90, 90, 90);
    return t;
}

static COLORREF ParseColorTriplet(const std::wstring& s, COLORREF fallback) {
    size_t p1 = s.find(L',');
    if (p1 == std::wstring::npos) return fallback;
    size_t p2 = s.find(L',', p1 + 1);
    if (p2 == std::wstring::npos) return fallback;

    int r = _wtoi(s.substr(0, p1).c_str());
    int g = _wtoi(s.substr(p1 + 1, p2 - p1 - 1).c_str());
    int b = _wtoi(s.substr(p2 + 1).c_str());

    r = std::max(0, std::min(255, r));
    g = std::max(0, std::min(255, g));
    b = std::max(0, std::min(255, b));
    return RGB(r, g, b);
}

static std::wstring GetThemesFolder() {
    wchar_t exePath[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    if (len == 0 || len == MAX_PATH) {
        return L".\\themes";
    }

    std::wstring path(exePath);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) path = path.substr(0, pos);
    path += L"\\themes";
    return path;
}

// Themes
static void EnsureDefaultThemeFile() {
    std::wstring folder = GetThemesFolder();
    CreateDirectoryW(folder.c_str(), nullptr);

    std::wstring defaultPath = folder + L"\\default.ini";
    if (GetFileAttributesW(defaultPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Theme d = DefaultTheme();
        WritePrivateProfileStringW(L"Theme", L"name", d.name.c_str(), defaultPath.c_str());
        WritePrivateProfileStringW(L"Colors", L"background", L"240,240,240", defaultPath.c_str());
        WritePrivateProfileStringW(L"Colors", L"separator", L"200,200,200", defaultPath.c_str());
        WritePrivateProfileStringW(L"Colors", L"text_primary", L"30,30,30", defaultPath.c_str());
        WritePrivateProfileStringW(L"Colors", L"text_secondary", L"90,90,90", defaultPath.c_str());
    }
}

static Theme LoadThemeFromFile(const std::wstring& path, const Theme& fallback) {
    Theme t = fallback;

    wchar_t buf[64];
    GetPrivateProfileStringW(L"Theme", L"name", fallback.name.c_str(), buf, 64, path.c_str());
    t.name = buf;
    if (t.name.size() > 24) t.name = t.name.substr(0, 24);

    auto readColor = [&](const wchar_t* key, COLORREF fb) -> COLORREF {
        wchar_t cbuf[64] = {0};
        GetPrivateProfileStringW(L"Colors", key, L"", cbuf, 64, path.c_str());
        if (cbuf[0] == L'\0') return fb;
        return ParseColorTriplet(cbuf, fb);
    };

    t.background = readColor(L"background", fallback.background);
    t.separator = readColor(L"separator", fallback.separator);
    t.textPrimary = readColor(L"text_primary", fallback.textPrimary);
    t.textSecondary = readColor(L"text_secondary", fallback.textSecondary);

    return t;
}

std::vector<Theme> g_themes;
std::wstring g_activeThemeName = L"Default";

static void ScanThemes() {
    g_themes.clear();
    Theme fallback = DefaultTheme();

    std::wstring folder = GetThemesFolder();
    std::wstring pattern = folder + L"\\*.ini";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring fullPath = folder + L"\\" + fd.cFileName;
            g_themes.push_back(LoadThemeFromFile(fullPath, fallback));
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    if (g_themes.empty()) {
        g_themes.push_back(fallback);
    }

    // default always first
    std::stable_sort(g_themes.begin(), g_themes.end(),
        [](const Theme& a, const Theme& b) {
            bool aDef = (a.name == L"Default");
            bool bDef = (b.name == L"Default");
            return aDef && !bDef;
        });
}

static const Theme& GetActiveTheme() {
    for (auto& t : g_themes) {
        if (t.name == g_activeThemeName) return t;
    }
    if (!g_themes.empty()) return g_themes[0];
    static Theme fallback = DefaultTheme();
    return fallback;
}

HBRUSH g_bgBrush = nullptr;
COLORREF g_bgBrushColor = 0xFFFFFFFF; // Invalid color

static HBRUSH GetBgBrush() {
    COLORREF current = GetActiveTheme().background;
    if (!g_bgBrush || g_bgBrushColor != current) {
        if (g_bgBrush) DeleteObject(g_bgBrush);
        g_bgBrush = CreateSolidBrush(current);
        g_bgBrushColor = current;
    }
    return g_bgBrush;
}

#define IDT_SPINNER_TIMER 1
ULONGLONG g_scanStartTick = 0;

const int MARQUEE_WIDTH = 52;
int g_marqueeOffset = 0;

const wchar_t* DECOR_LEFT  = L".:*~*:._.-->";
const wchar_t* DECOR_RIGHT = L"<--.-:*~*:.";

struct ScanSummary {
    unsigned processCount = 0;
    int high = 0, medium = 0, low = 0;
    double elapsedSeconds = 0.0;
};
ScanSummary g_lastScan;

static bool PassesFilter(const ProcessInfo& p) {
    if (g_filterText.empty()) return true;
    return Contains(p.name, g_filterText);
}

// Layout constants and score thresholds.

const int SCORE_THRESHOLD_HIGH   = 60;
const int SCORE_THRESHOLD_MEDIUM = 30;

const int ROW_ICON_MARGIN_LEFT   = 14;
const int ROW_ICON_TEXT_GAP      = 12;
const int ROW_NAME_WIDTH         = 260;
const int ROW_BADGE_GAP          = 10;
const int ROW_BADGE_WIDTH        = 90;
const int ROW_BADGE_HEIGHT       = 22;
const int ROW_REASONS_GAP        = 16;
const int ROW_REASONS_RIGHT_MARGIN = 56;
const int ROW_ARROW_WIDTH          = 28;
const int ROW_ARROW_RIGHT_MARGIN   = 12;
const int ROW_PATH_RIGHT_MARGIN    = 78;
const int ROW_ACTION_ICON_SIZE        = 16;
const int ROW_COPY_ICON_RIGHT_OFFSET  = 66;
const int ROW_FOLDER_ICON_RIGHT_OFFSET = 34;
const int ROW_COPY_CLICK_LEFT   = 68;
const int ROW_COPY_CLICK_RIGHT  = 44;
const int ROW_OPEN_CLICK_LEFT   = 36;
const int ROW_OPEN_CLICK_RIGHT  = 12;

static COLORREF ColorForScore(int score) {
    if (score >= SCORE_THRESHOLD_HIGH) return RGB(230, 90, 90);
    if (score >= SCORE_THRESHOLD_MEDIUM) return RGB(230, 190, 70);
    return RGB(120, 190, 120);
}

static int RowHeightOf(const ProcessInfo& p) {
    return ROW_HEIGHT + (p.expanded ? PATH_ROW_HEIGHT : 0);
}

static int TotalContentHeight() {
    int total = 0;
    for (auto& p : g_processes) {
        if (!PassesFilter(p)) continue;
        total += RowHeightOf(p);
    }
    return total;
}

static void UpdateScrollRange(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);

    SCROLLINFO si{ sizeof(si) };
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = std::max(0L, (long)TotalContentHeight() - 1);
    si.nPage = rc.bottom;
    si.nPos = g_scrollPos;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

struct RowHit {
    ProcessInfo* proc = nullptr;
    int rowTop = 0;
    int rowHeight = 0;
};

static bool HitTestRow(int mouseY, RowHit& hit) {
    int y = -g_scrollPos;
    for (auto& p : g_processes) {
        if (!PassesFilter(p)) continue;
        int rowH = RowHeightOf(p);
        if (mouseY >= y && mouseY < y + rowH) {
            hit.proc = &p;
            hit.rowTop = y;
            hit.rowHeight = rowH;
            return true;
        }
        y += rowH;
    }
    return false;
}

static void DrawProcessRow(HDC memDC, const ProcessInfo& p, int y, int rowH,
                            const Theme& theme, int clientRight,
                            HFONT nameFont, HFONT pathFont, HFONT arrowFont) {
    {
        ScopedBrush sevBrush(ColorForScore(p.score));
        RECT sevRc = { 0, y, 4, y + rowH };
        FillRect(memDC, &sevRc, sevBrush);
    }

    if (p.icon) {
        DrawIconEx(memDC, ROW_ICON_MARGIN_LEFT, y + (ROW_HEIGHT - ICON_SIZE) / 2,
                   p.icon, ICON_SIZE, ICON_SIZE, 0, nullptr, DI_NORMAL);
    }

    const int nameX = ROW_ICON_MARGIN_LEFT + ICON_SIZE + ROW_ICON_TEXT_GAP;

    // Name (PID)
    wchar_t label[300];
    swprintf(label, 300, L"%ls (%lu)", p.name.c_str(), p.pid);
    SelectObject(memDC, nameFont);
    SetTextColor(memDC, theme.textPrimary);
    RECT textRc = { nameX, y, nameX + ROW_NAME_WIDTH, y + ROW_HEIGHT };
    DrawTextW(memDC, label, -1, &textRc, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

    // Level badge
    const wchar_t* levelText = p.score >= SCORE_THRESHOLD_HIGH ? L"HIGH"
                              : p.score >= SCORE_THRESHOLD_MEDIUM ? L"MEDIUM" : L"LOW";
    int levelX = nameX + ROW_NAME_WIDTH + ROW_BADGE_GAP;
    RECT badgeRc = { levelX, y + (ROW_HEIGHT - ROW_BADGE_HEIGHT) / 2,
                      levelX + ROW_BADGE_WIDTH, y + (ROW_HEIGHT - ROW_BADGE_HEIGHT) / 2 + ROW_BADGE_HEIGHT };
    {
        ScopedBrush badgeBrush(ColorForScore(p.score));
        FillRect(memDC, &badgeRc, badgeBrush);
    }

    wchar_t badgeLabel[32];
    swprintf(badgeLabel, 32, L"%ls (%d)", levelText, p.score);
    SelectObject(memDC, pathFont);
    SetTextColor(memDC, RGB(255, 255, 255));
    DrawTextW(memDC, badgeLabel, -1, &badgeRc, DT_SINGLELINE | DT_CENTER | DT_VCENTER);

    // Motives
    int reasonsX = levelX + ROW_BADGE_WIDTH + ROW_REASONS_GAP;
    std::wstring motivos;
    for (size_t i = 0; i < p.reasons.size(); i++) {
        motivos += p.reasons[i];
        if (i + 1 < p.reasons.size()) motivos += L"  \u2022  ";
    }
    if (motivos.empty()) motivos = L"No signals detected";

    SelectObject(memDC, pathFont);
    SetTextColor(memDC, theme.textSecondary);
    RECT reasonsRc = { reasonsX, y, clientRight - ROW_REASONS_RIGHT_MARGIN, y + ROW_HEIGHT };
    DrawTextW(memDC, motivos.c_str(), -1, &reasonsRc, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

    // Expand/collapse arrow
    RECT arrowRc = { clientRight - (ROW_ARROW_WIDTH + ROW_ARROW_RIGHT_MARGIN), y,
                      clientRight - ROW_ARROW_RIGHT_MARGIN, y + ROW_HEIGHT };
    SelectObject(memDC, arrowFont);
    SetTextColor(memDC, theme.textSecondary);
    DrawTextW(memDC, p.expanded ? L"\u25BE" : L"\u25B8", -1, &arrowRc,
              DT_SINGLELINE | DT_CENTER | DT_VCENTER);

    // Expanded path + copy/open icons
    if (p.expanded) {
        RECT pathRc = { nameX, y + ROW_HEIGHT, clientRight - ROW_PATH_RIGHT_MARGIN, y + rowH };
        SelectObject(memDC, pathFont);
        SetTextColor(memDC, theme.textSecondary);
        DrawTextW(memDC, p.path.c_str(), -1, &pathRc, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

        int iconY = y + ROW_HEIGHT + (PATH_ROW_HEIGHT - ROW_ACTION_ICON_SIZE) / 2;
        DrawCopyIcon(memDC, clientRight - ROW_COPY_ICON_RIGHT_OFFSET, iconY, ROW_ACTION_ICON_SIZE);
        DrawFolderIcon(memDC, clientRight - ROW_FOLDER_ICON_RIGHT_OFFSET, iconY, ROW_ACTION_ICON_SIZE);
    }

    MoveToEx(memDC, 0, y + rowH - 1, nullptr);
    LineTo(memDC, clientRight, y + rowH - 1);
}

LRESULT CALLBACK ProcessListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

        const Theme& theme = GetActiveTheme();

        HBRUSH bgBrush = CreateSolidBrush(theme.background);
        FillRect(memDC, &rc, bgBrush);
        DeleteObject(bgBrush);

        HPEN linePen = CreatePen(PS_SOLID, 1, theme.separator);
        HPEN oldPen = (HPEN)SelectObject(memDC, linePen);

        SetBkMode(memDC, TRANSPARENT);

        HFONT nameFont = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HFONT pathFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HFONT arrowFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HFONT systemFallbackFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        if (!nameFont) nameFont = systemFallbackFont;
        if (!pathFont) pathFont = systemFallbackFont;
        if (!arrowFont) arrowFont = systemFallbackFont;

        int y = -g_scrollPos;
        for (auto& p : g_processes) {
            if (!PassesFilter(p)) continue;
            int rowH = RowHeightOf(p);

            if (y + rowH >= 0 && y <= rc.bottom) {
                DrawProcessRow(memDC, p, y, rowH, theme, rc.right, nameFont, pathFont, arrowFont);
            }

            y += rowH;
        }

        SelectObject(memDC, oldPen);
        DeleteObject(linePen);
        if (nameFont != systemFallbackFont) DeleteObject(nameFont);
        if (pathFont != systemFallbackFont) DeleteObject(pathFont);
        if (arrowFont != systemFallbackFont) DeleteObject(arrowFont);

        BitBlt(hdc, 0, 0, rc.right, rc.bottom, memDC, 0, 0, SRCCOPY);

        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme{ sizeof(tme) };
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = hwnd;
        TrackMouseEvent(&tme);

        int mx = GET_X_LPARAM(lParam);
        int my = GET_Y_LPARAM(lParam);

        ProcessInfo* hovered = nullptr;
        RowHit moveHit;
        if (HitTestRow(my, moveHit) && my < moveHit.rowTop + ROW_HEIGHT) {
            hovered = moveHit.proc;
        }

        DWORD newPid = hovered ? hovered->pid : 0;
        if (newPid != g_hoveredPid) {
            g_hoveredPid = newPid;

            TOOLINFOW ti{};
            ti.cbSize = TTTOOLINFOW_V1_SIZE;
            ti.hwnd = hwnd;
            ti.uId = TOOLTIP_TOOL_ID;

            if (hovered && !hovered->reasons.empty()) {
                static wchar_t tipBuf[1024];
                std::wstring text;
                for (size_t i = 0; i < hovered->reasons.size(); i++) {
                    text += L"\u2022 " + hovered->reasons[i];
                    if (i + 1 < hovered->reasons.size()) text += L"\n";
                }
                wcsncpy(tipBuf, text.c_str(), 1023);
                tipBuf[1023] = 0;
                ti.lpszText = tipBuf;
                SendMessageW(g_hTooltip, TTM_UPDATETIPTEXT, 0, (LPARAM)&ti);

                POINT pt{ mx, my };
                ClientToScreen(hwnd, &pt);
                SendMessageW(g_hTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(pt.x + 18, pt.y + 18));
                SendMessageW(g_hTooltip, TTM_TRACKACTIVATE, TRUE, (LPARAM)&ti);
            } else {
                SendMessageW(g_hTooltip, TTM_TRACKACTIVATE, FALSE, (LPARAM)&ti);
            }
        } else if (hovered) {
            POINT pt{ mx, my };
            ClientToScreen(hwnd, &pt);
            SendMessageW(g_hTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(pt.x + 18, pt.y + 18));
        }
        return 0;
    }

    case WM_MOUSELEAVE: {
        g_hoveredPid = 0;
        TOOLINFOW ti{};
        ti.cbSize = TTTOOLINFOW_V1_SIZE;
        ti.hwnd = hwnd;
        ti.uId = TOOLTIP_TOOL_ID;
        SendMessageW(g_hTooltip, TTM_TRACKACTIVATE, FALSE, (LPARAM)&ti);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int mx = GET_X_LPARAM(lParam);
        int my = GET_Y_LPARAM(lParam);

        RECT rc;
        GetClientRect(hwnd, &rc);

        RowHit lHit;
        if (HitTestRow(my, lHit)) {
            ProcessInfo& p = *lHit.proc;
            int y = lHit.rowTop;

            if (my < y + ROW_HEIGHT) {
                RECT arrowRc = { rc.right - (ROW_ARROW_WIDTH + ROW_ARROW_RIGHT_MARGIN), y,
                                  rc.right - ROW_ARROW_RIGHT_MARGIN, y + ROW_HEIGHT };
                if (mx >= arrowRc.left && mx <= arrowRc.right) {
                    p.expanded = !p.expanded;
                    UpdateScrollRange(hwnd);
                    InvalidateRect(hwnd, nullptr, TRUE);
                }
            } else if (p.expanded) {
                RECT copyRc = { rc.right - ROW_COPY_CLICK_LEFT, y + ROW_HEIGHT,
                                 rc.right - ROW_COPY_CLICK_RIGHT, y + lHit.rowHeight };
                RECT openRc = { rc.right - ROW_OPEN_CLICK_LEFT, y + ROW_HEIGHT,
                                 rc.right - ROW_OPEN_CLICK_RIGHT, y + lHit.rowHeight };

                if (mx >= copyRc.left && mx <= copyRc.right) {
                    CopyTextToClipboard(hwnd, p.path);
                } else if (mx >= openRc.left && mx <= openRc.right) {
                    OpenFileLocation(p.path);
                }
            }
        }
        return 0;
    }

    case WM_RBUTTONDOWN: {
        int mx = GET_X_LPARAM(lParam);
        int my = GET_Y_LPARAM(lParam);

        RECT rc;
        GetClientRect(hwnd, &rc);

        RowHit rHit;
        if (HitTestRow(my, rHit) && !rHit.proc->path.empty()) {
            const std::wstring& path = rHit.proc->path;

            POINT pt{ mx, my };
            ClientToScreen(hwnd, &pt);

            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, 1, L"Copy file path");
            AppendMenuW(menu, MF_STRING, 2, L"Open file location");

            int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                      pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);

            if (cmd == 1) CopyTextToClipboard(hwnd, path);
            else if (cmd == 2) OpenFileLocation(path);
        }
        return 0;
    }

    case WM_VSCROLL: {
        SCROLLINFO si{ sizeof(si) };
        si.fMask = SIF_ALL;
        GetScrollInfo(hwnd, SB_VERT, &si);

        int pos = si.nPos;
        switch (LOWORD(wParam)) {
        case SB_LINEUP:   pos -= 20; break;
        case SB_LINEDOWN: pos += 20; break;
        case SB_PAGEUP:   pos -= si.nPage; break;
        case SB_PAGEDOWN: pos += si.nPage; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: pos = si.nTrackPos; break;
        }
        pos = std::max((long)si.nMin, std::min((long)pos, si.nMax - (long)si.nPage + 1));
        g_scrollPos = pos;

        si.fMask = SIF_POS;
        si.nPos = pos;
        SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }

    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        RECT rc;
        GetClientRect(hwnd, &rc);
        long maxScroll = std::max(0L, (long)TotalContentHeight() - rc.bottom);

        g_scrollPos -= (delta / WHEEL_DELTA) * 40;
        g_scrollPos = (int)std::max(0L, std::min((long)g_scrollPos, maxScroll));

        UpdateScrollRange(hwnd);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Scan in separate thread

struct ScanChunk {
    ProcessInfo* items;
    size_t count;
    ScanContext ctx;
    PathCache* pathCache;
};

DWORD WINAPI ScanChunkProc(LPVOID param) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    auto* chunk = (ScanChunk*)param;
    for (size_t i = 0; i < chunk->count; i++) {
        ProcessInfo& p = chunk->items[i];
        PathScanResult r = GetPathScanResult(p.path, *chunk->pathCache);
        ComputeScore(p, chunk->ctx, r.imports, r.signedOk);
        p.icon = r.icon;
    }

    CoUninitialize();
    return 0;
}

DWORD WINAPI RefreshThreadProc(LPVOID) {
    auto* newList = new std::vector<ProcessInfo>(EnumerateProcesses());

    auto visibleWindowPids = GetPidsWithVisibleWindow();
    auto autostartTargets = GetAutostartTargets();

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    size_t numThreads = std::max(1u, (unsigned)sysInfo.dwNumberOfProcessors) * 2;
    numThreads = std::min(numThreads, (size_t)16);
    numThreads = std::min(numThreads, std::max((size_t)1, newList->size()));

    size_t total = newList->size();
    size_t chunkSize = (total + numThreads - 1) / numThreads;

    std::vector<ScanChunk> chunks(numThreads);
    std::vector<HANDLE> threads;

    for (size_t t = 0; t < numThreads; t++) {
        size_t start = t * chunkSize;
        size_t end = std::min(start + chunkSize, total);
        if (start >= end) continue;

        chunks[t].items = newList->data() + start;
        chunks[t].count = end - start;
        chunks[t].ctx.visibleWindowPids = &visibleWindowPids;
        chunks[t].ctx.autostartTargets = &autostartTargets;
        chunks[t].pathCache = &g_pathCache;

        HANDLE h = CreateThread(nullptr, 0, ScanChunkProc, &chunks[t], 0, nullptr);
        if (h) threads.push_back(h);
    }

    if (!threads.empty()) {
        WaitForMultipleObjects((DWORD)threads.size(), threads.data(), TRUE, INFINITE);
        for (auto h : threads) CloseHandle(h);
    }

    std::sort(newList->begin(), newList->end(),
              [](const ProcessInfo& a, const ProcessInfo& b) {
                  return a.score > b.score;
              });

    PostMessage(g_hMainWnd, WM_REFRESH_DONE, 0, (LPARAM)newList);
    return 0;
}

static void RefreshProcesses(HWND hwnd) {
    if (g_isRefreshing) return;
    g_isRefreshing = true;

    HWND btn = GetDlgItem(hwnd, IDC_REFRESH_BTN);
    EnableWindow(btn, FALSE);
    SetWindowTextW(btn, L"Refreshing...");

    g_scanStartTick = GetTickCount64();

    HANDLE hThread = CreateThread(nullptr, 0, RefreshThreadProc, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);
}

static void ShowThemesMenu(HWND hwnd) {
    ScanThemes();

    HWND btn = GetDlgItem(hwnd, IDC_THEMES_BTN);
    RECT btnRc;
    GetWindowRect(btn, &btnRc);

    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    for (size_t i = 0; i < g_themes.size(); i++) {
        AppendMenuW(menu, MF_OWNERDRAW, (UINT_PTR)(ID_THEME_BASE + i), nullptr);
    }

    TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_TOPALIGN, btnRc.left, btnRc.bottom, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

// Main window

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc;
        GetClientRect(hwnd, &rc);

        CreateWindowW(L"BUTTON", L"Refresh",
            WS_CHILD | WS_VISIBLE, 10, 5, 120, 28,
            hwnd, (HMENU)IDC_REFRESH_BTN, GetModuleHandle(nullptr), nullptr);

        HWND hFilter = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            140, 8, 220, 22,
            hwnd, (HMENU)IDC_FILTER_EDIT, GetModuleHandle(nullptr), nullptr);
        SendMessageW(hFilter, EM_SETCUEBANNER, 0, (LPARAM)L"Filter by name...");

        HWND hThemesBtn = CreateWindowW(L"BUTTON", L"Themes",
            WS_CHILD | WS_VISIBLE, rc.right - 170, 5, 160, 28,
            hwnd, (HMENU)IDC_THEMES_BTN, GetModuleHandle(nullptr), nullptr);
        {
            wchar_t btnText[64];
            swprintf(btnText, 64, L"Themes: %ls", GetActiveTheme().name.c_str());
            SetWindowTextW(hThemesBtn, btnText);
        }

        g_hListView = CreateWindowExW(WS_EX_CLIENTEDGE, PROCESS_LIST_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL,
            10, 45, rc.right - 20, rc.bottom - 55,
            hwnd, (HMENU)IDC_PROCESS_LIST, GetModuleHandle(nullptr), nullptr);
        if (!g_hListView) {
            MessageBoxW(hwnd, L"Failed to create the process list control.",
                        L"keyloggerDetector", MB_OK | MB_ICONERROR);
            return -1;
        }

        g_hTooltip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
            WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            hwnd, nullptr, GetModuleHandle(nullptr), nullptr);

        TOOLINFOW ti{};
        ti.cbSize = TTTOOLINFOW_V1_SIZE;
        ti.uFlags = TTF_TRACK | TTF_ABSOLUTE;
        ti.hwnd = g_hListView;
        ti.uId = TOOLTIP_TOOL_ID;
        ti.lpszText = (LPWSTR)L"";
        SendMessageW(g_hTooltip, TTM_ADDTOOL, 0, (LPARAM)&ti);
        SendMessageW(g_hTooltip, TTM_SETMAXTIPWIDTH, 0, 380);

        g_hMainWnd = hwnd;
        SetTimer(hwnd, IDT_SPINNER_TIMER, 120, nullptr);
        RefreshProcesses(hwnd);
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_REFRESH_BTN) {
            RefreshProcesses(hwnd);
        } else if (LOWORD(wParam) == IDC_FILTER_EDIT && HIWORD(wParam) == EN_CHANGE) {
            wchar_t buf[256];
            GetWindowTextW((HWND)lParam, buf, 256);
            g_filterText = buf;
            g_scrollPos = 0;
            UpdateScrollRange(g_hListView);
            InvalidateRect(g_hListView, nullptr, TRUE);
        } else if (LOWORD(wParam) == IDC_THEMES_BTN) {
            ShowThemesMenu(hwnd);
        } else if (LOWORD(wParam) >= ID_THEME_BASE &&
                   LOWORD(wParam) < ID_THEME_BASE + (int)g_themes.size()) {
            int idx = LOWORD(wParam) - ID_THEME_BASE;
            g_activeThemeName = g_themes[idx].name;

            wchar_t btnText[64];
            swprintf(btnText, 64, L"Themes: %ls", g_themes[idx].name.c_str());
            SetWindowTextW(GetDlgItem(hwnd, IDC_THEMES_BTN), btnText);

            InvalidateRect(hwnd, nullptr, TRUE);
            InvalidateRect(g_hListView, nullptr, TRUE);
        }
        break;

    case WM_MEASUREITEM: {
        auto mis = (LPMEASUREITEMSTRUCT)lParam;
        if (mis->CtlType == ODT_MENU) {
            mis->itemWidth = 160;
            mis->itemHeight = 26;
        }
        return TRUE;
    }

    case WM_DRAWITEM: {
        auto dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_MENU) {
            int idx = (int)dis->itemID - ID_THEME_BASE;
            bool isActive = (idx >= 0 && idx < (int)g_themes.size() &&
                              g_themes[idx].name == g_activeThemeName);

            COLORREF bg = isActive ? RGB(210, 225, 245) : RGB(255, 255, 255);
            {
                ScopedBrush brush(bg);
                FillRect(dis->hDC, &dis->rcItem, brush);
            }

            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, RGB(20, 20, 20));

            RECT textRc = dis->rcItem;
            textRc.left += 10;

            std::wstring name = (idx >= 0 && idx < (int)g_themes.size())
                                 ? g_themes[idx].name : L"?";
            DrawTextW(dis->hDC, name.c_str(), -1, &textRc,
                      DT_SINGLELINE | DT_VCENTER);
        }
        return TRUE;
    }

        case WM_TIMER:
        if (wParam == IDT_SPINNER_TIMER) {

            wchar_t base[MARQUEE_WIDTH + 1];
            swprintf(base, MARQUEE_WIDTH + 1, L"%-*ls", MARQUEE_WIDTH, L"keyloggerDetector by g0nchy");

            g_marqueeOffset = (g_marqueeOffset + 1) % MARQUEE_WIDTH;
            wchar_t marquee[MARQUEE_WIDTH + 1];
            for (int i = 0; i < g_marqueeOffset; i++)
                marquee[i] = base[MARQUEE_WIDTH - g_marqueeOffset + i];
            for (int i = 0; i < MARQUEE_WIDTH - g_marqueeOffset; i++)
                marquee[g_marqueeOffset + i] = base[i];
            marquee[MARQUEE_WIDTH] = L'\0';

            // Left block
            wchar_t leftPart[48];
            swprintf(leftPart, 48, L"%u processes", g_lastScan.processCount);

            // Center block
            wchar_t centerPart[220];
            if (g_isRefreshing) {
                swprintf(centerPart, 220, L"%ls %ls scanning... %ls",
                    DECOR_LEFT, marquee, DECOR_RIGHT);
            } else {
                swprintf(centerPart, 220, L"%ls %ls %ls",
                    DECOR_LEFT, marquee, DECOR_RIGHT);
            }

            // Right block
            wchar_t rightPart[64];
            swprintf(rightPart, 64, L"%d high | %d med | %d low | %.2fs",
                g_lastScan.high, g_lastScan.medium, g_lastScan.low, g_lastScan.elapsedSeconds);

            const wchar_t* PADDING = L"                              "; // ~30 spaces

            wchar_t title[350];
            swprintf(title, 350, L"%ls%ls     %ls     %ls", PADDING, leftPart, centerPart, rightPart);
            SetWindowTextW(hwnd, title);
        }
        break;

    case WM_REFRESH_DONE: {
        auto* newList = (std::vector<ProcessInfo>*)lParam;

        for (auto& p : g_processes) if (p.icon) DestroyIcon(p.icon);

        g_processes = std::move(*newList);
        delete newList;

        g_scrollPos = 0;
        UpdateScrollRange(g_hListView);
        InvalidateRect(g_hListView, nullptr, TRUE);

        HWND btn = GetDlgItem(hwnd, IDC_REFRESH_BTN);
        EnableWindow(btn, TRUE);
        SetWindowTextW(btn, L"Refresh");
        g_isRefreshing = false;

        int highCount = 0, mediumCount = 0, lowCount = 0;
        for (auto& p : g_processes) {
            if (p.score >= SCORE_THRESHOLD_HIGH) highCount++;
            else if (p.score >= SCORE_THRESHOLD_MEDIUM) mediumCount++;
            else lowCount++;
        }

        g_lastScan.processCount = (unsigned)g_processes.size();
        g_lastScan.high = highCount;
        g_lastScan.medium = mediumCount;
        g_lastScan.low = lowCount;
        g_lastScan.elapsedSeconds = (GetTickCount64() - g_scanStartTick) / 1000.0;

        break;
    }

    case WM_CTLCOLORBTN: {
        const Theme& theme = GetActiveTheme();
        HDC hdcBtn = (HDC)wParam;
        SetTextColor(hdcBtn, theme.textPrimary);
        SetBkColor(hdcBtn, theme.background);
        SetBkMode(hdcBtn, OPAQUE);
        return (LRESULT)GetBgBrush();
    }

    case WM_CTLCOLOREDIT: {
        const Theme& theme = GetActiveTheme();
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, theme.textPrimary);
        SetBkColor(hdcEdit, RGB(255, 255, 255));
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, GetBgBrush());
        return 1;
    }

    case WM_DESTROY:
        for (auto& p : g_processes) if (p.icon) DestroyIcon(p.icon);
        for (auto& kv : g_pathCache.map) if (kv.second.icon) DestroyIcon(kv.second.icon);
        if (g_bgBrush) DeleteObject(g_bgBrush);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    EnsureDefaultThemeFile();
    ScanThemes();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    const wchar_t CLASS_NAME[] = L"KeyloggerDetectorWnd";

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(MAINICON));

    RegisterClassW(&wc);

    WNDCLASSW listClass{};
    listClass.lpfnWndProc = ProcessListWndProc;
    listClass.hInstance = hInst;
    listClass.lpszClassName = PROCESS_LIST_CLASS;
    listClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    listClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&listClass);

    int winWidth = 940;
    int winHeight = 620;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - winWidth) / 2;
    int posY = (screenH - winHeight) / 2;

    // Without WS_THICKFRAME/WS_MAXIMIZEBOX
    HWND hwnd = CreateWindowExW(0, CLASS_NAME,
        L"keyloggerDetector",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, winWidth, winHeight,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
