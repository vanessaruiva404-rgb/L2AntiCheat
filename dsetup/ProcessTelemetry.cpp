#include "ProcessTelemetry.h"

#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wintrust.h>
#include <bcrypt.h>

#include <algorithm>
#include <cwctype>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

extern char g_CPU[128];
extern char g_HDD[128];
extern char g_MAC[128];
void BuildSecret(char* out, size_t size);

namespace
{
    const wchar_t* kTelemetryHost = L"127.0.0.1";
    const wchar_t* kTelemetryPath = L"/admin/api/hwid-report.php";
    const wchar_t* kClientVersion = L"1.2.0";
    const DWORD kReportIntervalMs = 60000;
    const DWORD kStatusIntervalMs = 5000;
    const DWORD kSessionRetryMs = 5000;
    const DWORD kNetworkRetryMs = 10000;
    const size_t kMaxProcesses = 256;
    const wchar_t* kBanWindowClass = L"L2_RP_BLOCKED_DEVICE";

    HANDLE g_TelemetryThread = NULL;
    HANDLE g_TelemetryStopEvent = NULL;
    volatile LONG g_TelemetryRunning = 0;
    RECT g_BanCloseRect = {};
    RECT g_BanButtonRect = {};
    int g_BanSecondsRemaining = 8;

    struct ProcessItem
    {
        std::wstring name;
        std::wstring displayName;
        std::wstring publisher;
        std::string sha256;
        bool signedTrusted;
        bool foreground;
        bool localSuspicious;
        unsigned int instanceCount;
    };

    struct FileMetadataCacheEntry
    {
        std::wstring path;
        FILETIME lastWriteTime;
        std::wstring displayName;
        std::wstring publisher;
        std::string sha256;
        bool signedTrusted;
        bool hashCalculated;
    };

    std::vector<FileMetadataCacheEntry> g_FileMetadataCache;

    void RemoveLegacyTelemetryFile()
    {
        wchar_t appData[32768] = { 0 };
        DWORD length = GetEnvironmentVariableW(
            L"APPDATA", appData, (DWORD)_countof(appData));
        if (length == 0 || length >= _countof(appData))
            return;

        std::wstring legacyPath =
            std::wstring(appData) + L"\\LineageII\\telemetry.ini";
        DeleteFileW(legacyPath.c_str());
    }

    std::wstring ToLower(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), towlower);
        return value;
    }

    bool HasL2SimpleBotIdentity(const std::wstring& value)
    {
        std::wstring compact;
        compact.reserve(value.size());
        for (size_t i = 0; i < value.size(); ++i)
        {
            if (iswalnum(value[i]))
                compact.push_back(static_cast<wchar_t>(towlower(value[i])));
        }
        return compact.find(L"l2simplebot") != std::wstring::npos;
    }

    void FillRectColor(HDC hdc, const RECT& rect, COLORREF color)
    {
        HBRUSH brush = CreateSolidBrush(color);
        FillRect(hdc, &rect, brush);
        DeleteObject(brush);
    }

    void DrawTextWithFont(
        HDC hdc,
        const std::wstring& text,
        RECT rect,
        int height,
        int weight,
        COLORREF color,
        UINT format)
    {
        HFONT font = CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS,
            L"Segoe UI");
        HFONT oldFont = (HFONT)SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, color);
        DrawTextW(hdc, text.c_str(), -1, &rect, format);
        SelectObject(hdc, oldFont);
        DeleteObject(font);
    }

    LRESULT CALLBACK BanWindowProc(
        HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
        {
            HRGN region = CreateRoundRectRgn(0, 0, 521, 261, 24, 24);
            SetWindowRgn(hwnd, region, TRUE);
            SetTimer(hwnd, 1, 1000, NULL);
            SetForegroundWindow(hwnd);
            return 0;
        }

        case WM_TIMER:
            if (wParam == 1)
            {
                if (g_BanSecondsRemaining > 0)
                    --g_BanSecondsRemaining;

                InvalidateRect(hwnd, &g_BanButtonRect, FALSE);
                if (g_BanSecondsRemaining <= 0)
                    DestroyWindow(hwnd);
            }
            return 0;

        case WM_LBUTTONUP:
        {
            POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (PtInRect(&g_BanCloseRect, point) ||
                PtInRect(&g_BanButtonRect, point))
            {
                DestroyWindow(hwnd);
            }
            return 0;
        }

        case WM_KEYDOWN:
            if (wParam == VK_RETURN || wParam == VK_ESCAPE)
                DestroyWindow(hwnd);
            return 0;

        case WM_NCHITTEST:
        {
            LRESULT hit = DefWindowProcW(hwnd, message, wParam, lParam);
            if (hit == HTCLIENT)
            {
                POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                ScreenToClient(hwnd, &point);
                if (point.y < 64 &&
                    !PtInRect(&g_BanCloseRect, point))
                {
                    return HTCAPTION;
                }
            }
            return hit;
        }

        case WM_PAINT:
        {
            PAINTSTRUCT paint = {};
            HDC hdc = BeginPaint(hwnd, &paint);
            RECT client = {};
            GetClientRect(hwnd, &client);

            FillRectColor(hdc, client, RGB(15, 14, 19));

            HPEN border = CreatePen(PS_SOLID, 1, RGB(136, 61, 18));
            HGDIOBJ oldPen = SelectObject(hdc, border);
            HGDIOBJ oldBrush = SelectObject(
                hdc, GetStockObject(NULL_BRUSH));
            RoundRect(
                hdc,
                client.left,
                client.top,
                client.right - 1,
                client.bottom - 1,
                24,
                24);
            SelectObject(hdc, oldBrush);
            SelectObject(hdc, oldPen);
            DeleteObject(border);

            g_BanCloseRect = { 466, 20, 500, 54 };
            FillRectColor(hdc, g_BanCloseRect, RGB(23, 22, 29));
            DrawTextWithFont(
                hdc,
                L"x",
                g_BanCloseRect,
                16,
                FW_BOLD,
                RGB(255, 255, 255),
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT title = { 32, 24, 450, 56 };
            DrawTextWithFont(
                hdc,
                L"Dispositivo bloqueado",
                title,
                24,
                FW_BOLD,
                RGB(255, 255, 255),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            RECT description = { 32, 68, 488, 119 };
            DrawTextWithFont(
                hdc,
                L"Este dispositivo foi bloqueado pela administra\u00e7\u00e3o do servidor.\n"
                L"O acesso ao jogo n\u00e3o ser\u00e1 permitido.",
                description,
                16,
                FW_NORMAL,
                RGB(224, 215, 207),
                DT_LEFT | DT_TOP | DT_WORDBREAK);

            g_BanButtonRect = { 32, 137, 488, 184 };
            FillRectColor(hdc, g_BanButtonRect, RGB(255, 84, 26));

            RECT buttonText = g_BanButtonRect;
            const std::wstring buttonLabel =
                L"Fechar jogo (" +
                std::to_wstring(g_BanSecondsRemaining) +
                L")";
            DrawTextWithFont(
                hdc,
                buttonLabel,
                buttonText,
                16,
                FW_BOLD,
                RGB(255, 255, 255),
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT footer = { 32, 204, 488, 232 };
            DrawTextWithFont(
                hdc,
                L"Se acredita que houve um engano, entre em contato com o suporte.",
                footer,
                14,
                FW_NORMAL,
                RGB(189, 178, 169),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            EndPaint(hwnd, &paint);
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    void ShowBlockedDeviceWindow()
    {
        HINSTANCE instance = GetModuleHandleW(NULL);
        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = BanWindowProc;
        windowClass.hInstance = instance;
        windowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
        windowClass.lpszClassName = kBanWindowClass;
        RegisterClassExW(&windowClass);

        const int width = 520;
        const int height = 260;
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        const int x =
            workArea.left + ((workArea.right - workArea.left - width) / 2);
        const int y =
            workArea.top + ((workArea.bottom - workArea.top - height) / 2);

        g_BanSecondsRemaining = 8;
        HWND window = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            kBanWindowClass,
            L"L2 Protection",
            WS_POPUP,
            x,
            y,
            width,
            height,
            NULL,
            NULL,
            instance,
            NULL);
        if (!window)
            return;

        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
        SetForegroundWindow(window);
        SetFocus(window);

        MSG message = {};
        while (GetMessageW(&message, NULL, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return std::string();

        int size = WideCharToMultiByte(
            CP_UTF8, 0, value.c_str(), (int)value.size(), NULL, 0, NULL, NULL);
        if (size <= 0)
            return std::string();

        std::string result((size_t)size, '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, value.c_str(), (int)value.size(), &result[0], size, NULL, NULL);
        return result;
    }

    std::string JsonEscape(const std::string& value)
    {
        std::ostringstream out;
        for (size_t i = 0; i < value.size(); ++i)
        {
            const unsigned char ch = (unsigned char)value[i];
            switch (ch)
            {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20)
                {
                    char escaped[7] = { 0 };
                    sprintf_s(escaped, sizeof(escaped), "\\u%04x", ch);
                    out << escaped;
                }
                else
                {
                    out << (char)ch;
                }
                break;
            }
        }
        return out.str();
    }

    std::wstring GetProcessPath(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return std::wstring();

        wchar_t path[32768] = { 0 };
        DWORD size = (DWORD)_countof(path);
        const bool ok = QueryFullProcessImageNameW(process, 0, path, &size) == TRUE;
        CloseHandle(process);
        return ok ? std::wstring(path, size) : std::wstring();
    }

    std::wstring QueryVersionString(
        const std::vector<BYTE>& versionData,
        WORD language,
        WORD codePage,
        const wchar_t* field)
    {
        wchar_t query[96] = { 0 };
        swprintf_s(
            query,
            _countof(query),
            L"\\StringFileInfo\\%04x%04x\\%s",
            language,
            codePage,
            field);

        LPVOID value = NULL;
        UINT valueLength = 0;
        if (!VerQueryValueW(
            (LPVOID)&versionData[0], query, &value, &valueLength) ||
            !value || valueLength == 0)
        {
            return std::wstring();
        }

        return std::wstring((const wchar_t*)value);
    }

    void ReadVersionMetadata(
        const std::wstring& path,
        std::wstring& displayName,
        std::wstring& publisher)
    {
        displayName.clear();
        publisher.clear();

        DWORD ignored = 0;
        DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
        if (size == 0)
            return;

        std::vector<BYTE> data(size);
        if (!GetFileVersionInfoW(path.c_str(), 0, size, &data[0]))
            return;

        struct Translation
        {
            WORD language;
            WORD codePage;
        };

        Translation* translations = NULL;
        UINT translationBytes = 0;
        WORD language = 0x0409;
        WORD codePage = 0x04b0;

        if (VerQueryValueW(
            &data[0],
            L"\\VarFileInfo\\Translation",
            (LPVOID*)&translations,
            &translationBytes) &&
            translations &&
            translationBytes >= sizeof(Translation))
        {
            language = translations[0].language;
            codePage = translations[0].codePage;
        }

        displayName = QueryVersionString(data, language, codePage, L"FileDescription");
        publisher = QueryVersionString(data, language, codePage, L"CompanyName");
    }

    bool IsSignedFileTrusted(const std::wstring& path)
    {
        if (path.empty())
            return false;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();

        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(NULL, &policy, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policy, &trustData);
        return status == ERROR_SUCCESS;
    }

    std::string BytesToHex(const BYTE* bytes, size_t size)
    {
        static const char digits[] = "0123456789abcdef";
        std::string result(size * 2, '0');
        for (size_t i = 0; i < size; ++i)
        {
            result[i * 2] = digits[(bytes[i] >> 4) & 0x0f];
            result[i * 2 + 1] = digits[bytes[i] & 0x0f];
        }
        return result;
    }

    std::string Sha256File(const std::wstring& path)
    {
        HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);
        if (file == INVALID_HANDLE_VALUE)
            return std::string();

        BCRYPT_ALG_HANDLE algorithm = NULL;
        BCRYPT_HASH_HANDLE hash = NULL;
        DWORD objectSize = 0;
        DWORD resultSize = 0;
        std::vector<BYTE> hashObject;
        BYTE digest[32] = { 0 };
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&objectSize,
                sizeof(objectSize),
                &resultSize,
                0) == 0)
        {
            hashObject.resize(objectSize);
            if (BCryptCreateHash(
                algorithm, &hash, &hashObject[0], objectSize, NULL, 0, 0) == 0)
            {
                BYTE buffer[64 * 1024];
                DWORD bytesRead = 0;
                ok = true;

                for (;;)
                {
                    if (!ReadFile(file, buffer, sizeof(buffer), &bytesRead, NULL))
                    {
                        ok = false;
                        break;
                    }
                    if (bytesRead == 0)
                        break;

                    if (BCryptHashData(hash, buffer, bytesRead, 0) != 0)
                    {
                        ok = false;
                        break;
                    }
                }

                if (ok && BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0)
                    ok = false;
            }
        }

        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
        CloseHandle(file);

        return ok ? BytesToHex(digest, sizeof(digest)) : std::string();
    }

    bool SameFileTime(const FILETIME& left, const FILETIME& right)
    {
        return left.dwLowDateTime == right.dwLowDateTime &&
            left.dwHighDateTime == right.dwHighDateTime;
    }

    void ReadCachedFileMetadata(
        const std::wstring& path,
        bool requireHash,
        ProcessItem& item)
    {
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        GetFileAttributesExW(
            path.c_str(), GetFileExInfoStandard, &attributes);

        const std::wstring normalizedPath = ToLower(path);
        for (size_t i = 0; i < g_FileMetadataCache.size(); ++i)
        {
            FileMetadataCacheEntry& cached = g_FileMetadataCache[i];
            if (ToLower(cached.path) != normalizedPath ||
                !SameFileTime(cached.lastWriteTime, attributes.ftLastWriteTime))
            {
                continue;
            }

            if (requireHash && !cached.hashCalculated)
            {
                cached.sha256 = Sha256File(path);
                cached.hashCalculated = true;
            }

            item.displayName = cached.displayName;
            item.publisher = cached.publisher;
            item.sha256 = cached.sha256;
            item.signedTrusted = cached.signedTrusted;
            return;
        }

        FileMetadataCacheEntry cached = {};
        cached.path = path;
        cached.lastWriteTime = attributes.ftLastWriteTime;
        ReadVersionMetadata(path, cached.displayName, cached.publisher);
        cached.signedTrusted = IsSignedFileTrusted(path);

        const bool trustedMicrosoft =
            cached.signedTrusted &&
            ToLower(cached.publisher).find(L"microsoft") != std::wstring::npos;
        cached.hashCalculated = requireHash || !trustedMicrosoft;
        if (cached.hashCalculated)
            cached.sha256 = Sha256File(path);

        if (g_FileMetadataCache.size() >= 512)
            g_FileMetadataCache.erase(g_FileMetadataCache.begin());
        g_FileMetadataCache.push_back(cached);

        item.displayName = cached.displayName;
        item.publisher = cached.publisher;
        item.sha256 = cached.sha256;
        item.signedTrusted = cached.signedTrusted;
    }

    bool IsLocallySuspicious(const std::wstring& processName)
    {
        static const wchar_t* keywords[] =
        {
            L"cheatengine", L"cheat engine", L"l2phx", L"l2walker",
            L"l2tower", L"l2 simple bot", L"l2simplebot", L"l2-simple-bot",
            L"l2_simple_bot", L"adrenaline", L"adrenalin", L"x64dbg",
            L"x32dbg", L"ollydbg", L"processhacker", L"process hacker",
            L"httpdebugger", L"packet editor", L"memory viewer", L"trainer"
        };

        if (HasL2SimpleBotIdentity(processName))
            return true;

        const std::wstring lower = ToLower(processName);
        for (size_t i = 0; i < _countof(keywords); ++i)
        {
            if (lower.find(keywords[i]) != std::wstring::npos)
                return true;
        }
        return false;
    }

    void AddOrMergeProcess(std::vector<ProcessItem>& items, const ProcessItem& item)
    {
        const std::wstring key = ToLower(item.name);
        for (size_t i = 0; i < items.size(); ++i)
        {
            if (ToLower(items[i].name) == key)
            {
                items[i].instanceCount++;
                items[i].foreground = items[i].foreground || item.foreground;
                items[i].localSuspicious =
                    items[i].localSuspicious || item.localSuspicious;
                if (items[i].displayName.empty() && !item.displayName.empty())
                    items[i].displayName = item.displayName;
                if (items[i].publisher.empty() && !item.publisher.empty())
                    items[i].publisher = item.publisher;
                if (items[i].sha256.empty() && !item.sha256.empty())
                    items[i].sha256 = item.sha256;
                items[i].signedTrusted =
                    items[i].signedTrusted || item.signedTrusted;
                return;
            }
        }

        items.push_back(item);
    }

    std::vector<ProcessItem> CollectProcesses()
    {
        std::vector<ProcessItem> result;
        HWND foregroundWindow = GetForegroundWindow();
        DWORD foregroundPid = 0;
        if (foregroundWindow)
            GetWindowThreadProcessId(foregroundWindow, &foregroundPid);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return result;

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (entry.th32ProcessID == 0 || result.size() >= kMaxProcesses)
                    continue;

                ProcessItem item = {};
                item.name = entry.szExeFile;
                item.foreground = entry.th32ProcessID == foregroundPid;
                item.localSuspicious = IsLocallySuspicious(item.name);
                item.instanceCount = 1;

                const std::wstring path = GetProcessPath(entry.th32ProcessID);
                if (!path.empty())
                {
                    ReadCachedFileMetadata(path, item.localSuspicious, item);
                    item.localSuspicious =
                        item.localSuspicious ||
                        IsLocallySuspicious(item.displayName);
                }

                AddOrMergeProcess(result, item);
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        std::sort(
            result.begin(),
            result.end(),
            [](const ProcessItem& left, const ProcessItem& right)
            {
                if (left.foreground != right.foreground)
                    return left.foreground > right.foreground;
                if (left.localSuspicious != right.localSuspicious)
                    return left.localSuspicious > right.localSuspicious;
                return ToLower(left.name) < ToLower(right.name);
            });

        return result;
    }

    std::string BuildPayload(
        const std::vector<ProcessItem>& processes,
        bool statusOnly)
    {
        std::ostringstream json;
        json << "{";
        json << "\"client_version\":\"" << WideToUtf8(kClientVersion) << "\",";
        json << "\"cpu\":\"" << JsonEscape(g_CPU) << "\",";
        json << "\"hdd\":\"" << JsonEscape(g_HDD) << "\",";
        json << "\"mac\":\"" << JsonEscape(g_MAC) << "\",";
        json << "\"status_only\":" << (statusOnly ? "true" : "false") << ",";
        json << "\"process_consent\":true,";
        json << "\"processes\":[";

        for (size_t i = 0; i < processes.size(); ++i)
        {
            if (i > 0)
                json << ",";

            const ProcessItem& item = processes[i];
            json << "{";
            json << "\"name\":\"" << JsonEscape(WideToUtf8(item.name)) << "\",";
            json << "\"display_name\":\""
                << JsonEscape(WideToUtf8(item.displayName)) << "\",";
            json << "\"publisher\":\""
                << JsonEscape(WideToUtf8(item.publisher)) << "\",";
            json << "\"sha256\":\"" << JsonEscape(item.sha256) << "\",";
            json << "\"signed\":" << (item.signedTrusted ? "true" : "false") << ",";
            json << "\"foreground\":" << (item.foreground ? "true" : "false") << ",";
            json << "\"local_suspicious\":"
                << (item.localSuspicious ? "true" : "false") << ",";
            json << "\"instances\":" << item.instanceCount;
            json << "}";
        }

        json << "]}";
        return json.str();
    }

    std::string CreateNonce()
    {
        BYTE randomBytes[16] = { 0 };
        if (BCryptGenRandom(
            NULL,
            randomBytes,
            sizeof(randomBytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            return std::string();
        }
        return BytesToHex(randomBytes, sizeof(randomBytes));
    }

    std::string HmacSha256(
        const std::string& key,
        const std::string& message)
    {
        BCRYPT_ALG_HANDLE algorithm = NULL;
        BCRYPT_HASH_HANDLE hash = NULL;
        DWORD objectSize = 0;
        DWORD resultSize = 0;
        std::vector<BYTE> hashObject;
        BYTE digest[32] = { 0 };
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0 &&
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&objectSize,
                sizeof(objectSize),
                &resultSize,
                0) == 0)
        {
            hashObject.resize(objectSize);
            if (BCryptCreateHash(
                algorithm,
                &hash,
                &hashObject[0],
                objectSize,
                (PUCHAR)key.data(),
                (ULONG)key.size(),
                0) == 0 &&
                BCryptHashData(
                    hash,
                    (PUCHAR)message.data(),
                    (ULONG)message.size(),
                    0) == 0 &&
                BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0)
            {
                ok = true;
            }
        }

        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
        return ok ? BytesToHex(digest, sizeof(digest)) : std::string();
    }

    void CloseHttpConnection(
        HINTERNET& session,
        HINTERNET& connection)
    {
        if (connection)
        {
            WinHttpCloseHandle(connection);
            connection = NULL;
        }

        if (session)
        {
            WinHttpCloseHandle(session);
            session = NULL;
        }
    }

    bool OpenHttpConnection(
        HINTERNET& session,
        HINTERNET& connection)
    {
        CloseHttpConnection(session, connection);

        session = WinHttpOpen(
            L"L2Protection/1.2",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!session)
            return false;

        WinHttpSetTimeouts(session, 5000, 5000, 8000, 8000);

        connection = WinHttpConnect(
            session,
            kTelemetryHost,
            INTERNET_DEFAULT_HTTPS_PORT,
            0);
        if (!connection)
        {
            CloseHttpConnection(session, connection);
            return false;
        }

        return true;
    }

    bool PostReport(
        HINTERNET session,
        HINTERNET connection,
        const std::string& payload,
        std::string& response,
        DWORD& statusCode)
    {
        response.clear();
        statusCode = 0;

        const std::string timestamp = std::to_string((long long)std::time(NULL));
        const std::string nonce = CreateNonce();
        if (nonce.empty())
            return false;

        char secretBuffer[128] = { 0 };
        BuildSecret(secretBuffer, sizeof(secretBuffer));
        std::string secret(secretBuffer);
        SecureZeroMemory(secretBuffer, sizeof(secretBuffer));

        const std::string signature =
            HmacSha256(secret, timestamp + "\n" + nonce + "\n" + payload);
        if (!secret.empty())
            SecureZeroMemory(&secret[0], secret.size());
        if (signature.empty())
            return false;

        if (!session || !connection)
            return false;

        HINTERNET request = WinHttpOpenRequest(
            connection,
            L"POST",
            kTelemetryPath,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!request)
            return false;

        const std::wstring headers =
            L"Content-Type: application/json; charset=utf-8\r\n"
            L"X-L2-Timestamp: " + std::wstring(timestamp.begin(), timestamp.end()) + L"\r\n"
            L"X-L2-Nonce: " + std::wstring(nonce.begin(), nonce.end()) + L"\r\n"
            L"X-L2-Signature: " + std::wstring(signature.begin(), signature.end()) + L"\r\n";

        BOOL ok = WinHttpSendRequest(
            request,
            headers.c_str(),
            (DWORD)-1L,
            (LPVOID)payload.data(),
            (DWORD)payload.size(),
            (DWORD)payload.size(),
            0);
        if (ok)
            ok = WinHttpReceiveResponse(request, NULL);

        if (ok)
        {
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &statusSize,
                WINHTTP_NO_HEADER_INDEX);

            for (;;)
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available) || available == 0)
                    break;

                std::vector<char> chunk(available);
                DWORD bytesRead = 0;
                if (!WinHttpReadData(request, &chunk[0], available, &bytesRead))
                    break;

                response.append(&chunk[0], bytesRead);
                if (response.size() > 64 * 1024)
                    break;
            }
        }

        WinHttpCloseHandle(request);
        return ok == TRUE;
    }

    void HandleBanResponse(const std::string& response)
    {
        if (response.find("\"banned\":true") == std::string::npos)
            return;

        ShowBlockedDeviceWindow();
        ExitProcess(0);
    }

    DWORD WINAPI TelemetryThreadProc(LPVOID)
    {
        HINTERNET session = NULL;
        HINTERNET connection = NULL;
        OpenHttpConnection(session, connection);

        {
            const std::vector<ProcessItem> noProcesses;
            const std::string statusPayload =
                BuildPayload(noProcesses, true);
            std::string statusResponse;
            DWORD statusCode = 0;
            if (PostReport(
                session,
                connection,
                statusPayload,
                statusResponse,
                statusCode))
            {
                HandleBanResponse(statusResponse);
            }
        }

        ULONGLONG nextInventoryTick = 0;
        while (InterlockedCompareExchange(&g_TelemetryRunning, 0, 0) == 1)
        {
            const ULONGLONG now = GetTickCount64();
            const bool inventoryDue = now >= nextInventoryTick;
            std::vector<ProcessItem> processes;
            if (inventoryDue)
                processes = CollectProcesses();

            const std::string payload =
                BuildPayload(processes, !inventoryDue);
            std::string response;
            DWORD statusCode = 0;
            if (!session || !connection)
                OpenHttpConnection(session, connection);

            const bool sent = PostReport(
                session,
                connection,
                payload,
                response,
                statusCode);
            if (sent)
                HandleBanResponse(response);
            else
                CloseHttpConnection(session, connection);

            if (inventoryDue)
            {
                if (sent && statusCode == 200)
                    nextInventoryTick = now + kReportIntervalMs;
                else
                    nextInventoryTick = now + kSessionRetryMs;
            }

            DWORD waitTime = kStatusIntervalMs;
            if (!sent)
                waitTime = kNetworkRetryMs;

            if (WaitForSingleObject(
                g_TelemetryStopEvent, waitTime) == WAIT_OBJECT_0)
            {
                break;
            }
        }

        CloseHttpConnection(session, connection);
        InterlockedExchange(&g_TelemetryRunning, 0);
        return 0;
    }
}

bool CheckBlockedDeviceBeforeStartup()
{
    RemoveLegacyTelemetryFile();

    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    if (!OpenHttpConnection(session, connection))
        return false;

    const std::vector<ProcessItem> noProcesses;
    const std::string payload = BuildPayload(noProcesses, true);
    std::string response;
    DWORD statusCode = 0;
    const bool sent = PostReport(
        session,
        connection,
        payload,
        response,
        statusCode);

    CloseHttpConnection(session, connection);

    if (!sent || response.find("\"banned\":true") == std::string::npos)
        return false;

    ShowBlockedDeviceWindow();
    return true;
}

void StartProcessTelemetry()
{
    if (InterlockedCompareExchange(&g_TelemetryRunning, 1, 0) != 0)
        return;

    RemoveLegacyTelemetryFile();

    g_TelemetryStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_TelemetryStopEvent)
    {
        InterlockedExchange(&g_TelemetryRunning, 0);
        return;
    }

    g_TelemetryThread =
        CreateThread(NULL, 0, TelemetryThreadProc, NULL, 0, NULL);
    if (!g_TelemetryThread)
    {
        CloseHandle(g_TelemetryStopEvent);
        g_TelemetryStopEvent = NULL;
        InterlockedExchange(&g_TelemetryRunning, 0);
    }
}

void StopProcessTelemetry()
{
    if (InterlockedExchange(&g_TelemetryRunning, 0) == 0)
        return;

    if (g_TelemetryStopEvent)
        SetEvent(g_TelemetryStopEvent);

    if (g_TelemetryThread)
    {
        WaitForSingleObject(g_TelemetryThread, 10000);
        CloseHandle(g_TelemetryThread);
        g_TelemetryThread = NULL;
    }

    if (g_TelemetryStopEvent)
    {
        CloseHandle(g_TelemetryStopEvent);
        g_TelemetryStopEvent = NULL;
    }
}
