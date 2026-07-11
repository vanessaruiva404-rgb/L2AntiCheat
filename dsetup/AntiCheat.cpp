// ============================================================
// AntiCheat_Pro.cpp - BAN-L2JNEXORA / L2JDEV
// Defensive client-side protection for L2J Interlude dsetup
// ============================================================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <shlobj.h>
#include <winver.h>

#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <cstdio>

#include "AntiCheat.h"
#include "NotificationIcon.h"
#include "FileProtection.h"
#include "ProtectionState.h"
#include "ProtectionUI.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

static HANDLE g_hStopEvent = NULL;
static volatile LONG g_IsRunning = 0;
static volatile LONG g_DetectionTriggered = 0;
static volatile LONG g_IsShuttingDown = 0;
static HINSTANCE g_hInstance = NULL;

// Input protection runs on its own message-pump thread. Low-level hooks can be
// silently removed by Windows when their owner thread is busy for too long, so
// they must not share the process/module/file scanning thread.
static HANDLE g_hInputMonitorThread = NULL;
static HANDLE g_hInputMonitorStopEvent = NULL;
static volatile LONG g_InputMonitorStarted = 0;
static HHOOK g_hLowLevelKeyboardHook = NULL;
static HHOOK g_hLowLevelMouseHook = NULL;

// 0 = empty, 2 = writer owns the buffer, 1 = ready for the anti-cheat thread.
static volatile LONG g_InputDetectionPending = 0;
static wchar_t g_InputDetectionReason[256] = { 0 };
static volatile LONG g_LastForegroundTick = 0;
static volatile LONG g_LastLowLevelKeyTick[256] = { 0 };
static volatile LONG g_LastLowLevelMouseTick = 0;
static volatile LONG g_SyntheticMessageCount = 0;
static volatile LONG g_SyntheticMessageWindowTick = 0;
static volatile LONG g_BackgroundKeyboardCount = 0;
static volatile LONG g_BackgroundKeyboardWindowTick = 0;
static volatile LONG g_BackgroundMouseCount = 0;
static volatile LONG g_BackgroundMouseWindowTick = 0;
static volatile LONG g_InjectedKeyboardCount = 0;
static volatile LONG g_InjectedKeyboardWindowTick = 0;
static volatile LONG g_InjectedMouseCount = 0;
static volatile LONG g_InjectedMouseWindowTick = 0;
static volatile LONG g_LastCountedKeySignalTick[256] = { 0 };
static volatile LONG g_LastCountedMouseSignalTick = 0;

struct ThreadInputHooks
{
    DWORD threadId;
    HHOOK getMessageHook;
    HHOOK callWndProcHook;
};

static std::vector<ThreadInputHooks> g_ThreadInputHooks;

static const wchar_t* g_BlockedProcessNames[] =
{
    L"l2phx.exe", L"l2walker.exe", L"l2tower.exe", L"l2 simple bot.exe",
    L"l2simplebot.exe", L"l2-simple-bot.exe", L"l2_simple_bot.exe",
    L"boot.exe", L"cheatengine.exe", L"cheat engine.exe", L"ollydbg.exe",
    L"x64dbg.exe", L"x32dbg.exe", L"processhacker.exe", L"process hacker.exe",
    L"httpdebuggerui.exe", L"wireshark.exe", L"fiddler.exe", L"petools.exe",
    L"adrenalin.exe", L"adrenaline.exe", L"update.exe", L"autoupdater.exe"
};

static const wchar_t* g_BlockedKeywords[] =
{
    L"l2phx", L"l2 walker", L"l2walker", L"l2tower", L"l2 simple bot",
    L"l2simplebot", L"l2-simple-bot", L"l2_simple_bot", L"cheat engine",
    L"ollydbg", L"x64dbg", L"x32dbg", L"process hacker", L"http debugger",
    L"packet editor", L"memory viewer", L"adrenalin", L"adrenaline",
    L"adrenalinebot", L"vanquard", L"autoupdater", L"trainer"
};

static const wchar_t* g_AllowedGameModules[] =
{
    L"dsetup.dll", L"engine.dll", L"core.dll", L"l2.exe", L"window.dll", L"l2ui.dll",
    L"libiconv-2.dll", L"lineageenv.dll", L"nophx.dll", L"vmfx.dll", L"vorbis.dll",
    L"ogg.dll", L"fire.dll", L"openal32.dll", L"orc.dll", L"npkcrypt.dll", L"npkscrypt.dll",
    L"vorbisfile.dll", L"ifc23.dll", L"windrv.dll", L"d3ddrv.dll", L"encvag.dll",
    L"entry.dll", L"ipdrv.dll", L"msxml4.dll", L"msxml4a.dll", L"msxml4r.dll",
    L"nosleep.dll", L"npkpdb.dll", L"wrap_oal.dll", L"nwindow.dll", L"alaudio.dll",
    L"defopenal32.dll", L"l2voice.dll", L"detoured.dll",
    L"d3d8.dll", L"ddraw.dll", L"d3dimm.dll", // Graphics wrappers (dgVoodoo2 / d3d8to9)

    // Optional overlays/capture modules. Remove what you don't want to allow.
    L"game_detour_32.dll", L"graphics-hook32.dll", L"graphics-hook64.dll",
    L"discordhook.dll", L"nvspcap.dll", L"nvscpapi.dll", L"gameoverlayrenderer.dll",
    L"gameoverlayrenderer64.dll", L"rtsshooks.dll",
    L"nvd3d9wrap.dll", L"nvd3d9wrapx.dll", L"nvinit.dll", L"nvinitx.dll", L"nvdxgiwrap.dll",

     L"L2CraftClub.dll", L"EmuDev.dll",
      L"discord_game_sdk.dll", L"authlogin746.dll", L"abstractex.dll",
      L"msvcp140d.dll", L"vcruntime140d.dll", L"ucrtbased.dll",
      L"bdcam32.dll", L"wslbscr32.dll", L"owexplorer.dll"

};

static const wchar_t* g_HijackSensitiveSystemDlls[] =
{
    L"iphlpapi.dll", L"comdlg32.dll", L"winmm.dll", L"version.dll", L"ws2_32.dll",
    L"crypt32.dll", L"dnsapi.dll", L"user32.dll", L"kernel32.dll", L"advapi32.dll"
};

static const wchar_t* g_BlockedDriverKeywords[] =
{
    L"dbk32", L"dbk64", L"cedriver", L"cheat", L"kernelhook", L"dbvm"
};

// Input signals are intentionally scored instead of punished immediately.
// Action-bar/target keys are common in normal farming/harvest routines, so
// they need more tolerance than movement, mouse, or direct background control.
static const DWORD kBackgroundFocusGraceMs = 2500;
static const DWORD kLowLevelCorrelationGraceMs = 1200;
static const DWORD kRepeatedKeySignalQuietMs = 120;
static const DWORD kRepeatedMouseSignalQuietMs = 120;

static const DWORD kBackgroundInputWindowMs = 10000;
static const LONG kBackgroundRoutineKeyThreshold = 10;
static const LONG kBackgroundControlKeyThreshold = 4;
static const LONG kBackgroundMouseThreshold = 4;

static const DWORD kSyntheticMessageWindowMs = 6000;
static const LONG kSyntheticRoutineKeyThreshold = 14;
static const LONG kSyntheticControlKeyThreshold = 5;
static const LONG kSyntheticMouseThreshold = 5;

static const DWORD kInjectedKeyboardWindowMs = 15000;
static const LONG kInjectedRoutineKeyThreshold = 45;
static const LONG kInjectedControlKeyThreshold = 10;
static const DWORD kInjectedMouseWindowMs = 6000;
static const LONG kInjectedMouseThreshold = 8;

void AntiCheatSetModuleHandle(HINSTANCE hInst)
{
    g_hInstance = hInst;
}

static std::wstring ToLowerW(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), towlower);
    return s;
}

static bool ContainsInsensitive(const std::wstring& source, const std::wstring& keyword)
{
    if (source.empty() || keyword.empty())
        return false;

    return ToLowerW(source).find(ToLowerW(keyword)) != std::wstring::npos;
}

static bool EqualsAnyInsensitive(const std::wstring& text, const wchar_t* const* values, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (_wcsicmp(text.c_str(), values[i]) == 0)
            return true;
    }
    return false;
}

static bool ContainsAnyInsensitive(const std::wstring& text, const wchar_t* const* values, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (ContainsInsensitive(text, values[i]))
            return true;
    }
    return false;
}

static bool HasL2SimpleBotIdentity(const std::wstring& text);

static std::wstring NormalizePath(const std::wstring& path)
{
    if (path.empty())
        return L"";

    wchar_t full[MAX_PATH] = { 0 };
    if (GetFullPathNameW(path.c_str(), MAX_PATH, full, NULL) == 0)
        return ToLowerW(path);

    return ToLowerW(full);
}

static bool StartsWithInsensitive(const std::wstring& value, const std::wstring& prefix)
{
    std::wstring a = ToLowerW(value);
    std::wstring b = ToLowerW(prefix);
    return a.size() >= b.size() && a.compare(0, b.size(), b) == 0;
}

static bool IsInDirectory(const std::wstring& filePath, const std::wstring& dirPath)
{
    if (filePath.empty() || dirPath.empty())
        return false;

    std::wstring normFile = NormalizePath(filePath);
    std::wstring normDir = NormalizePath(dirPath);

    if (!normDir.empty() && normDir.back() != L'\\')
        normDir += L'\\';

    return StartsWithInsensitive(normFile, normDir);
}

static std::wstring GetFileNameOnly(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
}

static std::wstring GetDirectoryOnly(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"" : path.substr(0, pos);
}

static std::wstring GetCurrentExePath()
{
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return path;
}

static std::wstring GetAppDataDir()
{
    wchar_t path[MAX_PATH] = { 0 };

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path)))
        return L".";

    std::wstring dir = std::wstring(path) + L"\\LineageII";
    CreateDirectoryW(dir.c_str(), NULL);
    return dir;
}

static void LogAntiCheat(const std::wstring& message)
{
    std::wstring file = GetAppDataDir() + L"\\anticheat.log";
    FILE* fp = NULL;
    _wfopen_s(&fp, file.c_str(), L"a+, ccs=UTF-8");
    if (!fp)
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fwprintf(fp, L"[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, message.c_str());
    fclose(fp);
}

static std::wstring GetProcessImagePath(DWORD pid)
{
    std::wstring result;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
        return L"";

    wchar_t path[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, path, &size))
        result = path;
    else if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH))
        result = path;

    CloseHandle(hProcess);
    return result;
}

static bool ReadVersionValue(
    const std::vector<BYTE>& versionData,
    WORD language,
    WORD codePage,
    const wchar_t* name,
    std::wstring& value)
{
    wchar_t query[128] = { 0 };
    swprintf_s(
        query,
        L"\\StringFileInfo\\%04x%04x\\%s",
        language,
        codePage,
        name);

    LPVOID text = NULL;
    UINT textLength = 0;
    if (!VerQueryValueW(
            const_cast<BYTE*>(&versionData[0]),
            query,
            &text,
            &textLength) ||
        !text || textLength <= 1)
    {
        return false;
    }

    value.assign(static_cast<const wchar_t*>(text), textLength - 1);
    return !value.empty();
}

static bool HasBlockedVersionIdentity(const std::wstring& filePath, std::wstring& identity)
{
    identity.clear();

    DWORD ignored = 0;
    const DWORD dataSize = GetFileVersionInfoSizeW(filePath.c_str(), &ignored);
    if (dataSize == 0)
        return false;

    std::vector<BYTE> data(dataSize);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, dataSize, &data[0]))
        return false;

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
            reinterpret_cast<LPVOID*>(&translations),
            &translationBytes) &&
        translations && translationBytes >= sizeof(Translation))
    {
        language = translations[0].language;
        codePage = translations[0].codePage;
    }

    static const wchar_t* fields[] =
    {
        L"OriginalFilename", L"InternalName", L"FileDescription", L"ProductName"
    };

    for (size_t i = 0; i < _countof(fields); ++i)
    {
        std::wstring value;
        if (ReadVersionValue(data, language, codePage, fields[i], value) &&
            (HasL2SimpleBotIdentity(value) ||
             ContainsAnyInsensitive(value, g_BlockedKeywords, _countof(g_BlockedKeywords))))
        {
            identity = std::wstring(fields[i]) + L": " + value;
            return true;
        }
    }

    return false;
}

static bool HasL2SimpleBotIdentity(const std::wstring& text)
{
    std::wstring compact;
    compact.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i)
    {
        if (iswalnum(text[i]))
            compact.push_back(static_cast<wchar_t>(towlower(text[i])));
    }

    return compact.find(L"l2simplebot") != std::wstring::npos;
}

static bool IsCurrentProcessForeground()
{
    HWND foreground = GetForegroundWindow();
    if (!foreground)
        return false;

    DWORD foregroundPid = 0;
    GetWindowThreadProcessId(foreground, &foregroundPid);
    return foregroundPid == GetCurrentProcessId();
}

static bool IsCurrentProcessWindow(HWND window)
{
    if (!window)
        return false;

    DWORD windowPid = 0;
    GetWindowThreadProcessId(window, &windowPid);
    return windowPid == GetCurrentProcessId();
}

static void ResetInputBucket(volatile LONG& windowTick, volatile LONG& count)
{
    InterlockedExchange(&windowTick, 0);
    InterlockedExchange(&count, 0);
}

static void RefreshForegroundTick()
{
    if (IsCurrentProcessForeground())
    {
        InterlockedExchange(&g_LastForegroundTick, static_cast<LONG>(GetTickCount()));
        ResetInputBucket(g_BackgroundKeyboardWindowTick, g_BackgroundKeyboardCount);
        ResetInputBucket(g_BackgroundMouseWindowTick, g_BackgroundMouseCount);
    }
}

static bool IsBackgroundPastFocusGrace()
{
    if (IsCurrentProcessForeground())
    {
        RefreshForegroundTick();
        return false;
    }

    const DWORD now = GetTickCount();
    const DWORD lastForeground = static_cast<DWORD>(
        InterlockedCompareExchange(&g_LastForegroundTick, 0, 0));
    return (now - lastForeground) >= kBackgroundFocusGraceMs;
}

static bool IsGameControlKey(DWORD virtualKey)
{
    if (virtualKey >= VK_F1 && virtualKey <= VK_F12)
        return true;

    switch (virtualKey)
    {
    case VK_TAB:
    case VK_RETURN:
    case VK_SPACE:
    case VK_LEFT:
    case VK_UP:
    case VK_RIGHT:
    case VK_DOWN:
    case VK_HOME:
    case VK_END:
    case VK_PRIOR:
    case VK_NEXT:
    case 'W':
    case 'A':
    case 'S':
    case 'D':
    case 'Q':
    case 'E':
        return true;
    default:
        return false;
    }
}

static bool IsRoutineActionBarOrTargetKey(DWORD virtualKey)
{
    return (virtualKey >= VK_F1 && virtualKey <= VK_F12) || virtualKey == VK_TAB;
}

static bool IsKeyboardDownMessage(UINT message)
{
    return message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
}

static bool IsMouseActionMessage(UINT message)
{
    switch (message)
    {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_XBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDBLCLK:
    case WM_MBUTTONDBLCLK:
    case WM_XBUTTONDBLCLK:
        return true;
    default:
        return false;
    }
}

static std::wstring GetVirtualKeyLabel(DWORD virtualKey)
{
    if (virtualKey >= VK_F1 && virtualKey <= VK_F12)
    {
        wchar_t label[8] = { 0 };
        swprintf_s(label, L"F%u", virtualKey - VK_F1 + 1);
        return label;
    }

    if (virtualKey >= 'A' && virtualKey <= 'Z')
        return std::wstring(1, static_cast<wchar_t>(virtualKey));

    switch (virtualKey)
    {
    case VK_TAB: return L"TAB/target";
    case VK_RETURN: return L"ENTER";
    case VK_SPACE: return L"SPACE";
    case VK_LEFT: return L"LEFT";
    case VK_UP: return L"UP";
    case VK_RIGHT: return L"RIGHT";
    case VK_DOWN: return L"DOWN";
    case VK_HOME: return L"HOME";
    case VK_END: return L"END";
    case VK_PRIOR: return L"PAGE UP";
    case VK_NEXT: return L"PAGE DOWN";
    default: return L"key";
    }
}

static void QueueInputDetection(const std::wstring& reason)
{
    if (InterlockedCompareExchange(&g_InputDetectionPending, 2, 0) != 0)
        return;

    wcsncpy_s(g_InputDetectionReason, reason.c_str(), _TRUNCATE);
    MemoryBarrier();
    InterlockedExchange(&g_InputDetectionPending, 1);
}

static LONG IncrementInputSignalBucket(
    volatile LONG& windowTick,
    volatile LONG& count,
    DWORD windowMs)
{
    const DWORD now = GetTickCount();
    const DWORD windowStart = static_cast<DWORD>(
        InterlockedCompareExchange(&windowTick, 0, 0));

    if (windowStart == 0 || (now - windowStart) > windowMs)
    {
        InterlockedExchange(&windowTick, static_cast<LONG>(now));
        InterlockedExchange(&count, 0);
    }

    return InterlockedIncrement(&count);
}

static void QueueRepeatedInputDetection(
    volatile LONG& windowTick,
    volatile LONG& count,
    DWORD windowMs,
    LONG threshold,
    const std::wstring& reason)
{
    if (IncrementInputSignalBucket(windowTick, count, windowMs) >= threshold)
        QueueInputDetection(reason);
}

static bool ShouldCountKeySignal(DWORD virtualKey, DWORD quietMs)
{
    if (virtualKey >= _countof(g_LastCountedKeySignalTick))
        return true;

    const DWORD now = GetTickCount();
    const DWORD last = static_cast<DWORD>(
        InterlockedCompareExchange(&g_LastCountedKeySignalTick[virtualKey], 0, 0));

    if (last != 0 && (now - last) < quietMs)
        return false;

    InterlockedExchange(
        &g_LastCountedKeySignalTick[virtualKey],
        static_cast<LONG>(now));
    return true;
}

static bool ShouldCountMouseSignal(DWORD quietMs)
{
    const DWORD now = GetTickCount();
    const DWORD last = static_cast<DWORD>(
        InterlockedCompareExchange(&g_LastCountedMouseSignalTick, 0, 0));

    if (last != 0 && (now - last) < quietMs)
        return false;

    InterlockedExchange(&g_LastCountedMouseSignalTick, static_cast<LONG>(now));
    return true;
}

static bool ConsumeInputDetection(std::wstring& reason)
{
    if (InterlockedCompareExchange(&g_InputDetectionPending, 0, 1) != 1)
        return false;

    MemoryBarrier();
    reason = g_InputDetectionReason;
    g_InputDetectionReason[0] = L'\0';
    return !reason.empty();
}

static void ResetInputHeuristics()
{
    InterlockedExchange(&g_InputDetectionPending, 0);
    g_InputDetectionReason[0] = L'\0';
    InterlockedExchange(&g_LastForegroundTick, static_cast<LONG>(GetTickCount()));
    InterlockedExchange(&g_LastLowLevelMouseTick, 0);
    InterlockedExchange(&g_LastCountedMouseSignalTick, 0);

    for (size_t i = 0; i < _countof(g_LastLowLevelKeyTick); ++i)
    {
        InterlockedExchange(&g_LastLowLevelKeyTick[i], 0);
        InterlockedExchange(&g_LastCountedKeySignalTick[i], 0);
    }

    ResetInputBucket(g_SyntheticMessageWindowTick, g_SyntheticMessageCount);
    ResetInputBucket(g_BackgroundKeyboardWindowTick, g_BackgroundKeyboardCount);
    ResetInputBucket(g_BackgroundMouseWindowTick, g_BackgroundMouseCount);
    ResetInputBucket(g_InjectedKeyboardWindowTick, g_InjectedKeyboardCount);
    ResetInputBucket(g_InjectedMouseWindowTick, g_InjectedMouseCount);
}

static bool HasRecentLowLevelKey(DWORD virtualKey)
{
    if (virtualKey >= _countof(g_LastLowLevelKeyTick))
        return false;

    const DWORD last = static_cast<DWORD>(
        InterlockedCompareExchange(&g_LastLowLevelKeyTick[virtualKey], 0, 0));
    return (GetTickCount() - last) <= kLowLevelCorrelationGraceMs;
}

static bool HasRecentLowLevelMouse()
{
    const DWORD last = static_cast<DWORD>(
        InterlockedCompareExchange(&g_LastLowLevelMouseTick, 0, 0));
    return (GetTickCount() - last) <= kLowLevelCorrelationGraceMs;
}

static void InspectInputWindowMessage(HWND window, UINT message, WPARAM wParam)
{
    // A NULL HWND is a PostThreadMessage delivered to one of the game's
    // window-owning threads (these hooks are never installed system-wide).
    if (window && !IsCurrentProcessWindow(window))
        return;

    const bool keyAction =
        IsKeyboardDownMessage(message) && IsGameControlKey(static_cast<DWORD>(wParam));
    const bool mouseAction = IsMouseActionMessage(message);
    if (!keyAction && !mouseAction)
        return;

    if (IsBackgroundPastFocusGrace())
    {
        if (keyAction)
        {
            const DWORD virtualKey = static_cast<DWORD>(wParam);
            if (ShouldCountKeySignal(virtualKey, kRepeatedKeySignalQuietMs))
            {
                QueueRepeatedInputDetection(
                    g_BackgroundKeyboardWindowTick,
                    g_BackgroundKeyboardCount,
                    kBackgroundInputWindowMs,
                    IsRoutineActionBarOrTargetKey(virtualKey)
                        ? kBackgroundRoutineKeyThreshold
                        : kBackgroundControlKeyThreshold,
                    L"Repeated background keyboard control directed to the game: " +
                    GetVirtualKeyLabel(virtualKey));
            }
        }
        else
        {
            if (ShouldCountMouseSignal(kRepeatedMouseSignalQuietMs))
            {
                QueueRepeatedInputDetection(
                    g_BackgroundMouseWindowTick,
                    g_BackgroundMouseCount,
                    kBackgroundInputWindowMs,
                    kBackgroundMouseThreshold,
                    L"Repeated background mouse control directed to the game");
            }
        }
        return;
    }

    // Posted/sent messages do not pass through the low-level input path.
    // Count repeated uncorrelated actions so normal skill/target bursts do not
    // get punished by one delayed or stale window message.
    if (IsCurrentProcessForeground())
    {
        const bool correlated = keyAction
            ? HasRecentLowLevelKey(static_cast<DWORD>(wParam))
            : HasRecentLowLevelMouse();

        if (!correlated)
        {
            if (keyAction)
            {
                const DWORD virtualKey = static_cast<DWORD>(wParam);
                if (ShouldCountKeySignal(virtualKey, kRepeatedKeySignalQuietMs))
                {
                    QueueRepeatedInputDetection(
                        g_SyntheticMessageWindowTick,
                        g_SyntheticMessageCount,
                        kSyntheticMessageWindowMs,
                        IsRoutineActionBarOrTargetKey(virtualKey)
                            ? kSyntheticRoutineKeyThreshold
                            : kSyntheticControlKeyThreshold,
                        L"Repeated synthetic keyboard messages directed to the game: " +
                        GetVirtualKeyLabel(virtualKey));
                }
            }
            else if (ShouldCountMouseSignal(kRepeatedMouseSignalQuietMs))
            {
                QueueRepeatedInputDetection(
                    g_SyntheticMessageWindowTick,
                    g_SyntheticMessageCount,
                    kSyntheticMessageWindowMs,
                    kSyntheticMouseThreshold,
                    L"Repeated synthetic mouse messages directed to the game");
            }
        }
    }
}

static LRESULT CALLBACK LowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION &&
        (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) &&
        IsCurrentProcessForeground())
    {
        const KBDLLHOOKSTRUCT* input = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (input && input->vkCode < _countof(g_LastLowLevelKeyTick))
        {
            InterlockedExchange(
                &g_LastLowLevelKeyTick[input->vkCode],
                static_cast<LONG>(GetTickCount()));

            if ((input->flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED)) != 0 &&
                IsGameControlKey(input->vkCode))
            {
                if (ShouldCountKeySignal(input->vkCode, kRepeatedKeySignalQuietMs))
                {
                    QueueRepeatedInputDetection(
                        g_InjectedKeyboardWindowTick,
                        g_InjectedKeyboardCount,
                        kInjectedKeyboardWindowMs,
                        IsRoutineActionBarOrTargetKey(input->vkCode)
                            ? kInjectedRoutineKeyThreshold
                            : kInjectedControlKeyThreshold,
                        L"Repeated injected keyboard input: " +
                        GetVirtualKeyLabel(input->vkCode));
                }
            }
        }
    }

    return CallNextHookEx(g_hLowLevelKeyboardHook, code, wParam, lParam);
}

static LRESULT CALLBACK LowLevelMouseProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && IsCurrentProcessForeground())
    {
        const bool mouseAction =
            wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN ||
            wParam == WM_MBUTTONDOWN || wParam == WM_XBUTTONDOWN;
        const MSLLHOOKSTRUCT* input = reinterpret_cast<const MSLLHOOKSTRUCT*>(lParam);

        if (mouseAction && input)
        {
            InterlockedExchange(&g_LastLowLevelMouseTick, static_cast<LONG>(GetTickCount()));
            if ((input->flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED)) != 0)
            {
                if (ShouldCountMouseSignal(kRepeatedMouseSignalQuietMs))
                {
                    QueueRepeatedInputDetection(
                        g_InjectedMouseWindowTick,
                        g_InjectedMouseCount,
                        kInjectedMouseWindowMs,
                        kInjectedMouseThreshold,
                        L"Repeated injected mouse control directed to the game");
                }
            }
        }
    }

    return CallNextHookEx(g_hLowLevelMouseHook, code, wParam, lParam);
}

static LRESULT CALLBACK GetMessageInputProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code >= 0 && wParam == PM_REMOVE)
    {
        const MSG* message = reinterpret_cast<const MSG*>(lParam);
        if (message)
            InspectInputWindowMessage(message->hwnd, message->message, message->wParam);
    }

    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK CallWndProcInputProc(int code, WPARAM wParam, LPARAM lParam)
{
    // Queued messages are already checked by WH_GETMESSAGE. Only inspect the
    // direct SendMessage family here to avoid counting the same action twice.
    if (code >= 0 && InSendMessageEx(NULL) != ISMEX_NOSEND)
    {
        const CWPSTRUCT* message = reinterpret_cast<const CWPSTRUCT*>(lParam);
        if (message)
            InspectInputWindowMessage(message->hwnd, message->message, message->wParam);
    }

    return CallNextHookEx(NULL, code, wParam, lParam);
}

struct WindowThreadEnumContext
{
    std::vector<DWORD>* threadIds;
};

static BOOL CALLBACK CollectCurrentProcessWindowThreads(HWND window, LPARAM lParam)
{
    DWORD pid = 0;
    const DWORD threadId = GetWindowThreadProcessId(window, &pid);
    if (pid != GetCurrentProcessId() || threadId == 0)
        return TRUE;

    WindowThreadEnumContext* context = reinterpret_cast<WindowThreadEnumContext*>(lParam);
    if (std::find(context->threadIds->begin(), context->threadIds->end(), threadId) ==
        context->threadIds->end())
    {
        context->threadIds->push_back(threadId);
    }

    return TRUE;
}

static bool IsThreadAlive(DWORD threadId)
{
    HANDLE thread = OpenThread(SYNCHRONIZE, FALSE, threadId);
    if (!thread)
        return false;

    const bool alive = WaitForSingleObject(thread, 0) == WAIT_TIMEOUT;
    CloseHandle(thread);
    return alive;
}

static void UnhookWindowThread(ThreadInputHooks& hooks)
{
    if (hooks.getMessageHook)
        UnhookWindowsHookEx(hooks.getMessageHook);
    if (hooks.callWndProcHook)
        UnhookWindowsHookEx(hooks.callWndProcHook);
    hooks.getMessageHook = NULL;
    hooks.callWndProcHook = NULL;
}

static void RefreshWindowThreadHooks()
{
    for (size_t i = 0; i < g_ThreadInputHooks.size();)
    {
        if (!IsThreadAlive(g_ThreadInputHooks[i].threadId))
        {
            UnhookWindowThread(g_ThreadInputHooks[i]);
            g_ThreadInputHooks.erase(g_ThreadInputHooks.begin() + i);
        }
        else
        {
            ++i;
        }
    }

    std::vector<DWORD> threadIds;
    WindowThreadEnumContext context = { &threadIds };
    EnumWindows(CollectCurrentProcessWindowThreads, reinterpret_cast<LPARAM>(&context));

    for (size_t i = 0; i < threadIds.size(); ++i)
    {
        bool alreadyHooked = false;
        for (size_t j = 0; j < g_ThreadInputHooks.size(); ++j)
        {
            if (g_ThreadInputHooks[j].threadId == threadIds[i])
            {
                alreadyHooked = true;
                break;
            }
        }

        if (alreadyHooked)
            continue;

        ThreadInputHooks hooks = {};
        hooks.threadId = threadIds[i];
        hooks.getMessageHook = SetWindowsHookExW(
            WH_GETMESSAGE,
            GetMessageInputProc,
            NULL,
            threadIds[i]);
        hooks.callWndProcHook = SetWindowsHookExW(
            WH_CALLWNDPROC,
            CallWndProcInputProc,
            NULL,
            threadIds[i]);

        if (hooks.getMessageHook && hooks.callWndProcHook)
        {
            g_ThreadInputHooks.push_back(hooks);
        }
        else
        {
            UnhookWindowThread(hooks);
        }
    }
}

static void UninstallAllInputHooks()
{
    for (size_t i = 0; i < g_ThreadInputHooks.size(); ++i)
        UnhookWindowThread(g_ThreadInputHooks[i]);
    g_ThreadInputHooks.clear();

    if (g_hLowLevelKeyboardHook)
    {
        UnhookWindowsHookEx(g_hLowLevelKeyboardHook);
        g_hLowLevelKeyboardHook = NULL;
    }
    if (g_hLowLevelMouseHook)
    {
        UnhookWindowsHookEx(g_hLowLevelMouseHook);
        g_hLowLevelMouseHook = NULL;
    }
}

static DWORD WINAPI InputMonitorThread(LPVOID)
{
    g_hLowLevelKeyboardHook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        g_hInstance,
        0);
    g_hLowLevelMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        LowLevelMouseProc,
        g_hInstance,
        0);

    if (!g_hLowLevelKeyboardHook || !g_hLowLevelMouseHook)
    {
        const DWORD error = GetLastError();
        wchar_t reason[160] = { 0 };
        swprintf_s(
            reason,
            L"Input protection hook unavailable (Win32 error %lu)",
            error);
        QueueInputDetection(reason);
    }

    ULONGLONG lastThreadRefresh = 0;
    while (g_hInputMonitorStopEvent &&
           WaitForSingleObject(g_hInputMonitorStopEvent, 0) == WAIT_TIMEOUT)
    {
        RefreshForegroundTick();

        const ULONGLONG now = GetTickCount64();
        if ((now - lastThreadRefresh) >= 1000)
        {
            RefreshWindowThreadHooks();
            lastThreadRefresh = now;
        }

        const DWORD waitResult = MsgWaitForMultipleObjects(
            1,
            &g_hInputMonitorStopEvent,
            FALSE,
            50,
            QS_ALLINPUT);
        if (waitResult == WAIT_OBJECT_0)
            break;

        MSG message;
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    UninstallAllInputHooks();
    return 0;
}

static void StartInputMonitoring()
{
    if (InterlockedCompareExchange(&g_InputMonitorStarted, 1, 0) != 0)
        return;

    g_hInputMonitorStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hInputMonitorStopEvent)
    {
        InterlockedExchange(&g_InputMonitorStarted, 0);
        LogAntiCheat(L"WARNING: input monitor stop event could not be created");
        return;
    }

    InterlockedExchange(&g_LastForegroundTick, static_cast<LONG>(GetTickCount()));
    g_hInputMonitorThread = CreateThread(NULL, 0, InputMonitorThread, NULL, 0, NULL);
    if (!g_hInputMonitorThread)
    {
        CloseHandle(g_hInputMonitorStopEvent);
        g_hInputMonitorStopEvent = NULL;
        InterlockedExchange(&g_InputMonitorStarted, 0);
        LogAntiCheat(L"WARNING: input monitor thread could not be created");
    }
}

static void StopInputMonitoring()
{
    if (InterlockedCompareExchange(&g_InputMonitorStarted, 0, 1) != 1)
        return;

    HANDLE stopEvent = g_hInputMonitorStopEvent;
    HANDLE thread = g_hInputMonitorThread;
    if (stopEvent)
        SetEvent(stopEvent);

    if (thread)
    {
        // A bounded wait also keeps process detach safe if Windows is already
        // tearing down window threads.
        WaitForSingleObject(thread, 1500);
        CloseHandle(thread);
    }

    if (stopEvent)
        CloseHandle(stopEvent);

    g_hInputMonitorThread = NULL;
    g_hInputMonitorStopEvent = NULL;
}

bool AntiCheat_IsRunning()
{
    return (InterlockedCompareExchange(&g_IsRunning, 0, 0) == 1);
}

void AntiCheat_OnStarted()
{
    NotificationIcon_SetStatus(L"Status: Active");
    NotificationIcon_Show();
}

void AntiCheat_OnStopped()
{
    NotificationIcon_SetStatus(L"Status: Stopped");
}
void KillProcessGracefully(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!hProcess)
        return;

    EnumWindows([](HWND hWnd, LPARAM lParam) -> BOOL
        {
            DWORD windowPid = 0;
            GetWindowThreadProcessId(hWnd, &windowPid);
            if (windowPid == (DWORD)lParam)
                PostMessageW(hWnd, WM_CLOSE, 0, 0);
            return TRUE;
        }, pid);

    if (WaitForSingleObject(hProcess, 1000) == WAIT_TIMEOUT)
        TerminateProcess(hProcess, 0);

    CloseHandle(hProcess);
}

void ShowDetectionMessageWithTimeout(const std::wstring& reason)
{
    ShowProtectionAlertBlocking(
        L"Amea\u00e7a bloqueada",
        L"Uma aplica\u00e7\u00e3o proibida ou altera\u00e7\u00e3o do cliente foi detectada.",
        L"Detec\u00e7\u00e3o: " + reason,
        3000);
}

static bool IsDebuggerPresentHard()
{
    if (IsDebuggerPresent())
        return true;

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return remote == TRUE;
}

static bool IsValidPeImage(HMODULE moduleBase)
{
    if (!moduleBase)
        return false;

    BYTE* base = reinterpret_cast<BYTE*>(moduleBase);

    __try
    {
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000)
            return false;
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;
        if (nt->FileHeader.NumberOfSections == 0)
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    return true;
}

static bool IsSignedFileTrusted(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    return status == ERROR_SUCCESS;
}

static bool ScanModules(std::wstring& reason)
{
    reason.clear();

    HMODULE modules[1024];
    DWORD needed = 0;
    HANDLE hProcess = GetCurrentProcess();

    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed))
        return false;

    std::wstring gameDir = GetDirectoryOnly(GetCurrentExePath());

    wchar_t systemDir[MAX_PATH] = { 0 };
    GetSystemDirectoryW(systemDir, MAX_PATH);
    wchar_t windowsDir[MAX_PATH] = { 0 };
    GetWindowsDirectoryW(windowsDir, MAX_PATH);

    int count = (int)(needed / sizeof(HMODULE));

    for (int i = 0; i < count; i++)
    {
        wchar_t fullPath[MAX_PATH] = { 0 };
        wchar_t baseName[MAX_PATH] = { 0 };

        if (!GetModuleFileNameExW(hProcess, modules[i], fullPath, MAX_PATH) ||
            !GetModuleBaseNameW(hProcess, modules[i], baseName, MAX_PATH))
        {
            reason = L"Module without path/name";
            return true;
        }

        std::wstring modPath = NormalizePath(fullPath);
        std::wstring modName = ToLowerW(baseName);

        if (!IsValidPeImage(modules[i]))
        {
            reason = L"Invalid PE header: " + modName;
            return true;
        }

        bool fromGame = IsInDirectory(modPath, gameDir);
        bool fromSystem32 =
            systemDir[0] != L'\0' &&
            IsInDirectory(modPath, systemDir);
        bool fromWindows =
            windowsDir[0] != L'\0' &&
            IsInDirectory(modPath, windowsDir);

        if (EqualsAnyInsensitive(modName, g_HijackSensitiveSystemDlls, _countof(g_HijackSensitiveSystemDlls)) && !fromSystem32)
        {
            reason = L"Hijacked system DLL: " + modName;
            return true;
        }

        if (HasL2SimpleBotIdentity(modName) ||
            HasL2SimpleBotIdentity(modPath) ||
            ContainsAnyInsensitive(modName, g_BlockedKeywords, _countof(g_BlockedKeywords)) ||
            ContainsAnyInsensitive(modPath, g_BlockedKeywords, _countof(g_BlockedKeywords)))
        {
            reason = L"Suspicious module: " + modName;
            return true;
        }

        if (fromGame)
        {
            if (!EqualsAnyInsensitive(modName, g_AllowedGameModules, _countof(g_AllowedGameModules)))
            {
                reason = L"Unexpected game module: " + modName;
                return true;
            }
            continue;
        }

        if (fromSystem32)
            continue;

        if (fromWindows)
        {
            if (!IsSignedFileTrusted(modPath))
            {
                reason = L"Untrusted Windows module: " + modName;
                return true;
            }
            continue;
        }

        if (EqualsAnyInsensitive(modName, g_AllowedGameModules, _countof(g_AllowedGameModules)))
            continue;

        reason = L"External module: " + modName;
        return true;
    }

    return false;
}
 

static bool CheckDrivers(std::wstring& reason)
{
    reason.clear();

    LPVOID drivers[1024];
    DWORD needed = 0;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed))
        return false;

    int count = needed / sizeof(drivers[0]);
    for (int i = 0; i < count; i++)
    {
        wchar_t name[MAX_PATH] = { 0 };
        GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH);

        if (ContainsAnyInsensitive(name, g_BlockedDriverKeywords, _countof(g_BlockedDriverKeywords)))
        {
            reason = L"Blocked kernel driver: " + std::wstring(name);
            return true;
        }
    }

    return false;
}

static bool IsSuspiciousProcess(
    DWORD pid,
    const std::wstring& processName,
    bool inspectImagePath,
    std::wstring& reason)
{
    if (processName.empty() || _wcsicmp(processName.c_str(), L"l2.exe") == 0)
        return false;

    std::wstring base = ToLowerW(GetFileNameOnly(processName));

    if (HasL2SimpleBotIdentity(base) ||
        EqualsAnyInsensitive(base, g_BlockedProcessNames, _countof(g_BlockedProcessNames)) ||
        ContainsAnyInsensitive(base, g_BlockedKeywords, _countof(g_BlockedKeywords)))
    {
        reason = processName;
        return true;
    }

    if (!inspectImagePath)
        return false;

    std::wstring imagePath = GetProcessImagePath(pid);
    if (!imagePath.empty())
    {
        if (HasL2SimpleBotIdentity(imagePath) ||
            ContainsAnyInsensitive(
                imagePath,
                g_BlockedKeywords,
                _countof(g_BlockedKeywords)))
        {
            reason = processName + L" [" + imagePath + L"]";
            return true;
        }

        std::wstring versionIdentity;
        if (HasBlockedVersionIdentity(imagePath, versionIdentity))
        {
            reason = processName + L" [blocked file identity: " + versionIdentity + L"]";
            return true;
        }
    }

    return false;
}

static bool ScanForSuspiciousProcess(
    std::wstring& result,
    bool inspectImagePaths)
{
    result.clear();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            std::wstring reason;
            if (IsSuspiciousProcess(
                pe.th32ProcessID,
                pe.szExeFile,
                inspectImagePaths,
                reason))
            {
                result = reason;
                found = true;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    wchar_t title[512] = { 0 };
    GetWindowTextW(hwnd, title, 511);
    std::wstring wtitle = title;

    // Scan hidden windows only for this high-confidence identity. Broad title
    // keywords remain limited to visible windows to avoid false positives.
    if (!wtitle.empty() &&
        (HasL2SimpleBotIdentity(wtitle) ||
         (IsWindowVisible(hwnd) &&
          ContainsAnyInsensitive(wtitle, g_BlockedKeywords, _countof(g_BlockedKeywords)))))
    {
        std::wstring* result = (std::wstring*)lParam;
        *result = wtitle;
        return FALSE;
    }

    return TRUE;
}

static bool ScanForSuspiciousWindow(std::wstring& result)
{
    result.clear();
    EnumWindows(EnumWindowsProc, (LPARAM)&result);
    return !result.empty();
}

static void HandleDetectionAndShutdown(const std::wstring& detectedName)
{
    if (InterlockedCompareExchange(&g_DetectionTriggered, 1, 0) != 0)
        return;

    InterlockedExchange(&g_IsRunning, 0);
    if (g_hStopEvent)
        SetEvent(g_hStopEvent);

    LogAntiCheat(L"DETECTION: " + detectedName);
    ShowDetectionMessageWithTimeout(detectedName);
    TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
}

void StartAntiCheat()
{
    if (!g_hStopEvent)
        g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (g_hStopEvent)
        ResetEvent(g_hStopEvent);

    InterlockedExchange(&g_IsRunning, 1);
    InterlockedExchange(&g_DetectionTriggered, 0);
    InterlockedExchange(&g_IsShuttingDown, 0);
    ResetInputHeuristics();

    AntiCheat_OnStarted();
    StartInputMonitoring();
}

void StopAntiCheat()
{
    if (InterlockedExchange(&g_IsShuttingDown, 1) != 0)
        return;

    InterlockedExchange(&g_IsRunning, 0);
    StopInputMonitoring();
    AntiCheat_OnStopped();

    if (g_hStopEvent)
    {
        SetEvent(g_hStopEvent);
    }

}
DWORD WINAPI AntiCheatThread(LPVOID)
{
    StartAntiCheat();

    ULONGLONG tickLight = GetTickCount64();
    ULONGLONG tickMedium = GetTickCount64();
    ULONGLONG tickHeavy = GetTickCount64();
    ULONGLONG tickFiles = GetTickCount64();
    ULONGLONG tickDrivers = GetTickCount64();

    while (InterlockedCompareExchange(&g_IsRunning, 0, 0) == 1)
    {
        if (g_hStopEvent && WaitForSingleObject(g_hStopEvent, 250) == WAIT_OBJECT_0)
            break;

        std::wstring detected;
        const ULONGLONG now = GetTickCount64();

        if (ConsumeInputDetection(detected))
        {
            HandleDetectionAndShutdown(detected);
            break;
        }

        if ((now - tickLight) >= 1000)
        {
            if (ScanForSuspiciousProcess(detected, false) ||
                ScanForSuspiciousWindow(detected))
            {
                HandleDetectionAndShutdown(detected);
                break;
            }

            tickLight = now;
        }

        if ((now - tickMedium) >= 5000)
        {
            if (IsDebuggerPresentHard())
            {
                HandleDetectionAndShutdown(L"Debugger");
                break;
            }

            tickMedium = now;
        }

        if ((now - tickHeavy) >= 10000)
        {
            if (ScanForSuspiciousProcess(detected, true) ||
                ScanModules(detected))
            {
                HandleDetectionAndShutdown(detected);
                break;
            }

            tickHeavy = now;
        }

        if ((now - tickFiles) >= 60000)
        {
            FileCheckResult fileCheck = VerifyProtectedFiles();

            if (!fileCheck.allOk)
            {
                InterlockedExchange(&g_ProtectionState.filesOk, 0);

                std::wstring reason;

                if (fileCheck.fileMissing)
                {
                    reason = L"Protected file missing: ";
                    reason += fileCheck.fileName;
                    reason += L" | path: ";
                    reason += fileCheck.fullPath;
                    reason += L" | error: ";
                    reason += std::to_wstring(fileCheck.errorCode);
                }
                else if (fileCheck.fileChanged)
                {
                    reason = L"Protected file modified: ";
                    reason += fileCheck.fileName;

                    reason += L" | current SHA256: ";
                    reason += std::wstring(fileCheck.hash.begin(), fileCheck.hash.end());

                    reason += L" | expected SHA256: ";
                    reason += std::wstring(fileCheck.expectedHash.begin(), fileCheck.expectedHash.end());
                }
                else
                {
                    reason = L"Protected file invalid: ";
                    reason += fileCheck.fileName;
                }

                HandleDetectionAndShutdown(reason);
                break;
            }

            InterlockedExchange(&g_ProtectionState.filesOk, 1);
            tickFiles = now;
        }
        if ((now - tickDrivers) >= 120000)
        {
            if (CheckDrivers(detected))
            {
                HandleDetectionAndShutdown(detected);
                break;
            }

            tickDrivers = now;
        }
    }

    StopAntiCheat();
    return 0;
}
