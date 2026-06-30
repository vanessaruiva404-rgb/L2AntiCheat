#include "NotificationIcon.h"
#include "resource.h"

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <string>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

namespace
{
    const UINT kTrayCallbackMessage = WM_APP + 4001;
    const UINT kShowIconMessage = WM_APP + 4002;
    const UINT kHideIconMessage = WM_APP + 4003;
    const UINT kRefreshIconMessage = WM_APP + 4004;
    const UINT kTrayIconId = 1001;
    const UINT_PTR kStatsTimerId = 5001;
    const UINT_PTR kPanelDeactivateTimerId = 5002;
    const UINT_PTR kTooltipTimerId = 5003;
    const int kPanelWidth = 340;
    const int kPanelHeight = 238;
    const int kTooltipWidth = 240;
    const int kTooltipHeight = 94;

    const wchar_t* kNotificationWindowClass =
        L"L2RP_NOTIFICATION_WINDOW";
    const wchar_t* kPanelWindowClass =
        L"L2RP_PROTECTION_PANEL";
    const wchar_t* kTooltipWindowClass =
        L"L2RP_NOTIFICATION_TOOLTIP";
    const wchar_t* kWebsiteUrl =
        L"https://www.l2rp.com.br";

    HINSTANCE g_Module = NULL;
    HANDLE g_UiThread = NULL;
    DWORD g_UiThreadId = 0;
    HANDLE g_UiReadyEvent = NULL;
    HWND g_NotificationWindow = NULL;
    HWND g_PanelWindow = NULL;
    HWND g_TooltipWindow = NULL;
    HICON g_MainIcon = NULL;
    NOTIFYICONDATAW g_NotificationData = {};
    bool g_NotificationVisible = false;
    bool g_NotificationRequested = false;
    bool g_WebsiteHovered = false;
    bool g_ProcessDetaching = false;
    UINT g_TaskbarCreatedMessage = 0;
    ULONGLONG g_LastTrayActivation = 0;

    RECT g_WebsiteRect = {};
    RECT g_CloseRect = {};
    RECT g_LastTooltipAnchor = {};
    bool g_HasLastTooltipAnchor = false;

    HFONT g_TitleFont = NULL;
    HFONT g_SubtitleFont = NULL;
    HFONT g_StatusFont = NULL;
    HFONT g_LabelFont = NULL;
    HFONT g_ValueFont = NULL;
    HFONT g_ButtonFont = NULL;

    SRWLOCK g_StateLock = SRWLOCK_INIT;
    wchar_t g_NotificationStatus[64] = L"Status: Starting";
    wchar_t g_TooltipText[128] = {};
    bool g_AntiCheatActive = false;
    ULONGLONG g_SessionStartedAt = 0;

    struct NotificationSnapshot
    {
        wchar_t status[64];
        bool active;
        ULONGLONG sessionStartedAt;
    };

    HFONT CreateUiFont(int height, int weight)
    {
        return CreateFontW(
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
    }

    void CreateUiFonts()
    {
        g_TitleFont = CreateUiFont(22, FW_BOLD);
        g_SubtitleFont = CreateUiFont(11, FW_SEMIBOLD);
        g_StatusFont = CreateUiFont(16, FW_BOLD);
        g_LabelFont = CreateUiFont(10, FW_SEMIBOLD);
        g_ValueFont = CreateUiFont(20, FW_BOLD);
        g_ButtonFont = CreateUiFont(12, FW_BOLD);
    }

    void DeleteUiFonts()
    {
        HFONT* fonts[] =
        {
            &g_TitleFont,
            &g_SubtitleFont,
            &g_StatusFont,
            &g_LabelFont,
            &g_ValueFont,
            &g_ButtonFont
        };

        for (HFONT* font : fonts)
        {
            if (*font)
            {
                DeleteObject(*font);
                *font = NULL;
            }
        }
    }

    NotificationSnapshot GetSnapshot()
    {
        NotificationSnapshot snapshot = {};

        AcquireSRWLockShared(&g_StateLock);
        lstrcpynW(
            snapshot.status,
            g_NotificationStatus,
            ARRAYSIZE(snapshot.status));
        snapshot.active = g_AntiCheatActive;
        snapshot.sessionStartedAt = g_SessionStartedAt;
        ReleaseSRWLockShared(&g_StateLock);

        return snapshot;
    }

    std::wstring FormatSessionTime(const NotificationSnapshot& snapshot)
    {
        if (!snapshot.active || snapshot.sessionStartedAt == 0)
            return L"00:00:00";

        const ULONGLONG totalSeconds =
            (GetTickCount64() - snapshot.sessionStartedAt) / 1000;
        const ULONGLONG hours = totalSeconds / 3600;
        const ULONGLONG minutes = (totalSeconds / 60) % 60;
        const ULONGLONG seconds = totalSeconds % 60;

        wchar_t text[32] = {};
        swprintf_s(
            text,
            ARRAYSIZE(text),
            L"%02llu:%02llu:%02llu",
            hours,
            minutes,
            seconds);
        return text;
    }

    void BuildTooltipText(wchar_t* buffer, size_t count)
    {
        const NotificationSnapshot snapshot = GetSnapshot();
        const std::wstring session = FormatSessionTime(snapshot);

        swprintf_s(
            buffer,
            count,
            L"L2PROTECTION Protection\nAntiCheat: %s\nSess\u00e3o: %s",
            snapshot.active ? L"Ativo" : L"Inativo",
            session.c_str());
    }

    void FillNotificationTooltip()
    {
        wchar_t tip[128] = {};
        BuildTooltipText(tip, ARRAYSIZE(tip));

        lstrcpynW(
            g_NotificationData.szTip,
            tip,
            ARRAYSIZE(g_NotificationData.szTip));
    }

    HICON LoadNotificationIcon()
    {
        HICON icon = reinterpret_cast<HICON>(LoadImageW(
            g_Module,
            MAKEINTRESOURCEW(IDI_TRAYICON),
            IMAGE_ICON,
            32,
            32,
            LR_DEFAULTCOLOR));

        if (!icon)
            icon = LoadIconW(NULL, IDI_SHIELD);
        if (!icon)
            icon = LoadIconW(NULL, IDI_APPLICATION);

        return icon;
    }

    void HideTrayTooltip();

    void AddNotificationIcon()
    {
        if (!g_NotificationWindow)
            return;

        if (!g_MainIcon)
            g_MainIcon = LoadNotificationIcon();

        if (g_NotificationVisible)
        {
            FillNotificationTooltip();
            g_NotificationData.hIcon = g_MainIcon;
            Shell_NotifyIconW(NIM_MODIFY, &g_NotificationData);
            return;
        }

        ZeroMemory(&g_NotificationData, sizeof(g_NotificationData));
        g_NotificationData.cbSize = sizeof(g_NotificationData);
        g_NotificationData.hWnd = g_NotificationWindow;
        g_NotificationData.uID = kTrayIconId;
        g_NotificationData.uFlags =
            NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_NotificationData.uCallbackMessage = kTrayCallbackMessage;
        g_NotificationData.hIcon = g_MainIcon;
        FillNotificationTooltip();

        if (Shell_NotifyIconW(NIM_ADD, &g_NotificationData))
        {
            g_NotificationData.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &g_NotificationData);
            g_NotificationVisible = true;
        }
    }

    void RemoveNotificationIcon()
    {
        if (!g_NotificationVisible)
            return;

        HideTrayTooltip();
        Shell_NotifyIconW(NIM_DELETE, &g_NotificationData);
        g_NotificationVisible = false;
        ZeroMemory(&g_NotificationData, sizeof(g_NotificationData));
    }
	void DrawStatusDot(HDC hdc, const RECT& statusRect, bool active)
	{
		const int dotSize = 7;
	
		const int dotX = statusRect.left + 13;
	
		// centraliza verticalmente dentro da barra
		const int dotY = statusRect.top + ((statusRect.bottom - statusRect.top - dotSize) / 2) - 1;
	
		COLORREF color = active ? RGB(0, 220, 105) : RGB(120, 120, 120);
	
		HBRUSH brush = CreateSolidBrush(color);
		HPEN pen = CreatePen(PS_SOLID, 1, color);
	
		HGDIOBJ oldBrush = SelectObject(hdc, brush);
		HGDIOBJ oldPen = SelectObject(hdc, pen);
	
		Ellipse(
			hdc,
			dotX,
			dotY,
			dotX + dotSize,
			dotY + dotSize);
	
		SelectObject(hdc, oldPen);
		SelectObject(hdc, oldBrush);
	
		DeleteObject(pen);
		DeleteObject(brush);
	}
	
    void FillSolidRect(HDC hdc, const RECT& rect, COLORREF color)
    {
        HBRUSH brush = CreateSolidBrush(color);
        FillRect(hdc, &rect, brush);
        DeleteObject(brush);
    }

    void FillRoundedRect(
        HDC hdc,
        const RECT& rect,
        COLORREF fill,
        COLORREF border,
        int radius)
    {
        HBRUSH brush = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, 1, border);
        HGDIOBJ oldBrush = SelectObject(hdc, brush);
        HGDIOBJ oldPen = SelectObject(hdc, pen);

        RoundRect(
            hdc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            radius,
            radius);

        RECT statusBox = { 21, 70, 226, 93 };

 
    }

    void DrawUiText(
        HDC hdc,
        const std::wstring& text,
        RECT rect,
        HFONT font,
        COLORREF color,
        UINT format)
    {
        HFONT oldFont = reinterpret_cast<HFONT>(SelectObject(hdc, font));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, color);
        DrawTextW(hdc, text.c_str(), -1, &rect, format);
        SelectObject(hdc, oldFont);
    }

    void DrawShield(HDC hdc)
    {
        POINT shield[] =
        {
            { 31, 18 },
            { 48, 24 },
            { 46, 43 },
            { 31, 55 },
            { 16, 43 },
            { 14, 24 }
        };

        HBRUSH shieldBrush = CreateSolidBrush(RGB(255, 84, 26));
        HPEN shieldPen = CreatePen(PS_SOLID, 1, RGB(255, 127, 65));
        HGDIOBJ oldBrush = SelectObject(hdc, shieldBrush);
        HGDIOBJ oldPen = SelectObject(hdc, shieldPen);
        Polygon(hdc, shield, ARRAYSIZE(shield));
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(shieldPen);
        DeleteObject(shieldBrush);

        HPEN checkPen = CreatePen(PS_SOLID, 3, RGB(255, 255, 255));
        oldPen = SelectObject(hdc, checkPen);
        MoveToEx(hdc, 23, 35, NULL);
        LineTo(hdc, 29, 41);
        LineTo(hdc, 40, 29);
        SelectObject(hdc, oldPen);
        DeleteObject(checkPen);
    }

    void DrawSmallShield(HDC hdc, int x, int y)
    {
        POINT shield[] =
        {
            { x + 17, y },
            { x + 34, y + 6 },
            { x + 32, y + 25 },
            { x + 17, y + 37 },
            { x + 2, y + 25 },
            { x, y + 6 }
        };

        HBRUSH shieldBrush = CreateSolidBrush(RGB(255, 84, 26));
        HPEN shieldPen = CreatePen(PS_SOLID, 1, RGB(255, 132, 77));
        HGDIOBJ oldBrush = SelectObject(hdc, shieldBrush);
        HGDIOBJ oldPen = SelectObject(hdc, shieldPen);
        Polygon(hdc, shield, ARRAYSIZE(shield));
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(shieldPen);
        DeleteObject(shieldBrush);

        HPEN checkPen = CreatePen(PS_SOLID, 3, RGB(255, 255, 255));
        oldPen = SelectObject(hdc, checkPen);
        MoveToEx(hdc, x + 9, y + 20, NULL);
        LineTo(hdc, x + 15, y + 26);
        LineTo(hdc, x + 26, y + 14);
        SelectObject(hdc, oldPen);
        DeleteObject(checkPen);
    }

    void PaintProtectionPanel(HWND window)
    {
        PAINTSTRUCT paint = {};
        HDC windowDc = BeginPaint(window, &paint);

        RECT client = {};
        GetClientRect(window, &client);

        HDC bufferDc = CreateCompatibleDC(windowDc);
        HBITMAP bufferBitmap = CreateCompatibleBitmap(
            windowDc,
            client.right,
            client.bottom);
        HGDIOBJ oldBitmap = SelectObject(bufferDc, bufferBitmap);

        FillSolidRect(bufferDc, client, RGB(15, 14, 19));
        RECT accent = { 0, 0, client.right, 4 };
        FillSolidRect(bufferDc, accent, RGB(255, 84, 26));

        HPEN border = CreatePen(PS_SOLID, 1, RGB(136, 61, 18));
        HGDIOBJ oldPen = SelectObject(bufferDc, border);
        HGDIOBJ oldBrush = SelectObject(
            bufferDc,
            GetStockObject(NULL_BRUSH));
        RoundRect(
            bufferDc,
            0,
            0,
            client.right - 1,
            client.bottom - 1,
            18,
            18);
        SelectObject(bufferDc, oldBrush);
        SelectObject(bufferDc, oldPen);
        DeleteObject(border);

        DrawShield(bufferDc);

        RECT title = { 60, 14, 285, 38 };
        DrawUiText(
            bufferDc,
            L"L2PROTECTION",
            title,
            g_TitleFont,
            RGB(255, 255, 255),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT subtitle = { 61, 37, 285, 54 };
        DrawUiText(
            bufferDc,
            L"PROTECTION CENTER",
            subtitle,
            g_SubtitleFont,
            RGB(255, 132, 77),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        g_CloseRect = { 301, 16, 326, 41 };
        FillRoundedRect(
            bufferDc,
            g_CloseRect,
            RGB(28, 26, 33),
            RGB(58, 53, 64),
            8);
        DrawUiText(
            bufferDc,
            L"x",
            g_CloseRect,
            g_StatusFont,
            RGB(210, 202, 197),
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        const NotificationSnapshot snapshot = GetSnapshot();

        RECT statusCard = { 16, 66, 324, 116 };
        FillRoundedRect(
            bufferDc,
            statusCard,
            RGB(24, 22, 28),
            RGB(67, 57, 51),
            12);

        HBRUSH statusBrush = CreateSolidBrush(
            snapshot.active ? RGB(68, 214, 121) : RGB(238, 86, 92));
        HGDIOBJ oldStatusBrush = SelectObject(bufferDc, statusBrush);
        HGDIOBJ oldStatusPen = SelectObject(
            bufferDc,
            GetStockObject(NULL_PEN));
        Ellipse(bufferDc, 29, 82, 39, 92);
        SelectObject(bufferDc, oldStatusPen);
        SelectObject(bufferDc, oldStatusBrush);
        DeleteObject(statusBrush);

        RECT statusTitle = { 49, 73, 307, 96 };
        DrawUiText(
            bufferDc,
            snapshot.active ? L"AntiCheat Ativo" : L"AntiCheat Inativo",
            statusTitle,
            g_StatusFont,
            RGB(246, 242, 238),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT statusDetail = { 49, 94, 307, 110 };
        DrawUiText(
            bufferDc,
            snapshot.active
                ? L"HWID e integridade monitorados"
                : L"Monitoramento interrompido",
            statusDetail,
            g_LabelFont,
            RGB(180, 169, 163),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT timeCard = { 16, 126, 324, 176 };
        FillRoundedRect(
            bufferDc,
            timeCard,
            RGB(24, 22, 28),
            RGB(67, 57, 51),
            12);

        RECT timeLabel = { 28, 132, 150, 148 };
        DrawUiText(
            bufferDc,
            L"TEMPO ONLINE",
            timeLabel,
            g_LabelFont,
            RGB(255, 132, 77),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT timeValue = { 166, 132, 312, 170 };
        DrawUiText(
            bufferDc,
            FormatSessionTime(snapshot),
            timeValue,
            g_ValueFont,
            RGB(255, 255, 255),
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

        g_WebsiteRect = { 72, 190, 268, 222 };
        FillRoundedRect(
            bufferDc,
            g_WebsiteRect,
            g_WebsiteHovered ? RGB(255, 111, 47) : RGB(255, 84, 26),
            g_WebsiteHovered ? RGB(255, 163, 112) : RGB(255, 116, 57),
            10);

        DrawUiText(
            bufferDc,
            L"LINEAGEII.COM.BR  >",
            g_WebsiteRect,
            g_ButtonFont,
            RGB(255, 255, 255),
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        BitBlt(
            windowDc,
            0,
            0,
            client.right,
            client.bottom,
            bufferDc,
            0,
            0,
            SRCCOPY);

        SelectObject(bufferDc, oldBitmap);
        DeleteObject(bufferBitmap);
        DeleteDC(bufferDc);
        EndPaint(window, &paint);
    }

    bool QueryTrayIconRect(RECT& anchor)
    {
        HMODULE shell = GetModuleHandleW(L"shell32.dll");
        if (shell)
        {
            typedef HRESULT(WINAPI* ShellNotifyIconGetRectFn)(
                const NOTIFYICONIDENTIFIER* identifier,
                RECT* iconLocation);

            ShellNotifyIconGetRectFn getIconRect =
                reinterpret_cast<ShellNotifyIconGetRectFn>(
                    GetProcAddress(shell, "Shell_NotifyIconGetRect"));

            if (getIconRect)
            {
                NOTIFYICONIDENTIFIER identifier = {};
                identifier.cbSize = sizeof(identifier);
                identifier.hWnd = g_NotificationWindow;
                identifier.uID = kTrayIconId;
                return SUCCEEDED(getIconRect(&identifier, &anchor));
            }
        }

        return false;
    }

    void ResolveTrayAnchor(RECT& anchor)
    {
        if (!QueryTrayIconRect(anchor))
        {
            POINT cursor = {};
            GetCursorPos(&cursor);
            anchor = { cursor.x, cursor.y, cursor.x + 1, cursor.y + 1 };
        }
    }

    void PositionPanelNearTray()
    {
        RECT anchor = {};
        ResolveTrayAnchor(anchor);

        HMONITOR monitor = MonitorFromRect(&anchor, MONITOR_DEFAULTTONEAREST);
        MONITORINFO monitorInfo = {};
        monitorInfo.cbSize = sizeof(monitorInfo);
        GetMonitorInfoW(monitor, &monitorInfo);

        int x = anchor.right - kPanelWidth;
        int y = anchor.top - kPanelHeight - 10;

        if (x < monitorInfo.rcWork.left + 8)
            x = monitorInfo.rcWork.left + 8;
        if (x + kPanelWidth > monitorInfo.rcWork.right - 8)
            x = monitorInfo.rcWork.right - kPanelWidth - 8;

        if (y < monitorInfo.rcWork.top + 8)
            y = anchor.bottom + 10;
        if (y + kPanelHeight > monitorInfo.rcWork.bottom - 8)
            y = monitorInfo.rcWork.bottom - kPanelHeight - 8;

        SetWindowPos(
            g_PanelWindow,
            HWND_TOPMOST,
            x,
            y,
            kPanelWidth,
            kPanelHeight,
            SWP_SHOWWINDOW);
    }

    void UpdateTrayTooltipText()
    {
        if (!g_TooltipWindow)
            return;

        BuildTooltipText(g_TooltipText, ARRAYSIZE(g_TooltipText));
        if (IsWindowVisible(g_TooltipWindow))
            InvalidateRect(g_TooltipWindow, NULL, FALSE);
    }

    void PositionTooltipNearTray()
    {
        if (!g_TooltipWindow)
            return;

        RECT anchor = {};
        ResolveTrayAnchor(anchor);
        g_LastTooltipAnchor = anchor;
        g_HasLastTooltipAnchor = true;

        HMONITOR monitor = MonitorFromRect(&anchor, MONITOR_DEFAULTTONEAREST);
        MONITORINFO monitorInfo = {};
        monitorInfo.cbSize = sizeof(monitorInfo);
        GetMonitorInfoW(monitor, &monitorInfo);

        int x = anchor.right - kTooltipWidth;
        int y = anchor.top - kTooltipHeight - 6;

        if (anchor.top < monitorInfo.rcWork.top + 32)
            y = anchor.bottom + 6;

        if (x < monitorInfo.rcWork.left + 8)
            x = monitorInfo.rcWork.left + 8;
        if (x + kTooltipWidth > monitorInfo.rcWork.right - 8)
            x = monitorInfo.rcWork.right - kTooltipWidth - 8;
        if (y < monitorInfo.rcWork.top + 8)
            y = anchor.bottom + 6;
        if (y + kTooltipHeight > monitorInfo.rcWork.bottom - 8)
            y = anchor.top - kTooltipHeight - 6;

        SetWindowPos(
            g_TooltipWindow,
            HWND_TOPMOST,
            x,
            y,
            kTooltipWidth,
            kTooltipHeight,
            SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }

    void PaintTrayTooltip(HWND window)
    {
        PAINTSTRUCT paint = {};
        HDC windowDc = BeginPaint(window, &paint);

        RECT client = {};
        GetClientRect(window, &client);

        HDC bufferDc = CreateCompatibleDC(windowDc);
        HBITMAP bufferBitmap = CreateCompatibleBitmap(
            windowDc,
            client.right,
            client.bottom);
        HGDIOBJ oldBitmap = SelectObject(bufferDc, bufferBitmap);

        FillSolidRect(bufferDc, client, RGB(15, 14, 19));
        RECT accent = { 0, 0, client.right, 4 };
        FillSolidRect(bufferDc, accent, RGB(255, 84, 26));

        HPEN border = CreatePen(PS_SOLID, 1, RGB(136, 61, 18));
        HGDIOBJ oldPen = SelectObject(bufferDc, border);
        HGDIOBJ oldBrush = SelectObject(bufferDc, GetStockObject(NULL_BRUSH));
        RoundRect(
            bufferDc,
            0,
            0,
            client.right - 1,
            client.bottom - 1,
            18,
            18);
        SelectObject(bufferDc, oldBrush);
        SelectObject(bufferDc, oldPen);
        DeleteObject(border);

        const NotificationSnapshot snapshot = GetSnapshot();
        DrawSmallShield(bufferDc, 14, 16);

        RECT title = { 58, 12, client.right - 14, 35 };
        DrawUiText(
            bufferDc,
            L"L2PROTECTION",
            title,
            g_StatusFont,
            RGB(255, 255, 255),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT subtitle = { 59, 34, client.right - 14, 51 };
        DrawUiText(
            bufferDc,
            L"PROTECTION CENTER",
            subtitle,
            g_SubtitleFont,
            RGB(255, 132, 77),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT info = { 14, 59, client.right - 14, client.bottom - 4 };
        FillRoundedRect(
            bufferDc,
            info,
            RGB(24, 22, 28),
            RGB(67, 57, 51),
            10);

        HBRUSH statusBrush = CreateSolidBrush(
            snapshot.active ? RGB(68, 214, 121) : RGB(238, 86, 92));
        HGDIOBJ oldStatusBrush = SelectObject(bufferDc, statusBrush);
        HGDIOBJ oldStatusPen = SelectObject(bufferDc, GetStockObject(NULL_PEN));
        Ellipse(bufferDc, info.left + 12, info.top + 12, info.left + 22, info.top + 22);
        SelectObject(bufferDc, oldStatusPen);
        SelectObject(bufferDc, oldStatusBrush);
        DeleteObject(statusBrush);

        RECT status = { info.left + 30, info.top + 4, info.right - 84, info.bottom - 4 };
        DrawUiText(
            bufferDc,
            snapshot.active ? L"AntiCheat Ativo" : L"AntiCheat Inativo",
            status,
            g_ButtonFont,
            RGB(246, 242, 238),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        RECT session = { info.right - 86, info.top + 4, info.right - 10, info.bottom - 4 };
        DrawUiText(
            bufferDc,
            FormatSessionTime(snapshot),
            session,
            g_ButtonFont,
            RGB(255, 255, 255),
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

        BitBlt(
            windowDc,
            0,
            0,
            client.right,
            client.bottom,
            bufferDc,
            0,
            0,
            SRCCOPY);

        SelectObject(bufferDc, oldBitmap);
        DeleteObject(bufferBitmap);
        DeleteDC(bufferDc);

        EndPaint(window, &paint);
    }

    bool IsCursorNearTrayTooltip()
    {
        POINT cursor = {};
        GetCursorPos(&cursor);

        RECT tooltipRect = {};
        if (g_TooltipWindow &&
            IsWindowVisible(g_TooltipWindow) &&
            GetWindowRect(g_TooltipWindow, &tooltipRect))
        {
            InflateRect(&tooltipRect, 4, 4);
            if (PtInRect(&tooltipRect, cursor))
                return true;
        }

        RECT trayRect = {};
        if (QueryTrayIconRect(trayRect))
        {
            InflateRect(&trayRect, 12, 12);
            if (PtInRect(&trayRect, cursor))
                return true;
        }
        else if (g_HasLastTooltipAnchor)
        {
            trayRect = g_LastTooltipAnchor;
            InflateRect(&trayRect, 12, 12);
            if (PtInRect(&trayRect, cursor))
                return true;
        }

        return false;
    }

    void HideTrayTooltip()
    {
        if (!g_TooltipWindow)
            return;

        if (g_NotificationWindow)
            KillTimer(g_NotificationWindow, kTooltipTimerId);

        ShowWindow(g_TooltipWindow, SW_HIDE);
    }

    void ShowTrayTooltip()
    {
        if (!g_TooltipWindow || !g_NotificationWindow || !g_NotificationVisible)
            return;

        if (g_PanelWindow && IsWindowVisible(g_PanelWindow))
            return;

        UpdateTrayTooltipText();
        PositionTooltipNearTray();
        InvalidateRect(g_TooltipWindow, NULL, FALSE);

        SetTimer(g_NotificationWindow, kTooltipTimerId, 250, NULL);
    }

    LRESULT CALLBACK TooltipWindowProc(
        HWND window,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
        {
            HRGN region = CreateRoundRectRgn(
                0,
                0,
                kTooltipWidth + 1,
                kTooltipHeight + 1,
                18,
                18);
            SetWindowRgn(window, region, TRUE);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
            PaintTrayTooltip(window);
            return 0;

        case WM_NCHITTEST:
            return HTTRANSPARENT;

        case WM_CLOSE:
            HideTrayTooltip();
            return 0;

        case WM_DESTROY:
            g_TooltipWindow = NULL;
            return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }

    void ShowProtectionPanel()
    {
        if (!g_PanelWindow)
            return;

        HideTrayTooltip();
        PositionPanelNearTray();
        InvalidateRect(g_PanelWindow, NULL, FALSE);
        ShowWindow(g_PanelWindow, SW_SHOWNORMAL);
        SetForegroundWindow(g_PanelWindow);
    }

    void ToggleProtectionPanel()
    {
        if (!g_PanelWindow)
            return;

        if (IsWindowVisible(g_PanelWindow))
        {
            KillTimer(g_PanelWindow, kPanelDeactivateTimerId);
            ShowWindow(g_PanelWindow, SW_HIDE);
        }
        else
            ShowProtectionPanel();
    }

    LRESULT CALLBACK ProtectionPanelProc(
        HWND window,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
        {
            HRGN region = CreateRoundRectRgn(
                0,
                0,
                kPanelWidth + 1,
                kPanelHeight + 1,
                18,
                18);
            SetWindowRgn(window, region, TRUE);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
            PaintProtectionPanel(window);
            return 0;

        case WM_MOUSEMOVE:
        {
            POINT point =
            {
                GET_X_LPARAM(lParam),
                GET_Y_LPARAM(lParam)
            };
            const bool hovered = PtInRect(&g_WebsiteRect, point) != FALSE;
            if (hovered != g_WebsiteHovered)
            {
                g_WebsiteHovered = hovered;
                InvalidateRect(window, &g_WebsiteRect, FALSE);
            }

            TRACKMOUSEEVENT tracking = {};
            tracking.cbSize = sizeof(tracking);
            tracking.dwFlags = TME_LEAVE;
            tracking.hwndTrack = window;
            TrackMouseEvent(&tracking);
            return 0;
        }

        case WM_MOUSELEAVE:
            if (g_WebsiteHovered)
            {
                g_WebsiteHovered = false;
                InvalidateRect(window, &g_WebsiteRect, FALSE);
            }
            return 0;

        case WM_SETCURSOR:
        {
            POINT point = {};
            GetCursorPos(&point);
            ScreenToClient(window, &point);
            SetCursor(LoadCursor(
                NULL,
                PtInRect(&g_WebsiteRect, point) ? IDC_HAND : IDC_ARROW));
            return TRUE;
        }

        case WM_LBUTTONUP:
        {
            POINT point =
            {
                GET_X_LPARAM(lParam),
                GET_Y_LPARAM(lParam)
            };

            if (PtInRect(&g_CloseRect, point))
            {
                ShowWindow(window, SW_HIDE);
                return 0;
            }

            if (PtInRect(&g_WebsiteRect, point))
            {
                ShellExecuteW(
                    window,
                    L"open",
                    kWebsiteUrl,
                    NULL,
                    NULL,
                    SW_SHOWNORMAL);
                ShowWindow(window, SW_HIDE);
                return 0;
            }

            return 0;
        }

        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE)
                ShowWindow(window, SW_HIDE);
            return 0;

        case WM_TIMER:
            if (wParam == kPanelDeactivateTimerId)
            {
                KillTimer(window, kPanelDeactivateTimerId);
                ShowWindow(window, SW_HIDE);
                return 0;
            }
            break;

        case WM_ACTIVATE:
            if (LOWORD(wParam) == WA_INACTIVE)
                SetTimer(window, kPanelDeactivateTimerId, 300, NULL);
            else
                KillTimer(window, kPanelDeactivateTimerId);
            return 0;

        case WM_CLOSE:
            KillTimer(window, kPanelDeactivateTimerId);
            ShowWindow(window, SW_HIDE);
            return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }

    void RefreshRuntimeInformation()
    {
        if (g_NotificationVisible)
        {
            FillNotificationTooltip();
            Shell_NotifyIconW(NIM_MODIFY, &g_NotificationData);
        }

        if (g_PanelWindow && IsWindowVisible(g_PanelWindow))
            InvalidateRect(g_PanelWindow, NULL, FALSE);

        if (g_TooltipWindow && IsWindowVisible(g_TooltipWindow))
            UpdateTrayTooltipText();
    }

    LRESULT CALLBACK NotificationWindowProc(
        HWND window,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        if (message == g_TaskbarCreatedMessage)
        {
            g_NotificationVisible = false;
            if (g_NotificationRequested)
                AddNotificationIcon();
            return 0;
        }

        switch (message)
        {
        case kTrayCallbackMessage:
        {
            const UINT eventCode = LOWORD(lParam);
            if (eventCode == WM_LBUTTONUP ||
                eventCode == WM_LBUTTONDBLCLK ||
                eventCode == WM_CONTEXTMENU ||
                eventCode == NIN_SELECT ||
                eventCode == NIN_KEYSELECT)
            {
                HideTrayTooltip();
                const ULONGLONG now = GetTickCount64();
                if (now - g_LastTrayActivation >= 250)
                {
                    g_LastTrayActivation = now;
                    ToggleProtectionPanel();
                }
            }
            else if (eventCode == WM_MOUSEMOVE ||
                eventCode == NIN_POPUPOPEN)
            {
                ShowTrayTooltip();
            }
            else if (eventCode == NIN_POPUPCLOSE)
            {
                HideTrayTooltip();
            }
            return 0;
        }

        case kShowIconMessage:
            g_NotificationRequested = true;
            AddNotificationIcon();
            return 0;

        case kHideIconMessage:
            g_NotificationRequested = false;
            HideTrayTooltip();
            if (g_PanelWindow)
                ShowWindow(g_PanelWindow, SW_HIDE);
            RemoveNotificationIcon();
            return 0;

        case kRefreshIconMessage:
            RefreshRuntimeInformation();
            return 0;

        case WM_TIMER:
            if (wParam == kStatsTimerId)
            {
                RefreshRuntimeInformation();
                return 0;
            }
            if (wParam == kTooltipTimerId)
            {
                if ((g_PanelWindow && IsWindowVisible(g_PanelWindow)) ||
                    !IsCursorNearTrayTooltip())
                {
                    HideTrayTooltip();
                }
                else
                {
                    UpdateTrayTooltipText();
                    PositionTooltipNearTray();
                }
                return 0;
            }
            break;

        case WM_CLOSE:
            KillTimer(window, kStatsTimerId);
            HideTrayTooltip();
            if (g_TooltipWindow)
                DestroyWindow(g_TooltipWindow);
            g_TooltipWindow = NULL;
            if (g_PanelWindow)
                DestroyWindow(g_PanelWindow);
            g_PanelWindow = NULL;
            RemoveNotificationIcon();
            DestroyWindow(window);
            return 0;

        case WM_DESTROY:
            g_NotificationWindow = NULL;
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }

    bool RegisterNotificationClasses()
    {
        WNDCLASSEXW notificationClass = {};
        notificationClass.cbSize = sizeof(notificationClass);
        notificationClass.lpfnWndProc = NotificationWindowProc;
        notificationClass.hInstance = g_Module;
        notificationClass.lpszClassName = kNotificationWindowClass;

        if (!RegisterClassExW(&notificationClass) &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            return false;
        }

        WNDCLASSEXW panelClass = {};
        panelClass.cbSize = sizeof(panelClass);
        panelClass.lpfnWndProc = ProtectionPanelProc;
        panelClass.hInstance = g_Module;
        panelClass.hCursor = LoadCursor(NULL, IDC_ARROW);
        panelClass.lpszClassName = kPanelWindowClass;

        if (!RegisterClassExW(&panelClass) &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            return false;
        }

        WNDCLASSEXW tooltipClass = {};
        tooltipClass.cbSize = sizeof(tooltipClass);
        tooltipClass.lpfnWndProc = TooltipWindowProc;
        tooltipClass.hInstance = g_Module;
        tooltipClass.hCursor = LoadCursor(NULL, IDC_ARROW);
        tooltipClass.lpszClassName = kTooltipWindowClass;

        if (!RegisterClassExW(&tooltipClass) &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            return false;
        }

        return true;
    }

    DWORD WINAPI NotificationUiThread(LPVOID)
    {
        if (!RegisterNotificationClasses())
        {
            SetEvent(g_UiReadyEvent);
            return 0;
        }

        CreateUiFonts();
        g_TaskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

        g_NotificationWindow = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            kNotificationWindowClass,
            L"",
            WS_OVERLAPPED,
            -32000,
            -32000,
            1,
            1,
            NULL,
            NULL,
            g_Module,
            NULL);

        g_PanelWindow = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            kPanelWindowClass,
            L"L2PROTECTION Protection",
            WS_POPUP,
            0,
            0,
            kPanelWidth,
            kPanelHeight,
            NULL,
            NULL,
            g_Module,
            NULL);

        g_TooltipWindow = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            kTooltipWindowClass,
            L"",
            WS_POPUP,
            0,
            0,
            kTooltipWidth,
            kTooltipHeight,
            NULL,
            NULL,
            g_Module,
            NULL);

        if (g_NotificationWindow)
            SetTimer(g_NotificationWindow, kStatsTimerId, 1000, NULL);

        SetEvent(g_UiReadyEvent);

        if (!g_NotificationWindow || !g_PanelWindow || !g_TooltipWindow)
        {
            if (g_TooltipWindow)
                DestroyWindow(g_TooltipWindow);
            if (g_PanelWindow)
                DestroyWindow(g_PanelWindow);
            if (g_NotificationWindow)
                DestroyWindow(g_NotificationWindow);
            g_TooltipWindow = NULL;
            g_PanelWindow = NULL;
            g_NotificationWindow = NULL;
            DeleteUiFonts();
            return 0;
        }

        MSG message = {};
        while (GetMessageW(&message, NULL, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        DeleteUiFonts();
        return 0;
    }
}

bool NotificationIcon_Initialize(HINSTANCE moduleHandle)
{
    if (g_UiThread)
        return true;

    g_Module = moduleHandle;
    g_ProcessDetaching = false;
    g_UiReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_UiReadyEvent)
        return false;

    g_UiThread = CreateThread(
        NULL,
        0,
        NotificationUiThread,
        NULL,
        0,
        &g_UiThreadId);
    if (!g_UiThread)
    {
        CloseHandle(g_UiReadyEvent);
        g_UiReadyEvent = NULL;
        return false;
    }

    WaitForSingleObject(g_UiReadyEvent, 5000);
    CloseHandle(g_UiReadyEvent);
    g_UiReadyEvent = NULL;
    return g_NotificationWindow != NULL && g_PanelWindow != NULL;
}

void NotificationIcon_Show()
{
    if (g_NotificationWindow)
        PostMessageW(g_NotificationWindow, kShowIconMessage, 0, 0);
}

void NotificationIcon_Hide()
{
    if (g_NotificationWindow)
        PostMessageW(g_NotificationWindow, kHideIconMessage, 0, 0);
}

void NotificationIcon_HandleProcessDetach()
{
    g_ProcessDetaching = true;

    HideTrayTooltip();

    if (g_NotificationVisible)
    {
        Shell_NotifyIconW(NIM_DELETE, &g_NotificationData);
        g_NotificationVisible = false;
    }

    if (g_NotificationWindow)
        PostMessageW(g_NotificationWindow, WM_CLOSE, 0, 0);
}

void NotificationIcon_Shutdown()
{
    if (g_NotificationWindow)
        PostMessageW(g_NotificationWindow, WM_CLOSE, 0, 0);

    if (g_UiThread && !g_ProcessDetaching)
        WaitForSingleObject(g_UiThread, 2000);

    if (g_UiThread)
    {
        CloseHandle(g_UiThread);
        g_UiThread = NULL;
    }

    if (g_MainIcon)
    {
        DestroyIcon(g_MainIcon);
        g_MainIcon = NULL;
    }

    g_UiThreadId = 0;
    g_NotificationRequested = false;
    g_NotificationWindow = NULL;
    g_PanelWindow = NULL;
    g_TooltipWindow = NULL;
    g_Module = NULL;
}

bool NotificationIcon_IsVisible()
{
    return g_NotificationVisible;
}

void NotificationIcon_SetStatus(const wchar_t* status)
{
    if (!status)
        return;

    const bool active =
        wcsstr(status, L"Active") != NULL ||
        wcsstr(status, L"Ativo") != NULL;

    AcquireSRWLockExclusive(&g_StateLock);
    lstrcpynW(
        g_NotificationStatus,
        status,
        ARRAYSIZE(g_NotificationStatus));

    if (active && !g_AntiCheatActive)
        g_SessionStartedAt = GetTickCount64();

    g_AntiCheatActive = active;
    ReleaseSRWLockExclusive(&g_StateLock);

    if (g_NotificationWindow)
        PostMessageW(g_NotificationWindow, kRefreshIconMessage, 0, 0);
}
