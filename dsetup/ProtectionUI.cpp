#include "ProtectionUI.h"

#include <windows.h>
#include <windowsx.h>

namespace
{
    const wchar_t* kProtectionAlertClass =
        L"L2RP_PROTECTION_ALERT";
    const UINT_PTR kAlertTimerId = 1;
    const int kAlertWidth = 430;
    const int kAlertHeight = 206;

    struct AlertRequest
    {
        std::wstring title;
        std::wstring message;
        std::wstring detail;
        DWORD durationMs;
        ULONGLONG startedAt;
    };

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

        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(pen);
        DeleteObject(brush);
    }

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
            { 35, 25 },
            { 51, 31 },
            { 49, 49 },
            { 35, 61 },
            { 21, 49 },
            { 19, 31 }
        };

        HBRUSH brush = CreateSolidBrush(RGB(255, 84, 26));
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 132, 77));
        HGDIOBJ oldBrush = SelectObject(hdc, brush);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        Polygon(hdc, shield, ARRAYSIZE(shield));
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(pen);
        DeleteObject(brush);

        HPEN checkPen = CreatePen(PS_SOLID, 3, RGB(255, 255, 255));
        oldPen = SelectObject(hdc, checkPen);
        MoveToEx(hdc, 27, 41, NULL);
        LineTo(hdc, 33, 47);
        LineTo(hdc, 43, 36);
        SelectObject(hdc, oldPen);
        DeleteObject(checkPen);
    }

    void PaintAlert(HWND window, AlertRequest* request)
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

        HFONT brandFont = CreateUiFont(18, FW_BOLD);
        HFONT titleFont = CreateUiFont(17, FW_BOLD);
        HFONT bodyFont = CreateUiFont(14, FW_NORMAL);
        HFONT detailFont = CreateUiFont(12, FW_SEMIBOLD);
        HFONT timeFont = CreateUiFont(11, FW_BOLD);

        RECT brand = { 66, 18, 404, 38 };
        DrawUiText(
            bufferDc,
            L"L2 PROTECTION",
            brand,
            brandFont,
            RGB(255, 255, 255),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT brandSubtitle = { 67, 39, 404, 56 };
        DrawUiText(
            bufferDc,
            L"SECURITY CENTER",
            brandSubtitle,
            timeFont,
            RGB(255, 132, 77),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT content = { 16, 72, 414, 158 };
        FillRoundedRect(
            bufferDc,
            content,
            RGB(24, 22, 28),
            RGB(67, 57, 51),
            12);

        RECT title = { 30, 81, 400, 105 };
        DrawUiText(
            bufferDc,
            request->title,
            title,
            titleFont,
            RGB(246, 242, 238),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        RECT message = { 30, 105, 400, 132 };
        DrawUiText(
            bufferDc,
            request->message,
            message,
            bodyFont,
            RGB(215, 207, 201),
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS);

        RECT detail = { 30, 133, 400, 151 };
        DrawUiText(
            bufferDc,
            request->detail,
            detail,
            detailFont,
            RGB(255, 132, 77),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        const ULONGLONG elapsed = GetTickCount64() - request->startedAt;
        const DWORD remainingMs = elapsed >= request->durationMs
            ? 0
            : request->durationMs - (DWORD)elapsed;
        const int remainingSeconds = (int)((remainingMs + 999) / 1000);

        RECT progressBackground = { 16, 176, 350, 184 };
        FillRoundedRect(
            bufferDc,
            progressBackground,
            RGB(42, 37, 40),
            RGB(42, 37, 40),
            6);

        RECT progress = progressBackground;
        if (request->durationMs > 0)
        {
            const double ratio =
                (double)remainingMs / (double)request->durationMs;
            progress.right = progress.left +
                (int)((progressBackground.right -
                    progressBackground.left) * ratio);
        }

        if (progress.right > progress.left)
        {
            FillRoundedRect(
                bufferDc,
                progress,
                RGB(255, 84, 26),
                RGB(255, 84, 26),
                6);
        }

        RECT countdown = { 358, 166, 414, 194 };
        DrawUiText(
            bufferDc,
            std::to_wstring(remainingSeconds) + L"s",
            countdown,
            timeFont,
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

        DeleteObject(brandFont);
        DeleteObject(titleFont);
        DeleteObject(bodyFont);
        DeleteObject(detailFont);
        DeleteObject(timeFont);
        SelectObject(bufferDc, oldBitmap);
        DeleteObject(bufferBitmap);
        DeleteDC(bufferDc);
        EndPaint(window, &paint);
    }

    LRESULT CALLBACK ProtectionAlertProc(
        HWND window,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        AlertRequest* request = reinterpret_cast<AlertRequest*>(
            GetWindowLongPtrW(window, GWLP_USERDATA));

        switch (message)
        {
        case WM_NCCREATE:
        {
            CREATESTRUCTW* create =
                reinterpret_cast<CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(
                window,
                GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            return TRUE;
        }

        case WM_CREATE:
        {
            HRGN region = CreateRoundRectRgn(
                0,
                0,
                kAlertWidth + 1,
                kAlertHeight + 1,
                18,
                18);
            SetWindowRgn(window, region, TRUE);
            SetTimer(window, kAlertTimerId, 50, NULL);
            SetWindowPos(
                window,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_TIMER:
            if (wParam == kAlertTimerId && request)
            {
                if (GetTickCount64() - request->startedAt >=
                    request->durationMs)
                {
                    DestroyWindow(window);
                }
                else
                {
                    InvalidateRect(window, NULL, FALSE);
                }
                return 0;
            }
            break;

        case WM_PAINT:
            if (request)
                PaintAlert(window, request);
            return 0;

        case WM_CLOSE:
            return 0;

        case WM_DESTROY:
            KillTimer(window, kAlertTimerId);
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }

    bool RegisterAlertClass(HINSTANCE instance)
    {
        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = ProtectionAlertProc;
        windowClass.hInstance = instance;
        windowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
        windowClass.lpszClassName = kProtectionAlertClass;

        return RegisterClassExW(&windowClass) != 0 ||
            GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    }

    void RunAlert(AlertRequest* request)
    {
        if (!request)
            return;

        HINSTANCE instance = GetModuleHandleW(NULL);
        if (!RegisterAlertClass(instance))
            return;

        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);

        const int x = workArea.left +
            ((workArea.right - workArea.left - kAlertWidth) / 2);
        const int y = workArea.top +
            ((workArea.bottom - workArea.top - kAlertHeight) / 2);

        request->startedAt = GetTickCount64();

        HWND window = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            kProtectionAlertClass,
            L"L2 Protection",
            WS_POPUP,
            x,
            y,
            kAlertWidth,
            kAlertHeight,
            NULL,
            NULL,
            instance,
            request);
        if (!window)
            return;

        ShowWindow(window, SW_SHOWNORMAL);
        UpdateWindow(window);
        SetForegroundWindow(window);

        MSG message = {};
        while (GetMessageW(&message, NULL, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    DWORD WINAPI AlertThread(LPVOID parameter)
    {
        AlertRequest* request =
            reinterpret_cast<AlertRequest*>(parameter);
        RunAlert(request);
        delete request;
        return 0;
    }

    AlertRequest* CreateRequest(
        const std::wstring& title,
        const std::wstring& message,
        const std::wstring& detail,
        int milliseconds)
    {
        AlertRequest* request = new AlertRequest();
        request->title = title;
        request->message = message;
        request->detail = detail;
        request->durationMs =
            milliseconds > 250 ? (DWORD)milliseconds : 250;
        request->startedAt = 0;
        return request;
    }
}

void ShowProtectionMessage(const std::wstring& text)
{
    ShowProtectionAlertTimed(
        L"Aviso de prote\u00e7\u00e3o",
        text,
        L"L2 Security",
        3000);
}

void ShowProtectionMessageTimed(const std::wstring& text, int seconds)
{
    ShowProtectionAlertTimed(
        L"Aviso de prote\u00e7\u00e3o",
        text,
        L"L2 Security",
        seconds * 1000);
}

void ShowProtectionAlertTimed(
    const std::wstring& title,
    const std::wstring& message,
    const std::wstring& detail,
    int milliseconds)
{
    AlertRequest* request =
        CreateRequest(title, message, detail, milliseconds);

    HANDLE thread = CreateThread(
        NULL,
        0,
        AlertThread,
        request,
        0,
        NULL);
    if (!thread)
    {
        delete request;
        return;
    }

    CloseHandle(thread);
}

void ShowProtectionAlertBlocking(
    const std::wstring& title,
    const std::wstring& message,
    const std::wstring& detail,
    int milliseconds)
{
    AlertRequest* request =
        CreateRequest(title, message, detail, milliseconds);
    RunAlert(request);
    delete request;
}
