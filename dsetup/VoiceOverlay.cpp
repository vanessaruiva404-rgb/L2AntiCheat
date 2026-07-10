#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include "VoiceClient.h"
#include "VoiceOverlay.h"
#include "VoiceState.h"
#include "VoiceConfig.h"
#include "AccountLogin.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")

extern VoiceClient g_VoiceClient;
extern "C" void SendBypassToServer(const wchar_t* bypass);

namespace
{
    static HINSTANCE g_hInstance = NULL;
    static HWND g_hSettings = NULL;
    static HWND g_hSpeakers = NULL;

    static HANDLE g_hOverlayThread = NULL;
    static DWORD g_overlayThreadId = 0;

    static bool g_visible = false;
    static bool g_capturePttKey = false;
    static bool g_capturePanelHotkey = false;
    static bool g_dragSettings = false;
    static bool g_dragSpeakers = false;
    static bool g_introVisible = false;
    static bool g_openPanelHotkeyWasDown = false;
    static DWORD g_introStartedAt = 0;
    static POINT g_dragOffset = { 0, 0 };

    static const int TIMER_SPEAKERS_REFRESH = 1;
    static const int TIMER_INTRO = 2;
    static const int TIMER_HOTKEY_POLL = 3;
    static const DWORD INTRO_DURATION_MS = 4200;

#define WM_L2VOICE_OVERLAY_SHOW   (WM_APP + 501)
#define WM_L2VOICE_OVERLAY_HIDE   (WM_APP + 502)
#define WM_L2VOICE_OVERLAY_TOGGLE (WM_APP + 503)
#define WM_L2VOICE_SPEAKERS_DIRTY (WM_APP + 504)

    static const int PANEL_W = 306;
    static const int PANEL_H = 368;
    static const int PANEL_MIN_W = 296;
    static const int PANEL_MIN_H = 354;
    static const int PANEL_RESIZE_GRIP = 10;
    static const int SPEAKERS_W = 260;
    static const int SPEAKER_ROW_H = 24;
    static const int HEADER_H = 38;

    static int g_panelW = PANEL_W;
    static int g_panelH = PANEL_H;

    static COLORREF C_KEY = RGB(255, 0, 255);
    static COLORREF C_BG = RGB(15, 14, 19);
    static COLORREF C_PANEL = RGB(24, 22, 28);
    static COLORREF C_PANEL_2 = RGB(31, 28, 35);
    static COLORREF C_CARD = RGB(31, 28, 35);
    static COLORREF C_CARD_HOVER = RGB(39, 35, 43);
    static COLORREF C_STROKE = RGB(136, 61, 18);
    static COLORREF C_STROKE_SOFT = RGB(67, 57, 51);
    static COLORREF C_GOLD = RGB(255, 84, 26);
    static COLORREF C_GOLD_2 = RGB(255, 132, 77);
    static COLORREF C_GOLD_DARK = RGB(211, 62, 21);
    static COLORREF C_TEXT = RGB(246, 242, 238);
    static COLORREF C_DIM = RGB(180, 169, 163);
    static COLORREF C_MUTED = RGB(238, 86, 92);
    static COLORREF C_GREEN = RGB(68, 214, 121);
    static COLORREF C_BLUE = RGB(255, 132, 77);

    struct OverlayHotkey
    {
        UINT modifiers;
        UINT vk;
    };

    struct ButtonRect
    {
        int id;
        RECT rc;
    };

    enum VoiceButtonId
    {
        BTN_NONE = 0,
        BTN_PARTY,
        BTN_GLOBAL,
        BTN_PTT,
        BTN_OPEN,
        BTN_PTT_KEY,
        BTN_PANEL_KEY,
        BTN_MIC,
        BTN_AUTO_PANEL,
        BTN_SPEAKERS,
        BTN_SUPPORT
    };

    enum MiniIcon
    {
        ICON_NONE = 0,
        ICON_DOT,
        ICON_MIC,
        ICON_KEY,
        ICON_EYE,
        ICON_USERS
    };

    static ButtonRect g_buttons[] =
    {
        { BTN_PARTY,      { 12,  58, 116, 82 } },
        { BTN_GLOBAL,     { 136, 58, 240, 82 } },
        { BTN_PTT,        { 12,  105,116, 129 } },
        { BTN_OPEN,       { 136,105,240, 129 } },
        { BTN_PTT_KEY,    { 12,  152,240, 176 } },
        { BTN_PANEL_KEY,  { 12,  183,240, 207 } },
        { BTN_MIC,        { 12,  230, 78, 254 } },
        { BTN_AUTO_PANEL, { 93,  230,159, 254 } },
        { BTN_SPEAKERS,   { 174, 230,240, 254 } },
        { BTN_SUPPORT,    { 12,  308, 240, 332 } }
    };

    struct SpeakerRow
    {
        int objectId;
        RECT rect;
    };

    static OverlayHotkey g_panelHotkey = { 0, VK_F9 };
    static int g_hoverButton = BTN_NONE;
    static int g_pressedButton = BTN_NONE;
    static int g_hoverSpeakerObjectId = 0;
    static SpeakerRow g_speakerRows[16];
    static int g_speakerRowCount = 0;
    static RECT g_dragHandleRect = { 0, 0, 0, 0 };

    static DWORD WINAPI VoiceOverlayThread(LPVOID param);
    static LRESULT CALLBACK VoiceSettingsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK VoiceSpeakersProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static void UpdateSpeakersWindowVisibility(HWND hwnd);
    

    static bool IsLineageWindowActive()
    {
        HWND fg = GetForegroundWindow();
        if (!fg)
            return false;

        DWORD pid = 0;
        GetWindowThreadProcessId(fg, &pid);

        if (pid == 0)
            return false;

        DWORD myPid = GetCurrentProcessId();

        return pid == myPid;
    }
    static bool PtIn(const RECT& rc, int x, int y)
    {
        POINT p = { x, y };
        return PtInRect(&rc, p) != FALSE;
    }

    static RECT MakeRect(int l, int t, int r, int b)
    {
        RECT rc = { l, t, r, b };
        return rc;
    }

    static bool IsMainPanelVisible()
    {
        return g_hSettings && IsWindow(g_hSettings) && IsWindowVisible(g_hSettings);
    }

    static std::string GetOverlayIniPath()
    {
        char appData[MAX_PATH];

        if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appData)))
            return "voice.ini";

        char dir[MAX_PATH];
        sprintf_s(dir, sizeof(dir), "%s\\LineageII", appData);
        CreateDirectoryA(dir, NULL);

        char file[MAX_PATH];
        sprintf_s(file, sizeof(file), "%s\\voice.ini", dir);
        return file;
    }

    static bool IsModifierVk(UINT vk)
    {
        return vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU ||
            vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
            vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT ||
            vk == VK_LWIN || vk == VK_RWIN;
    }

    static UINT CurrentModifierFlags()
    {
        UINT mods = 0;

        if ((GetAsyncKeyState(VK_MENU) & 0x8000) != 0)
            mods |= MOD_ALT;

        if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0)
            mods |= MOD_CONTROL;

        if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0)
            mods |= MOD_SHIFT;

        if ((GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0)
            mods |= MOD_WIN;

        return mods;
    }

    static UINT NormalizeVk(UINT vk)
    {
        if (vk == VK_LMENU || vk == VK_RMENU) return VK_MENU;
        if (vk == VK_LCONTROL || vk == VK_RCONTROL) return VK_CONTROL;
        if (vk == VK_LSHIFT || vk == VK_RSHIFT) return VK_SHIFT;
        return vk;
    }

    static std::string KeyToText(UINT vk)
    {
        vk = NormalizeVk(vk);

        if (vk == 0) return "NONE";
        if (vk == VK_MENU) return "ALT";
        if (vk == VK_CONTROL) return "CTRL";
        if (vk == VK_SHIFT) return "SHIFT";
        if (vk == VK_SPACE) return "SPACE";
        if (vk == VK_TAB) return "TAB";
        if (vk == VK_CAPITAL) return "CAPS";
        if (vk == VK_ESCAPE) return "ESC";
        if (vk == VK_RETURN) return "ENTER";
        if (vk == VK_BACK) return "BACKSPACE";
        if (vk == VK_INSERT) return "INSERT";
        if (vk == VK_DELETE) return "DELETE";
        if (vk == VK_HOME) return "HOME";
        if (vk == VK_END) return "END";
        if (vk == VK_PRIOR) return "PAGE UP";
        if (vk == VK_NEXT) return "PAGE DOWN";

        UINT scan = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC) << 16;

        if (vk == VK_LEFT || vk == VK_UP || vk == VK_RIGHT || vk == VK_DOWN ||
            vk == VK_INSERT || vk == VK_DELETE || vk == VK_HOME || vk == VK_END ||
            vk == VK_PRIOR || vk == VK_NEXT)
        {
            scan |= 0x01000000;
        }

        char name[64];
        if (GetKeyNameTextA((LONG)scan, name, sizeof(name)) > 0)
            return name;

        char fallback[32];
        sprintf_s(fallback, sizeof(fallback), "VK_%u", vk);
        return fallback;
    }

    static std::string HotkeyToText(const OverlayHotkey& hk)
    {
        std::string out;

        if ((hk.modifiers & MOD_CONTROL) != 0) out += "CTRL+";
        if ((hk.modifiers & MOD_ALT) != 0) out += "ALT+";
        if ((hk.modifiers & MOD_SHIFT) != 0) out += "SHIFT+";
        if ((hk.modifiers & MOD_WIN) != 0) out += "WIN+";

        out += KeyToText(hk.vk);
        return out;
    }

    static bool IsHotkeyValid(const OverlayHotkey& hk)
    {
        return hk.vk != 0 && hk.vk != VK_ESCAPE && !IsModifierVk(hk.vk);
    }
 
    static void LoadOverlayHotkey()
    {
        VoiceConfig config = VoiceState::GetConfig();

        std::string ini = GetOverlayIniPath();
        UINT defaultVk = config.OpenPanelKey > 0 ? (UINT)config.OpenPanelKey : (UINT)VK_F9;

        g_panelHotkey.modifiers = GetPrivateProfileIntA("VoiceKeys", "OpenPanelModifiers", 0, ini.c_str());
        g_panelHotkey.vk = GetPrivateProfileIntA("VoiceKeys", "OpenPanel", defaultVk, ini.c_str());

        if (!IsHotkeyValid(g_panelHotkey))
        {
            g_panelHotkey.modifiers = 0;
            g_panelHotkey.vk = defaultVk;
        }

        config.OpenPanelKey = (int)g_panelHotkey.vk;
        VoiceState::SetConfig(config);
    }

 

    static LRESULT HitTestResizeBorder(HWND hwnd, LPARAM lParam)
    {
        RECT rc;
        GetWindowRect(hwnd, &rc);

        int x = (int)(short)LOWORD(lParam);
        int y = (int)(short)HIWORD(lParam);

        bool left = x >= rc.left && x < rc.left + PANEL_RESIZE_GRIP;
        bool right = x <= rc.right && x > rc.right - PANEL_RESIZE_GRIP;
        bool top = y >= rc.top && y < rc.top + PANEL_RESIZE_GRIP;
        bool bottom = y <= rc.bottom && y > rc.bottom - PANEL_RESIZE_GRIP;

        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;

        return HTCLIENT;
    }

    static bool IsPanelHotkeyDown()
    {
        if (!IsHotkeyValid(g_panelHotkey))
            return false;

        if ((GetAsyncKeyState((int)g_panelHotkey.vk) & 0x8000) == 0)
            return false;

        return CurrentModifierFlags() == g_panelHotkey.modifiers;
    }

    static HFONT MakeFont(int size, bool bold, const char* face = "Segoe UI")
    {
        return CreateFontA(size, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH, face);
    }

    static void FillRound(HDC hdc, RECT rc, COLORREF fill, int radius, COLORREF border, int borderSize = 1)
    {
        HBRUSH brush = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, borderSize, border);
        HGDIOBJ oldBrush = SelectObject(hdc, brush);
        HGDIOBJ oldPen = SelectObject(hdc, pen);

        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
        DeleteObject(pen);
    }

    static void FillRectColor(HDC hdc, RECT rc, COLORREF color)
    {
        HBRUSH brush = CreateSolidBrush(color);
        FillRect(hdc, &rc, brush);
        DeleteObject(brush);
    }

    static void DrawTextBox(HDC hdc, RECT rc, const char* text, COLORREF color, int size, bool bold, UINT format)
    {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, color);

        HFONT font = MakeFont(size, bold);
        HGDIOBJ oldFont = SelectObject(hdc, font);

        DrawTextA(hdc, text, -1, &rc, format | DT_END_ELLIPSIS);

        SelectObject(hdc, oldFont);
        DeleteObject(font);
    }

    static void DrawLeft(HDC hdc, int x, int y, const char* text, COLORREF color, int size, bool bold)
    {
        RECT rc = { x, y, 1000, y + size + 12 };
        DrawTextBox(hdc, rc, text, color, size, bold, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    }

    static void DrawStatusDot(HDC hdc, int x, int y, COLORREF color)
    {
        RECT rc = { x, y, x + 9, y + 9 };
        FillRound(hdc, rc, color, 9, color);
    }

    static void DrawIcon(HDC hdc, RECT rc, MiniIcon icon, COLORREF color);

    static void DrawVoiceBadge(HDC hdc, int x, int y)
    {
        RECT badge = { x, y, x + 34, y + 34 };
        FillRound(hdc, badge, C_GOLD, 10, C_GOLD_2, 1);

        RECT iconRc = { x + 7, y + 6, x + 27, y + 26 };
        DrawIcon(hdc, iconRc, ICON_MIC, RGB(255, 255, 255));
    }

    static void DrawIcon(HDC hdc, RECT rc, MiniIcon icon, COLORREF color)
    {
        HPEN pen = CreatePen(PS_SOLID, 2, color);
        HBRUSH brush = CreateSolidBrush(color);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        HGDIOBJ oldBrush = SelectObject(hdc, brush);

        int cx = (rc.left + rc.right) / 2;
        int cy = (rc.top + rc.bottom) / 2;

        if (icon == ICON_DOT)
        {
            Ellipse(hdc, cx - 4, cy - 4, cx + 4, cy + 4);
        }
        else if (icon == ICON_MIC)
        {
            RoundRect(hdc, cx - 4, cy - 8, cx + 4, cy + 5, 5, 5);
            MoveToEx(hdc, cx - 8, cy - 1, NULL);
            LineTo(hdc, cx - 8, cy + 2);
            Arc(hdc, cx - 9, cy - 6, cx + 9, cy + 10, cx - 9, cy + 1, cx + 9, cy + 1);
            MoveToEx(hdc, cx, cy + 8, NULL);
            LineTo(hdc, cx, cy + 12);
        }
        else if (icon == ICON_KEY)
        {
            Ellipse(hdc, cx - 9, cy - 5, cx + 1, cy + 5);
            MoveToEx(hdc, cx, cy, NULL);
            LineTo(hdc, cx + 10, cy);
            MoveToEx(hdc, cx + 6, cy, NULL);
            LineTo(hdc, cx + 6, cy + 5);
        }
        else if (icon == ICON_EYE)
        {
            Arc(hdc, cx - 11, cy - 7, cx + 11, cy + 8, cx - 11, cy, cx + 11, cy);
            Arc(hdc, cx - 11, cy - 8, cx + 11, cy + 7, cx + 11, cy, cx - 11, cy);
            Ellipse(hdc, cx - 3, cy - 3, cx + 3, cy + 3);
        }
        else if (icon == ICON_USERS)
        {
            Ellipse(hdc, cx - 7, cy - 9, cx + 1, cy - 1);
            Ellipse(hdc, cx + 2, cy - 7, cx + 8, cy - 1);
            Arc(hdc, cx - 11, cy - 1, cx + 5, cy + 14, cx - 10, cy + 8, cx + 4, cy + 8);
            Arc(hdc, cx, cy, cx + 12, cy + 12, cx, cy + 7, cx + 12, cy + 7);
        }

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
        DeleteObject(pen);
    }

    static void InvalidateSettings()
    {
        if (g_hSettings && IsWindow(g_hSettings))
            InvalidateRect(g_hSettings, NULL, FALSE);
    }

    static void InvalidateSpeakers()
    {
        if (g_hSpeakers && IsWindow(g_hSpeakers))
            InvalidateRect(g_hSpeakers, NULL, FALSE);
    }

    static void PaintBuffered(HWND hwnd, void (*paintFn)(HDC, RECT))
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HGDIOBJ oldBmp = SelectObject(mem, bmp);

        paintFn(mem, rc);
        BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);

        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);

        EndPaint(hwnd, &ps);
    }

    static void LayoutSettingsButtons(const RECT& client)
    {
        int w = client.right - client.left;
        int h = client.bottom - client.top;

        if (w < PANEL_MIN_W) w = PANEL_MIN_W;
        if (h < PANEL_MIN_H) h = PANEL_MIN_H;

        // Layout "contra idiota": todos os elementos têm faixas fixas e seguras.
        // O redimensionamento nunca joga botão em cima de texto/legenda.
        const int margin = 14;
        const int gap = 12;
        const int btnH = 28;
        const int fullR = w - margin;
        const int colW = (w - margin * 2 - gap) / 2;
        const int x1 = margin;
        const int x2 = margin + colW + gap;

        const int yCanal = 76;
        const int yModo = 130;
        const int yPttKey = 184;
        const int yPanelKey = 218;
        const int yOptions = 270;

        const int optGap = 9;
        const int optW = (w - margin * 2 - optGap * 2) / 3;

        g_buttons[0].rc = MakeRect(x1, yCanal, x1 + colW, yCanal + btnH);
        g_buttons[1].rc = MakeRect(x2, yCanal, x2 + colW, yCanal + btnH);
        g_buttons[2].rc = MakeRect(x1, yModo, x1 + colW, yModo + btnH);
        g_buttons[3].rc = MakeRect(x2, yModo, x2 + colW, yModo + btnH);
        g_buttons[4].rc = MakeRect(margin, yPttKey, fullR, yPttKey + btnH);
        g_buttons[5].rc = MakeRect(margin, yPanelKey, fullR, yPanelKey + btnH);
        g_buttons[6].rc = MakeRect(margin, yOptions, margin + optW, yOptions + btnH);
        g_buttons[7].rc = MakeRect(margin + optW + optGap, yOptions, margin + optW * 2 + optGap, yOptions + btnH);
        g_buttons[8].rc = MakeRect(margin + optW * 2 + optGap * 2, yOptions, fullR, yOptions + btnH);

        const int ySupport = 312;
        g_buttons[9].rc = MakeRect(margin, ySupport, fullR, ySupport + btnH);
    }

    static void LayoutSettingsButtonsForWindow(HWND hwnd)
    {
        RECT client;
        GetClientRect(hwnd, &client);
        LayoutSettingsButtons(client);
    }

    static int HitButton(int x, int y)
    {
        for (size_t i = 0; i < sizeof(g_buttons) / sizeof(g_buttons[0]); ++i)
        {
            if (PtIn(g_buttons[i].rc, x, y))
                return g_buttons[i].id;
        }

        return BTN_NONE;
    }

    static const ButtonRect* FindButton(int id)
    {
        for (size_t i = 0; i < sizeof(g_buttons) / sizeof(g_buttons[0]); ++i)
        {
            if (g_buttons[i].id == id)
                return &g_buttons[i];
        }

        return NULL;
    }

    static void DrawPill(HDC hdc, RECT rc, const char* text, bool active, int id, MiniIcon icon = ICON_NONE)
    {
        COLORREF fill = active ? C_GOLD : C_CARD;
        COLORREF border = active ? C_GOLD_2 : C_STROKE_SOFT;
        COLORREF textColor = active ? RGB(255, 255, 255) : C_TEXT;

        if (g_hoverButton == id)
        {
            fill = active ? RGB(255, 111, 47) : C_CARD_HOVER;
            border = active ? RGB(255, 163, 112) : RGB(121, 78, 45);
        }

        if (g_pressedButton == id)
            fill = active ? C_GOLD_DARK : RGB(34, 30, 37);

        FillRound(hdc, rc, fill, 8, border, 1);

        if (icon != ICON_NONE)
        {
            RECT iconRc = { rc.left + 6, rc.top + 5, rc.left + 20, rc.bottom - 5 };
            DrawIcon(hdc, iconRc, icon, textColor);
            rc.left += 19;
        }

        DrawTextBox(hdc, rc, text, textColor, 9, true, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    static void DrawSectionLabel(HDC hdc, int x, int y, const char* text)
    {
        DrawLeft(hdc, x, y, text, C_DIM, 10, true);
    }

    static void StartIntroMessage()
    {
        g_introVisible = true;
        g_introStartedAt = GetTickCount();

        if (g_hSettings && IsWindow(g_hSettings))
        {
            KillTimer(g_hSettings, TIMER_INTRO);
            SetTimer(g_hSettings, TIMER_INTRO, 100, NULL);
            InvalidateSettings();
        }
    }

    static void StopIntroMessage()
    {
        g_introVisible = false;

        if (g_hSettings && IsWindow(g_hSettings))
        {
            KillTimer(g_hSettings, TIMER_INTRO);
            InvalidateSettings();
        }
    }

    static void ShowOverlay()
    {

        if (!g_hSettings || !IsWindow(g_hSettings))
            return;
        if (!IsLineageWindowActive())
        {
            g_visible = true;
            return;
        }
        VoiceConfig config = VoiceState::GetConfig();

        ShowWindow(g_hSettings, SW_SHOW);
        SetWindowPos(g_hSettings, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);

        if (g_hSpeakers && IsWindow(g_hSpeakers))
        {
            // A janela de falantes é independente do painel principal.
            // Se alguém estiver falando e a opção FALANTES estiver ativa,
            // ela deve aparecer mesmo com o painel VOICE fechado.
            if (config.SpeakersVisible)
                UpdateSpeakersWindowVisibility(g_hSpeakers);
            else
                ShowWindow(g_hSpeakers, SW_HIDE);
        }

        SetForegroundWindow(g_hSettings);
        UpdateWindow(g_hSettings);

        g_visible = true;
        StartIntroMessage();
    }

    static void HideOverlay()
    {
        StopIntroMessage();

        if (g_hSettings && IsWindow(g_hSettings))
            ShowWindow(g_hSettings, SW_HIDE);

        // Não esconder a janela de falantes ao fechar o painel principal.
        // Ela só some quando ninguém está falando ou quando FALANTES está OFF.
        if (g_hSpeakers && IsWindow(g_hSpeakers))
            UpdateSpeakersWindowVisibility(g_hSpeakers);

        g_visible = false;
    }

    static void ToggleOverlayVisible()
    {
        if (IsMainPanelVisible())
            HideOverlay();
        else
            ShowOverlay();
    }

    static void PollOpenPanelHotkey()
    {
        bool down = IsPanelHotkeyDown();

        if (!IsLineageWindowActive())
        {
            g_openPanelHotkeyWasDown = down;
            return;
        }

        if (down && !g_openPanelHotkeyWasDown && !g_capturePanelHotkey && !g_capturePttKey)
            ToggleOverlayVisible();

        g_openPanelHotkeyWasDown = down;
    }

    static void PaintSettings(HDC hdc, RECT client)
    {
        VoiceConfig config = VoiceState::GetConfig();
        LayoutSettingsButtons(client);

        FillRound(hdc, client, C_BG, 15, C_STROKE, 1);
        RECT accent = { 0, 0, client.right, 4 };
        FillRectColor(hdc, accent, C_GOLD);

        RECT header = { 0, 0, client.right, HEADER_H };
        FillRound(hdc, header, C_BG, 15, C_BG);

        DrawVoiceBadge(hdc, 14, 8);
        DrawLeft(hdc, 56, 7, "VOZ DO JOGO", C_TEXT, 15, true);
        DrawLeft(hdc, 56, 25, "canal, modo e atalhos", C_DIM, 9, false);

        std::string panelKey = HotkeyToText(g_panelHotkey);
        RECT keyRc = { client.right - 104, 9, client.right - 14, 31 };
        FillRound(hdc, keyRc, C_PANEL_2, 8, C_STROKE_SOFT);
        DrawTextBox(hdc, keyRc, panelKey.c_str(), C_GOLD, 10, true, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

        // O aviso inicial não ocupa espaço no meio do formulário para não cobrir os textos.

        DrawSectionLabel(hdc, 14, 60, "1. CANAL DE VOZ");
        DrawPill(hdc, g_buttons[0].rc, "PARTY", config.Channel == VoiceChannelType::Party, BTN_PARTY);
        DrawPill(hdc, g_buttons[1].rc, "GLOBAL", config.Channel == VoiceChannelType::Global, BTN_GLOBAL);

        DrawSectionLabel(hdc, 14, 114, "2. COMO FALAR");
        DrawPill(hdc, g_buttons[2].rc, "APERTE P/ FALAR", config.TalkMode == VoiceTalkMode::PushToTalk, BTN_PTT);
        DrawPill(hdc, g_buttons[3].rc, "MIC ABERTO", config.TalkMode == VoiceTalkMode::VoiceActivation, BTN_OPEN);

        char line[160];
        DrawSectionLabel(hdc, 14, 168, "3. ATALHOS");

        if (g_capturePttKey)
            sprintf_s(line, sizeof(line), "PRESSIONE A TECLA DO PTT...");
        else
            sprintf_s(line, sizeof(line), "PTT  %s", KeyToText((UINT)config.PushToTalkKey).c_str());

        DrawPill(hdc, g_buttons[4].rc, line, g_capturePttKey, BTN_PTT_KEY, ICON_KEY);

        if (g_capturePanelHotkey)
            sprintf_s(line, sizeof(line), "PRESSIONE UMA TECLA OU COMBO...");
        else
            sprintf_s(line, sizeof(line), "PAINEL  %s", panelKey.c_str());

        DrawPill(hdc, g_buttons[5].rc, line, g_capturePanelHotkey, BTN_PANEL_KEY, ICON_KEY);

        DrawSectionLabel(hdc, 14, g_buttons[6].rc.top - 16, "4. OPCOES RAPIDAS");
        DrawPill(hdc, g_buttons[6].rc, config.Muted ? "MUTADO" : "MIC", !config.Muted, BTN_MIC, ICON_MIC);
        DrawPill(hdc, g_buttons[7].rc, config.PanelVisible ? "AUTO" : "MANUAL", config.PanelVisible, BTN_AUTO_PANEL, ICON_EYE);
        DrawPill(hdc, g_buttons[8].rc, config.SpeakersVisible ? "FALANTES" : "OFF", config.SpeakersVisible, BTN_SPEAKERS, ICON_USERS);

        DrawSectionLabel(hdc, 14, g_buttons[9].rc.top - 16, "5. CENTRAL DE SUPORTE");
        DrawPill(hdc, g_buttons[9].rc, "FALAR COM ADM / ADMIN", false, BTN_SUPPORT, ICON_USERS);

        const bool inGame = AccountLogin_IsGameSessionActive();
        DrawStatusDot(hdc, 13, client.bottom - 13, !inGame || config.Muted ? C_MUTED : C_GREEN);
        DrawLeft(
            hdc,
            29,
            client.bottom - 19,
            !inGame ? "aguardando personagem" : (config.Muted ? "microfone mutado" : "voz pronta"),
            C_DIM,
            9,
            false);

        RECT foot = { client.right - 104, client.bottom - 20, client.right - 10, client.bottom - 4 };
        DrawTextBox(hdc, foot, "ESC cancela", C_DIM, 8, false, DT_RIGHT | DT_SINGLELINE | DT_VCENTER);
    }

    static void ApplyButton(int id)
    {
        VoiceConfig config = VoiceState::GetConfig();

        switch (id)
        {
        case BTN_PARTY:
            config.Channel = VoiceChannelType::Party;
            VoiceState::SetConfig(config);
            g_VoiceClient.SetChannelParty();
            break;

        case BTN_GLOBAL:
            config.Channel = VoiceChannelType::Global;
            VoiceState::SetConfig(config);
            g_VoiceClient.SetChannelGlobal();
            break;

        case BTN_PTT:
            config.TalkMode = VoiceTalkMode::PushToTalk;
            VoiceState::SetConfig(config);
            g_VoiceClient.SetTalkMode(VoiceTalkMode::PushToTalk);
            break;

        case BTN_OPEN:
            config.TalkMode = VoiceTalkMode::VoiceActivation;
            VoiceState::SetConfig(config);
            g_VoiceClient.SetTalkMode(VoiceTalkMode::VoiceActivation);
            break;

        case BTN_PTT_KEY:
            g_capturePttKey = true;
            g_capturePanelHotkey = false;
            SetFocus(g_hSettings);
            break;

        case BTN_PANEL_KEY:
            g_capturePanelHotkey = true;
            g_capturePttKey = false;
            SetFocus(g_hSettings);
            break;

        case BTN_MIC:
            config.Muted = !config.Muted;
            VoiceState::SetConfig(config);
            g_VoiceClient.SetMuted(config.Muted);
            break;

        case BTN_AUTO_PANEL:
            config.PanelVisible = !config.PanelVisible;
            VoiceState::SetConfig(config);
            break;

        case BTN_SPEAKERS:
            config.SpeakersVisible = !config.SpeakersVisible;
            VoiceState::SetConfig(config);

            if (g_hSpeakers && IsWindow(g_hSpeakers))
            {
                if (config.SpeakersVisible)
                    UpdateSpeakersWindowVisibility(g_hSpeakers);
                else
                    ShowWindow(g_hSpeakers, SW_HIDE);
            }

            break;

        case BTN_SUPPORT:
            SendBypassToServer(L"suporte");
            break;
        }

        InvalidateSettings();
        InvalidateSpeakers();
    }

    static int HitSpeakerRow(int x, int y)
    {
        for (int i = 0; i < g_speakerRowCount; ++i)
        {
            if (PtIn(g_speakerRows[i].rect, x, y))
                return g_speakerRows[i].objectId;
        }

        return 0;
    }

    static bool HitDragHandle(int x, int y)
    {
        return PtIn(g_dragHandleRect, x, y);
    }

    static void DrawDragDots(HDC hdc, int x, int y, COLORREF color)
    {
        HBRUSH brush = CreateSolidBrush(color);
        HPEN pen = CreatePen(PS_NULL, 0, color);

        HGDIOBJ oldBrush = SelectObject(hdc, brush);
        HGDIOBJ oldPen = SelectObject(hdc, pen);

        const int r = 1;
        const int gap = 5;

        for (int row = 0; row < 2; ++row)
        {
            for (int col = 0; col < 3; ++col)
            {
                int cx = x + col * gap;
                int cy = y + row * gap;
                Ellipse(hdc, cx - r, cy - r, cx + r + 1, cy + r + 1);
            }
        }

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
        DeleteObject(pen);
    }

    static void HideSpeakersWindow(HWND hwnd)
    {
        if (g_dragSpeakers)
        {
            g_dragSpeakers = false;
            ReleaseCapture();
        }

        ShowWindow(hwnd, SW_HIDE);
        g_speakerRowCount = 0;
        g_hoverSpeakerObjectId = 0;
        g_dragHandleRect = MakeRect(0, 0, 0, 0);
    }

    static void UpdateSpeakersWindowVisibility(HWND hwnd)
    {
        if (!hwnd || !IsWindow(hwnd))
            return;

        if (!IsLineageWindowActive())
        {
            HideSpeakersWindow(hwnd);
            return;
        }

        VoiceConfig config = VoiceState::GetConfig();

        // Não depende mais do painel principal estar aberto.
        // FALANTES ON + lista de pessoas falando = janela visível.
        if (!config.SpeakersVisible)
        {
            HideSpeakersWindow(hwnd);
            return;
        }

        VoiceState::CleanupSpeakers();
        std::vector<VoiceSpeaker> speakers = VoiceState::GetSpeakers();

        if (speakers.empty())
        {
            // Se o jogador parou de falar enquanto você arrastava a janela,
            // cancela o arrasto para não ficar preso segurando uma janela invisível.
            HideSpeakersWindow(hwnd);
            return;
        }

        const int maxRows = 6;
        const int gap = 1;
        const int headerH = 22;
        const int paddingY = 4;

        int visibleRows = (int)speakers.size();
        if (visibleRows > maxRows)
            visibleRows = maxRows;

        int width = SPEAKERS_W;
        int height = headerH + paddingY + visibleRows * SPEAKER_ROW_H + (visibleRows - 1) * gap + 4;

        if (height < 48)
            height = 48;

        RECT rc;
        GetWindowRect(hwnd, &rc);

        SetWindowPos(hwnd, HWND_TOPMOST, rc.left, rc.top, width, height, SWP_NOACTIVATE | SWP_SHOWWINDOW);
        InvalidateRect(hwnd, NULL, TRUE);
    }

    static void PaintSpeakers(HDC hdc, RECT client)
    {
        FillRectColor(hdc, client, C_KEY);

        VoiceState::CleanupSpeakers();
        std::vector<VoiceSpeaker> speakers = VoiceState::GetSpeakers();

        g_speakerRowCount = 0;
        g_dragHandleRect = MakeRect(0, 0, 0, 0);

        if (speakers.empty())
            return;

        const int margin = 4;
    const int headerH = 22;
    const int gap = 1;
    const int maxRows = 6;
    const int width = client.right - margin * 2;

    RECT panel = { margin, 0, client.right - margin, client.bottom - 1 };
    FillRound(hdc, panel, C_BG, 8, C_STROKE, 1);

    RECT header = { margin, 0, client.right - margin, headerH };
    FillRound(hdc, header, C_PANEL, 8, C_STROKE_SOFT, 1);
    g_dragHandleRect = header;

    RECT titleRc = { header.left + 10, header.top, header.right - 10, header.bottom };
    DrawTextBox(hdc, titleRc, "FALANDO AGORA", C_TEXT, 9, true,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    char countText[32];
    sprintf_s(countText, sizeof(countText), "%d", (int)speakers.size());
    RECT countRc = { header.right - 34, header.top + 4, header.right - 10, header.bottom - 4 };
    FillRound(hdc, countRc, C_GOLD, 7, C_GOLD_2, 1);
    DrawTextBox(hdc, countRc, countText, RGB(255, 255, 255), 8, true,
        DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    int visibleRows = (int)speakers.size();
    if (visibleRows > maxRows)
        visibleRows = maxRows;

    int y = headerH + 4;

    for (int i = 0; i < visibleRows; ++i)
    {
        const VoiceSpeaker& s = speakers[i];
        bool muted = VoiceState::IsPlayerMuted(s.objectId);
        bool hover = g_hoverSpeakerObjectId == s.objectId;

        RECT row = { margin + 4, y, margin + width - 4, y + SPEAKER_ROW_H };
        COLORREF rowFill = hover ? C_CARD_HOVER : C_PANEL_2;
        COLORREF rowBorder = hover ? RGB(121, 78, 45) : C_STROKE_SOFT;

        FillRound(hdc, row, rowFill, 5, rowBorder, 1);

        RECT dot = { row.left + 8, row.top + 8, row.left + 14, row.top + 14 };
        FillRound(hdc, dot, muted ? C_MUTED : C_GREEN, 6, muted ? C_MUTED : C_GREEN, 1);

        char name[190];
        sprintf_s(name, sizeof(name), "%s%s", muted ? "[MUTADO] " : "", s.name.c_str());

        RECT nameRc = { row.left + 22, row.top, row.right - 72, row.bottom };
        DrawTextBox(hdc, nameRc, name, muted ? C_MUTED : C_TEXT,
            10, true, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        RECT hintRc = { row.right - 68, row.top, row.right - 8, row.bottom };
        DrawTextBox(hdc, hintRc, muted ? "ativar" : "silenciar", hover ? C_GOLD_2 : C_DIM,
            8, false, DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

        if (g_speakerRowCount < 16)
        {
            g_speakerRows[g_speakerRowCount].objectId = s.objectId;
            g_speakerRows[g_speakerRowCount].rect = row;
            ++g_speakerRowCount;
        }

        y += SPEAKER_ROW_H + gap;
    }
}
    static void SavePanelSize(HWND hwnd)
    {
        if (!hwnd || !IsWindow(hwnd))
            return;

        RECT rc;
        GetWindowRect(hwnd, &rc);

        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w < PANEL_MIN_W) w = PANEL_MIN_W;
        if (h < PANEL_MIN_H) h = PANEL_MIN_H;

        g_panelW = w;
        g_panelH = h;

        std::string ini = GetOverlayIniPath();
        char tmp[32];

        sprintf_s(tmp, sizeof(tmp), "%d", g_panelW);
        WritePrivateProfileStringA("VoicePanel", "Width", tmp, ini.c_str());

        sprintf_s(tmp, sizeof(tmp), "%d", g_panelH);
        WritePrivateProfileStringA("VoicePanel", "Height", tmp, ini.c_str());
    }
    static void TogglePlayerMuteByPoint(int x, int y)
    {
        int objectId = HitSpeakerRow(x, y);

        if (objectId <= 0)
            return;

        bool muted = !VoiceState::IsPlayerMuted(objectId);
        VoiceState::SetPlayerMuted(objectId, muted);
        g_VoiceClient.SetPlayerMuted(objectId, muted);

        InvalidateSpeakers();
    }

    static void SaveWindowPos(HWND hwnd, bool speakers)
    {
        if (!hwnd || !IsWindow(hwnd))
            return;

        RECT rc;
        GetWindowRect(hwnd, &rc);

        if (speakers)
            VoiceState::SetSpeakersPos(rc.left, rc.top);
        else
        {
            VoiceState::SetSettingsPos(rc.left, rc.top);
            SavePanelSize(hwnd);
        }
    }

    static void CommitCapturedPttKey(UINT vk)
    {
        if (vk == VK_ESCAPE)
            return;

        vk = NormalizeVk(vk);

        if (vk == 0 || IsModifierVk(vk))
            return;

        VoiceConfig config = VoiceState::GetConfig();
        config.PushToTalkKey = (int)vk;
        VoiceState::SetConfig(config);
        g_VoiceClient.SetPushToTalkKey((int)vk);
    }
  
    
    static void SaveOverlayHotkey()
    {
        std::string ini = GetOverlayIniPath();
        char tmp[32];

        sprintf_s(tmp, sizeof(tmp), "%u", g_panelHotkey.modifiers);
        WritePrivateProfileStringA("VoiceKeys", "OpenPanelModifiers", tmp, ini.c_str());

        sprintf_s(tmp, sizeof(tmp), "%u", g_panelHotkey.vk);
        WritePrivateProfileStringA("VoiceKeys", "OpenPanel", tmp, ini.c_str());

    }
    static void CommitCapturedPanelHotkey(UINT vk)
    {
        if (vk == VK_ESCAPE)
            return;

        vk = NormalizeVk(vk);

        if (vk == 0 || IsModifierVk(vk))
            return;

        OverlayHotkey next;
        next.modifiers = CurrentModifierFlags();
        next.vk = vk;

        if (!IsHotkeyValid(next))
            return;

        g_panelHotkey = next;
        SaveOverlayHotkey();

        VoiceConfig config = VoiceState::GetConfig();
        config.OpenPanelKey = (int)g_panelHotkey.vk;
        VoiceState::SetConfig(config);

        g_openPanelHotkeyWasDown = IsPanelHotkeyDown();
    }

    static LRESULT CALLBACK VoiceSettingsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
        case WM_NCHITTEST:
            return HitTestResizeBorder(hwnd, lParam);

        case WM_GETMINMAXINFO:
        {
            MINMAXINFO* info = (MINMAXINFO*)lParam;
            info->ptMinTrackSize.x = PANEL_MIN_W;
            info->ptMinTrackSize.y = PANEL_MIN_H;
            return 0;
        }

        case WM_SIZE:
            InvalidateSettings();
            return 0;

        case WM_EXITSIZEMOVE:
            SavePanelSize(hwnd);
            SaveWindowPos(hwnd, false);
            return 0;

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
            PaintBuffered(hwnd, PaintSettings);
            return 0;

        case WM_TIMER:
            if (wParam == TIMER_HOTKEY_POLL)
            {
                PollOpenPanelHotkey();

                if (!IsLineageWindowActive())
                {
                    if (g_hSettings && IsWindow(g_hSettings) && IsWindowVisible(g_hSettings))
                        ShowWindow(g_hSettings, SW_HIDE);

                    if (g_hSpeakers && IsWindow(g_hSpeakers) && IsWindowVisible(g_hSpeakers))
                        ShowWindow(g_hSpeakers, SW_HIDE);

                    return 0;
                }

                if (g_visible)
                {
                    if (g_hSettings && IsWindow(g_hSettings) && !IsWindowVisible(g_hSettings))
                        ShowWindow(g_hSettings, SW_SHOW);
                }

                UpdateSpeakersWindowVisibility(g_hSpeakers);
                return 0;
            }

            if (wParam == TIMER_INTRO)
            {
                if (g_introVisible)
                {
                    DWORD now = GetTickCount();
                    if (now - g_introStartedAt >= INTRO_DURATION_MS)
                        StopIntroMessage();
                }

                return 0;
            }

            return 0;

        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
            if (g_capturePttKey || g_capturePanelHotkey)
            {
                UINT vk = (UINT)wParam;

                if (g_capturePttKey)
                    CommitCapturedPttKey(vk);
                else
                    CommitCapturedPanelHotkey(vk);

                g_capturePttKey = false;
                g_capturePanelHotkey = false;
                InvalidateSettings();
                return 0;
            }

            if (wParam == VK_ESCAPE)
            {
                HideOverlay();
                return 0;
            }

            return 0;

        case WM_MOUSEMOVE:
        {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);

            if (g_dragSettings)
            {
                POINT pt;
                GetCursorPos(&pt);
                SetWindowPos(hwnd, NULL, pt.x - g_dragOffset.x, pt.y - g_dragOffset.y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                return 0;
            }

            LayoutSettingsButtonsForWindow(hwnd);
            int hover = HitButton(x, y);

            if (hover != g_hoverButton)
            {
                g_hoverButton = hover;
                InvalidateSettings();
            }

            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);

            return 0;
        }

        case WM_MOUSELEAVE:
            g_hoverButton = BTN_NONE;
            InvalidateSettings();
            return 0;

        case WM_LBUTTONDOWN:
        {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            LayoutSettingsButtonsForWindow(hwnd);
            int button = HitButton(x, y);

            if (button != BTN_NONE)
            {
                g_pressedButton = button;
                SetCapture(hwnd);
                InvalidateSettings();
                return 0;
            }

            if (y <= HEADER_H)
            {
                POINT pt;
                RECT rc;

                GetCursorPos(&pt);
                GetWindowRect(hwnd, &rc);

                g_dragOffset.x = pt.x - rc.left;
                g_dragOffset.y = pt.y - rc.top;
                g_dragSettings = true;

                SetCapture(hwnd);
            }

            return 0;
        }

        case WM_LBUTTONUP:
        {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            LayoutSettingsButtonsForWindow(hwnd);
            int button = HitButton(x, y);

            if (g_pressedButton != BTN_NONE && button == g_pressedButton)
                ApplyButton(g_pressedButton);

            if (g_dragSettings)
                SaveWindowPos(hwnd, false);

            g_pressedButton = BTN_NONE;
            g_dragSettings = false;

            ReleaseCapture();
            InvalidateSettings();
            return 0;
        }

        case WM_L2VOICE_OVERLAY_SHOW:
            ShowOverlay();
            return 0;

        case WM_L2VOICE_OVERLAY_HIDE:
            HideOverlay();
            return 0;

        case WM_L2VOICE_OVERLAY_TOGGLE:
            ToggleOverlayVisible();
            return 0;

        case WM_CLOSE:
            HideOverlay();
            return 0;
        }

        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }

    static LRESULT CALLBACK VoiceSpeakersProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
            PaintBuffered(hwnd, PaintSpeakers);
            return 0;

        case WM_TIMER:
            if (wParam == TIMER_SPEAKERS_REFRESH)
                UpdateSpeakersWindowVisibility(hwnd);

            return 0;

        case WM_L2VOICE_SPEAKERS_DIRTY:
            UpdateSpeakersWindowVisibility(hwnd);
            return 0;

        case WM_MOUSEMOVE:
        {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);

            if (g_dragSpeakers)
            {
                POINT pt;
                GetCursorPos(&pt);
                SetWindowPos(hwnd, NULL, pt.x - g_dragOffset.x, pt.y - g_dragOffset.y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                return 0;
            }

            int hoverId = HitSpeakerRow(x, y);

            if (hoverId != g_hoverSpeakerObjectId)
            {
                g_hoverSpeakerObjectId = hoverId;
                InvalidateSpeakers();
            }

            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);

            return 0;
        }

        case WM_MOUSELEAVE:
            g_hoverSpeakerObjectId = 0;
            InvalidateSpeakers();
            return 0;

        case WM_LBUTTONDOWN:
        {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);

            if (HitDragHandle(x, y))
            {
                POINT pt;
                RECT rc;

                GetCursorPos(&pt);
                GetWindowRect(hwnd, &rc);

                g_dragOffset.x = pt.x - rc.left;
                g_dragOffset.y = pt.y - rc.top;
                g_dragSpeakers = true;

                SetCapture(hwnd);
                return 0;
            }

            if (HitSpeakerRow(x, y) > 0)
            {
                TogglePlayerMuteByPoint(x, y);
                return 0;
            }

            return 0;
        }

        case WM_LBUTTONUP:
            if (g_dragSpeakers)
                SaveWindowPos(hwnd, true);

            g_dragSpeakers = false;
            ReleaseCapture();
            return 0;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }

        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

void VoiceOverlay_Initialize(HINSTANCE hInstance)
{
    g_hInstance = hInstance;

    if (g_hOverlayThread)
        return;

    g_hOverlayThread = CreateThread(NULL, 0, VoiceOverlayThread, hInstance, 0, &g_overlayThreadId);
}

void VoiceOverlay_Shutdown()
{
    if (g_hSettings && IsWindow(g_hSettings))
        SaveWindowPos(g_hSettings, false);

    if (g_hSpeakers && IsWindow(g_hSpeakers))
        SaveWindowPos(g_hSpeakers, true);

    if (g_hSettings && IsWindow(g_hSettings))
        PostMessageA(g_hSettings, WM_CLOSE, 0, 0);

    if (g_overlayThreadId != 0)
        PostThreadMessageA(g_overlayThreadId, WM_QUIT, 0, 0);

    if (g_hOverlayThread)
    {
        WaitForSingleObject(g_hOverlayThread, 1500);
        CloseHandle(g_hOverlayThread);
        g_hOverlayThread = NULL;
    }

    g_overlayThreadId = 0;
    g_hSettings = NULL;
    g_hSpeakers = NULL;
    g_visible = false;
    g_openPanelHotkeyWasDown = false;
    g_introVisible = false;
    g_capturePttKey = false;
    g_capturePanelHotkey = false;
    g_dragSettings = false;
    g_dragSpeakers = false;

    VoiceState::Shutdown();
}

void VoiceOverlay_Show()
{
    if (g_hSettings && IsWindow(g_hSettings))
        PostMessageA(g_hSettings, WM_L2VOICE_OVERLAY_SHOW, 0, 0);
}

void VoiceOverlay_Hide()
{
    if (g_hSettings && IsWindow(g_hSettings))
        PostMessageA(g_hSettings, WM_L2VOICE_OVERLAY_HIDE, 0, 0);
}

void VoiceOverlay_Toggle()
{
    if (g_hSettings && IsWindow(g_hSettings))
        PostMessageA(g_hSettings, WM_L2VOICE_OVERLAY_TOGGLE, 0, 0);
}

void VoiceOverlay_OnTalkStart(int objectId, const char* name)
{
    VoiceState::AddSpeaker(objectId, name);

    if (g_hSpeakers && IsWindow(g_hSpeakers))
        PostMessageA(g_hSpeakers, WM_L2VOICE_SPEAKERS_DIRTY, 0, 0);
}

void VoiceOverlay_OnTalkStop(int objectId)
{
    VoiceState::RemoveSpeaker(objectId);

    if (g_hSpeakers && IsWindow(g_hSpeakers))
        PostMessageA(g_hSpeakers, WM_L2VOICE_SPEAKERS_DIRTY, 0, 0);
}

static void LoadPanelSize()
{
    std::string ini = GetOverlayIniPath();

    int w = GetPrivateProfileIntA("VoicePanel", "Width", PANEL_W, ini.c_str());
    int h = GetPrivateProfileIntA("VoicePanel", "Height", PANEL_H, ini.c_str());

    if (w < PANEL_MIN_W) w = PANEL_MIN_W;
    if (h < PANEL_MIN_H) h = PANEL_MIN_H;

    g_panelW = w;
    g_panelH = h;
}

namespace
{
    static DWORD WINAPI VoiceOverlayThread(LPVOID param)
    {
        HINSTANCE hInstance = (HINSTANCE)param;

        VoiceState::Initialize();
        LoadOverlayHotkey();
        LoadPanelSize();

        WNDCLASSA wcSettings;
        ZeroMemory(&wcSettings, sizeof(wcSettings));
        wcSettings.lpfnWndProc = VoiceSettingsProc;
        wcSettings.hInstance = hInstance;
        wcSettings.lpszClassName = "L2VoiceSettingsFinal";
        wcSettings.hCursor = LoadCursor(NULL, IDC_ARROW);
        wcSettings.hbrBackground = NULL;
        RegisterClassA(&wcSettings);

        WNDCLASSA wcSpeakers;
        ZeroMemory(&wcSpeakers, sizeof(wcSpeakers));
        wcSpeakers.lpfnWndProc = VoiceSpeakersProc;
        wcSpeakers.hInstance = hInstance;
        wcSpeakers.lpszClassName = "L2VoiceSpeakersFinal";
        wcSpeakers.hCursor = LoadCursor(NULL, IDC_ARROW);
        wcSpeakers.hbrBackground = NULL;
        RegisterClassA(&wcSpeakers);

        VoiceWindowPos settingsPos = VoiceState::GetSettingsPos();
        VoiceWindowPos speakersPos = VoiceState::GetSpeakersPos();

        g_hSettings = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
            "L2VoiceSettingsFinal",
            "Voice Settings",
            WS_POPUP,
            settingsPos.x,
            settingsPos.y,
            g_panelW,
            g_panelH,
            NULL,
            NULL,
            hInstance,
            NULL
        );

        g_hSpeakers = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
            "L2VoiceSpeakersFinal",
            "Voice Speakers",
            WS_POPUP,
            speakersPos.x,
            speakersPos.y,
            SPEAKERS_W,
            32,
            NULL,
            NULL,
            hInstance,
            NULL
        );

        if (!g_hSettings || !g_hSpeakers)
        {
            if (g_hSettings)
            {
                DestroyWindow(g_hSettings);
                g_hSettings = NULL;
            }

            if (g_hSpeakers)
            {
                DestroyWindow(g_hSpeakers);
                g_hSpeakers = NULL;
            }

            return 0;
        }

        SetLayeredWindowAttributes(g_hSettings, 0, 247, LWA_ALPHA);
        SetLayeredWindowAttributes(g_hSpeakers, C_KEY, 255, LWA_COLORKEY);

        ShowWindow(g_hSpeakers, SW_HIDE);

        SetTimer(g_hSettings, TIMER_HOTKEY_POLL, 100, NULL);
        SetTimer(g_hSpeakers, TIMER_SPEAKERS_REFRESH, 500, NULL);

        g_openPanelHotkeyWasDown = IsPanelHotkeyDown();

        VoiceConfig config = VoiceState::GetConfig();

        if (config.PanelVisible)
            ShowOverlay();
        else
            HideOverlay();

        MSG msg;

        while (GetMessageA(&msg, NULL, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (g_hSettings && IsWindow(g_hSettings))
        {
            KillTimer(g_hSettings, TIMER_HOTKEY_POLL);
            KillTimer(g_hSettings, TIMER_INTRO);
            SaveWindowPos(g_hSettings, false);
        }

        if (g_hSpeakers && IsWindow(g_hSpeakers))
        {
            KillTimer(g_hSpeakers, TIMER_SPEAKERS_REFRESH);
            SaveWindowPos(g_hSpeakers, true);
        }

        if (g_hSpeakers && IsWindow(g_hSpeakers))
        {
            DestroyWindow(g_hSpeakers);
            g_hSpeakers = NULL;
        }

        if (g_hSettings && IsWindow(g_hSettings))
        {
            DestroyWindow(g_hSettings);
            g_hSettings = NULL;
        }

        g_visible = false;
        g_openPanelHotkeyWasDown = false;
        g_introVisible = false;
        g_capturePttKey = false;
        g_capturePanelHotkey = false;
        g_dragSettings = false;
        g_dragSpeakers = false;

        return 0;
    }
}
