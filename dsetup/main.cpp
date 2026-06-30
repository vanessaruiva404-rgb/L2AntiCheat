// ============================================================
// main.cpp - BAN-L2JNEXORA / L2JDEV
// Defensive client-side protection for L2J Interlude main
// ============================================================
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <shlobj.h>
#include "Hook.h"
#include "resource.h"
#include "AntiCheat.h"
#include "StringCipher.h"
#include "NotificationIcon.h"
 
#include "ProtectionUI.h"
#include "ClientInstanceManager.h"
#include "AccountOverlay.h"
#include "AccountVault.h"
#include "AccountLogin.h"
#include "VoiceConfig.h"
#include "VoiceClient.h"
#include "VoiceLog.h"
#include "VoiceOverlay.h"
#include "ProcessTelemetry.h"


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

static const unsigned short LOGIN_PORT = 2106;
static const unsigned short GAME_PORT = 7777;
static const LONG STARTUP_GATE_PENDING = 0;
static const LONG STARTUP_GATE_ALLOWED = 1;
static const LONG STARTUP_GATE_BLOCKED = 2;
static const unsigned char HWID_MAGIC[4] = { 'B', 'H', 'W', 'D' };

static const unsigned char obf_secret_part1[] = {
    0x18,0x1B,0x14,0x05,0x16,0x68
};

static const unsigned char obf_secret_part2[] = {
    0x10,0x1E,0x1F,0x0C,0x05
};

static const unsigned char obf_secret_part3[] = {
    0x68,0x6A,0x6D,0x6A
};

static const unsigned char obf_mutex[] = {
    0x16,0x35,0x39,0x3B,0x36,0x06,0x18,0x1B,0x14,0x05,
    0x16,0x68,0x10,0x1E,0x1F,0x0C,0x05,0x1D,0x0F,0x1B,
    0x08,0x1E,0x05,0x17,0x0F,0x0E,0x1F,0x02,0x00
};

static const unsigned char obf_map[] = {
    0x16,0x35,0x39,0x3B,0x36,0x06,0x18,0x1B,0x14,0x05,
    0x16,0x68,0x10,0x1E,0x1F,0x0C,0x05,0x17,0x3B,0x2A,
    0x00
};
VoiceClient g_VoiceClient;
HWND g_hSplash = NULL;
HINSTANCE g_ModuleHandle = NULL;
HANDLE g_hAntiCheatThread = NULL;
HANDLE g_hBootstrapThread = NULL;
HANDLE g_hOwnershipMonitorThread = NULL;
HANDLE g_hVoiceLifecycleThread = NULL;
HANDLE g_hStopEvent = NULL;
HANDLE g_hStartupGateEvent = NULL;

HANDLE g_hSharedMutex = NULL;
HANDLE g_hSharedMap = NULL;

bool g_IsPrimaryOwner = false;
bool g_GlobalSystemsStarted = false;
volatile LONG g_StartupGateState = STARTUP_GATE_PENDING;

char g_ServerIP[] = "157.254.248.55";
//char g_ServerIP[] = "www.l2auth.com";
char g_CPU[128] = { 0 };
char g_HDD[128] = { 0 };
char g_MAC[128] = { 0 };
char g_HwidKey[128] = { 0 };
char g_FinalPayload[512] = { 0 };

volatile SOCKET g_LoginSocket = INVALID_SOCKET;
volatile SOCKET g_GameSocket = INVALID_SOCKET;

struct ClientSharedState
{
    LONG  processCount;
    DWORD primaryOwnerPid;
};

ClientSharedState* g_SharedState = NULL;

typedef int(__stdcall* _connect)(SOCKET, const sockaddr*, int);
typedef int(WSAAPI* _send)(SOCKET, const char*, int, int);
typedef int(WSAAPI* _closesocket)(SOCKET);

static _connect true_connect = nullptr;
static _send true_send = nullptr;
static _closesocket true_closesocket = nullptr;

LRESULT CALLBACK SplashProc(HWND, UINT, WPARAM, LPARAM);
DWORD WINAPI SplashThread(LPVOID);
DWORD WINAPI BootstrapThread(LPVOID);
DWORD WINAPI OwnershipMonitorThread(LPVOID);
DWORD WINAPI VoiceLifecycleThread(LPVOID);

void ShowSplash();
void DrawSplash();
void FadeIn(HWND hwnd);
void FadeOut(HWND hwnd);

bool InitializeSharedState();
void CloseSharedState();

bool LockSharedState(DWORD timeout = 5000);
void UnlockSharedState();

bool IsProcessAlive(DWORD pid);
bool IsAnyLineageClientRunning();
void RefreshPrimaryOwnership();
void AcquirePrimaryOwnership();
void ReleasePrimaryOwnership();
void StartGlobalSystems();
void StopGlobalSystems();
void BuildPayload();
void SignalStartupGate(LONG state);
bool IsVoiceSystemStarted();

bool GetCPUId(char* out, size_t size);
bool GetHDDSerial(char* out, size_t size);
bool GetMAC(char* out, size_t size);
void BuildSecret(char* out, size_t size);

bool IsProtocolVersion(const unsigned char* buf, int len);
bool HasHWID(const unsigned char* buf, int len);
int BuildPacket(const unsigned char* in, int inLen, unsigned char* out);

int __stdcall HookConnect(SOCKET s, const sockaddr* name, int len);
int WSAAPI HookSend(SOCKET s, const char* buf, int len, int flags);
void InstallHooks();

void BuildSecret(char* out, size_t size)
{
    DECODE_STR_A(p1, obf_secret_part1, 0x5A);
    DECODE_STR_A(p2, obf_secret_part2, 0x5A);
    DECODE_STR_A(p3, obf_secret_part3, 0x5A);

    std::string secret = p1.str() + p2.str() + p3.str();
    strcpy_s(out, size, secret.c_str());

    SecureZeroMemory((void*)secret.data(), secret.size());
}

void SignalStartupGate(LONG state)
{
    InterlockedExchange(&g_StartupGateState, state);

    if (g_hStartupGateEvent)
        SetEvent(g_hStartupGateEvent);
}

bool LockSharedState(DWORD timeout)
{
    if (!g_hSharedMutex)
        return false;

    DWORD result = WaitForSingleObject(g_hSharedMutex, timeout);
    return (result == WAIT_OBJECT_0);
}

void UnlockSharedState()
{
    if (g_hSharedMutex)
        ReleaseMutex(g_hSharedMutex);
}

bool IsProcessAlive(DWORD pid)
{
    if (pid == 0)
        return false;

    HANDLE processHandle = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!processHandle)
        return false;

    DWORD result = WaitForSingleObject(processHandle, 0);
    CloseHandle(processHandle);
    return (result == WAIT_TIMEOUT);
}

bool IsAnyLineageClientRunning()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    bool found = false;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"l2.exe") == 0)
            {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

bool InitializeSharedState()
{
    DECODE_STR_A(mutexName, obf_mutex, 0x5A);
    DECODE_STR_A(mapName, obf_map, 0x5A);

    g_hSharedMutex = CreateMutexA(NULL, FALSE, mutexName.c_str());
    if (!g_hSharedMutex)
        return false;

    g_hSharedMap = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(ClientSharedState),
        mapName.c_str()
    );

    if (!g_hSharedMap)
        return false;

    bool alreadyExists = (GetLastError() == ERROR_ALREADY_EXISTS);

    g_SharedState = (ClientSharedState*)MapViewOfFile(
        g_hSharedMap,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(ClientSharedState)
    );

    if (!g_SharedState)
        return false;

    if (LockSharedState())
    {
        if (!alreadyExists)
        {
            g_SharedState->processCount = 0;
            g_SharedState->primaryOwnerPid = 0;
        }

        g_SharedState->processCount++;
        UnlockSharedState();
    }

    return true;
}

void CloseSharedState()
{
    if (g_SharedState && LockSharedState())
    {
        if (g_SharedState->processCount > 0)
            g_SharedState->processCount--;

        if (g_IsPrimaryOwner && g_SharedState->primaryOwnerPid == GetCurrentProcessId())
            g_SharedState->primaryOwnerPid = 0;

        UnlockSharedState();
    }

    if (g_SharedState)
    {
        UnmapViewOfFile(g_SharedState);
        g_SharedState = NULL;
    }

    if (g_hSharedMap)
    {
        CloseHandle(g_hSharedMap);
        g_hSharedMap = NULL;
    }

    if (g_hSharedMutex)
    {
        CloseHandle(g_hSharedMutex);
        g_hSharedMutex = NULL;
    }
}

void StartGlobalSystems()
{
    if (!g_IsPrimaryOwner || g_GlobalSystemsStarted)
        return;

    ResetEvent(g_hStopEvent);

    g_hAntiCheatThread = CreateThread(NULL, 0, AntiCheatThread, NULL, 0, NULL);
    g_GlobalSystemsStarted = (g_hAntiCheatThread != NULL);

    if (g_GlobalSystemsStarted)
    {
        StartProcessTelemetry();
    }
}

void StopGlobalSystems()
{
    if (!g_GlobalSystemsStarted)
        return;

    StopProcessTelemetry();
    StopAntiCheat();

    if (g_hAntiCheatThread)
    {
        CloseHandle(g_hAntiCheatThread);
        g_hAntiCheatThread = NULL;
    }

    g_GlobalSystemsStarted = false;
}

void AcquirePrimaryOwnership()
{
    if (g_IsPrimaryOwner)
        return;

    g_IsPrimaryOwner = true;
    StartGlobalSystems();

}

void ReleasePrimaryOwnership()
{
    if (!g_IsPrimaryOwner)
        return;

    StopGlobalSystems(); // AC para, mas ícone não some aqui

    if (g_SharedState && LockSharedState())
    {
        if (g_SharedState->primaryOwnerPid == GetCurrentProcessId())
            g_SharedState->primaryOwnerPid = 0;

        UnlockSharedState();
    }

    g_IsPrimaryOwner = false;
}

void RefreshPrimaryOwnership()
{
    if (!g_SharedState)
        return;

    DWORD myPid = GetCurrentProcessId();
    bool shouldOwnPrimaryRole = false;

    if (!LockSharedState())
        return;

    DWORD currentOwnerPid = g_SharedState->primaryOwnerPid;

    if (currentOwnerPid != 0 && !IsProcessAlive(currentOwnerPid))
    {
        g_SharedState->primaryOwnerPid = 0;
        currentOwnerPid = 0;
    }

    if (g_SharedState->processCount <= 0)
    {
        g_SharedState->primaryOwnerPid = 0;
        shouldOwnPrimaryRole = false;
    }
    else if (currentOwnerPid == 0)
    {
        g_SharedState->primaryOwnerPid = myPid;
        shouldOwnPrimaryRole = true;
    }
    else
    {
        shouldOwnPrimaryRole = (currentOwnerPid == myPid);
    }

    UnlockSharedState();

    if (shouldOwnPrimaryRole && !g_IsPrimaryOwner)
    {
        AcquirePrimaryOwnership();
    }
    else if (!shouldOwnPrimaryRole && g_IsPrimaryOwner)
    {
        ReleasePrimaryOwnership();
    }
}

bool GetCPUId(char* out, size_t size)
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);

    sprintf_s(
        out,
        size,
        "%08X%08X%08X%08X",
        cpuInfo[0],
        cpuInfo[1],
        cpuInfo[2],
        cpuInfo[3]
    );

    return true;
}

bool GetHDDSerial(char* out, size_t size)
{
    DWORD serial = 0;

    if (!GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0))
        return false;

    sprintf_s(out, size, "%08X", serial);
    return true;
}

bool GetMAC(char* out, size_t size)
{
    IP_ADAPTER_INFO adapter[16];
    DWORD bufferLen = sizeof(adapter);

    if (GetAdaptersInfo(adapter, &bufferLen) != ERROR_SUCCESS)
        return false;

    PIP_ADAPTER_INFO adapterInfo = adapter;

    sprintf_s(
        out,
        size,
        "%02X%02X%02X%02X%02X%02X",
        adapterInfo->Address[0],
        adapterInfo->Address[1],
        adapterInfo->Address[2],
        adapterInfo->Address[3],
        adapterInfo->Address[4],
        adapterInfo->Address[5]
    );

    return true;
}

void BuildPayload()
{
    if (!GetCPUId(g_CPU, sizeof(g_CPU)))
        strcpy_s(g_CPU, "CPU_FAIL");

    if (!GetHDDSerial(g_HDD, sizeof(g_HDD)))
        strcpy_s(g_HDD, "HDD_FAIL");

    if (!GetMAC(g_MAC, sizeof(g_MAC)))
        strcpy_s(g_MAC, "MAC_FAIL");
 
    BuildSecret(g_HwidKey, sizeof(g_HwidKey));

    sprintf_s(g_FinalPayload, "%s|%s|%s|%s", g_CPU, g_HDD, g_MAC, g_HwidKey);
    SecureZeroMemory(g_HwidKey, sizeof(g_HwidKey));



}

LRESULT CALLBACK SplashProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void DrawSplash()
{
    HDC dc = GetDC(g_hSplash);

    HBITMAP bitmap = (HBITMAP)LoadImageW(
        g_ModuleHandle,
        MAKEINTRESOURCEW(IDB_SPLASHLOAD),
        IMAGE_BITMAP,
        0,
        0,
        LR_CREATEDIBSECTION
    );

    if (!bitmap)
    {
        ReleaseDC(g_hSplash, dc);
        return;
    }

    HDC memoryDc = CreateCompatibleDC(dc);
    HGDIOBJ oldObject = SelectObject(memoryDc, bitmap);

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    BITMAP bmp{};
    GetObject(bitmap, sizeof(bmp), &bmp);

    BitBlt(dc, 0, 0, bmp.bmWidth, bmp.bmHeight, memoryDc, 0, 0, SRCCOPY);

    SelectObject(memoryDc, oldObject);
    DeleteDC(memoryDc);
    DeleteObject(bitmap);
    ReleaseDC(g_hSplash, dc);
}

void FadeIn(HWND hwnd)
{
    for (int i = 0; i <= 255; i += 5)
    {
        SetLayeredWindowAttributes(hwnd, 0, (BYTE)i, LWA_ALPHA);
        Sleep(5);
    }
}

void FadeOut(HWND hwnd)
{
    for (int i = 255; i >= 0; i -= 5)
    {
        SetLayeredWindowAttributes(hwnd, 0, (BYTE)i, LWA_ALPHA);
        Sleep(5);
    }
}

void ShowSplash()
{
    static bool classRegistered = false;

    if (!classRegistered)
    {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = SplashProc;
        wc.hInstance = g_ModuleHandle;
        wc.lpszClassName = L"L2SplashClass";

        if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return;

        classRegistered = true;
    }

    int width = 256;
    int height = 128;

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    int x = screenW - width - 20;
    int y = screenH - height - 60;

    g_hSplash = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        L"L2SplashClass",
        L"",
        WS_POPUP,
        x, y, width, height,
        NULL, NULL,
        g_ModuleHandle,
        NULL
    );

    if (!g_hSplash)
        return;

    ShowWindow(g_hSplash, SW_SHOW);
    SetLayeredWindowAttributes(g_hSplash, 0, 0, LWA_ALPHA);
    DrawSplash();
    FadeIn(g_hSplash);
    Sleep(2000);
    FadeOut(g_hSplash);
    DestroyWindow(g_hSplash);
    g_hSplash = NULL;
}

DWORD WINAPI SplashThread(LPVOID)
{
    ShowSplash();
    return 0;
}

bool IsProtocolVersion(const unsigned char* buf, int len)
{
    return (len > 2 && buf[2] == 0x00);
}

bool HasHWID(const unsigned char* buf, int len)
{
    for (int i = 0; i < len - 4; i++)
    {
        if (buf[i] == 'B' && buf[i + 1] == 'H' && buf[i + 2] == 'W' && buf[i + 3] == 'D')
            return true;
    }

    return false;
}

int BuildPacket(const unsigned char* in, int inLen, unsigned char* out)
{
    int payloadLen = (int)strlen(g_FinalPayload) + 1;
    int newLen = inLen + 4 + 4 + payloadLen;

    memcpy(out, in, inLen);
    int pos = inLen;

    memcpy(out + pos, HWID_MAGIC, 4);
    pos += 4;

    memcpy(out + pos, &payloadLen, 4);
    pos += 4;

    memcpy(out + pos, g_FinalPayload, payloadLen);

    unsigned short size = (unsigned short)newLen;
    out[0] = size & 0xFF;
    out[1] = (size >> 8);

    return newLen;
}

int __stdcall HookConnect(SOCKET s, const sockaddr* name, int len)
{
    sockaddr_in addr = *(sockaddr_in*)name;
    unsigned short port = ntohs(addr.sin_port);
    const bool isLoginServer = port == LOGIN_PORT;
    const bool isGameServer = port == GAME_PORT;

    if (isLoginServer || isGameServer)
    {
        inet_pton(AF_INET, g_ServerIP, &addr.sin_addr);
    }

    int result = true_connect(s, (sockaddr*)&addr, len);

    if (isLoginServer)
    {
        AccountLogin_SetGameSessionActive(false);
    }
    else if (isGameServer)
    {
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        const bool accepted =
            result != SOCKET_ERROR ||
            error == WSAEWOULDBLOCK ||
            error == WSAEINPROGRESS ||
            error == WSAEALREADY;

        if (accepted)
        {
            g_GameSocket = s;
            AccountLogin_SetGameSessionActive(true);
        }
        else
        {
            if (g_GameSocket == s)
                g_GameSocket = INVALID_SOCKET;

            AccountLogin_SetGameSessionActive(false);
        }
    }

    return result;
}

int WSAAPI HookSend(SOCKET s, const char* buf, int len, int flags)
{
    if (s == g_GameSocket)
    {
        if (IsProtocolVersion((unsigned char*)buf, len) && !HasHWID((unsigned char*)buf, len))
        {
            unsigned char newBuf[4096];
            int newLen = BuildPacket((unsigned char*)buf, len, newBuf);
            return true_send(s, (char*)newBuf, newLen, flags);
        }
    }

    return true_send(s, buf, len, flags);
}

int WSAAPI HookCloseSocket(SOCKET s)
{
    if (s == g_GameSocket)
    {
        g_GameSocket = INVALID_SOCKET;
        AccountLogin_SetGameSessionActive(false);
    }

    if (!true_closesocket)
        return SOCKET_ERROR;

    return true_closesocket(s);
}

void InstallHooks()
{
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2)
        return;

    if (!true_connect)
        true_connect = (_connect)splice((unsigned char*)GetProcAddress(ws2, "connect"), HookConnect);

    if (!true_send)
        true_send = (_send)splice((unsigned char*)GetProcAddress(ws2, "send"), HookSend);

    if (!true_closesocket)
        true_closesocket = (_closesocket)splice((unsigned char*)GetProcAddress(ws2, "closesocket"), HookCloseSocket);
}

DWORD WINAPI OwnershipMonitorThread(LPVOID)
{
    while (WaitForSingleObject(g_hStopEvent, 500) == WAIT_TIMEOUT)
    {
        RefreshPrimaryOwnership();

        bool noProcessesInShared = false;

        if (g_SharedState && LockSharedState())
        {
            noProcessesInShared = (g_SharedState->processCount <= 0);
            UnlockSharedState();
        }

        if (g_IsPrimaryOwner && noProcessesInShared && !IsAnyLineageClientRunning())
        {
            ReleasePrimaryOwnership();

            if (g_SharedState && LockSharedState())
            {
                if (g_SharedState->primaryOwnerPid == GetCurrentProcessId())
                    g_SharedState->primaryOwnerPid = 0;

                UnlockSharedState();
            }

            break;
        }
    }

    return 0;
}

static volatile LONG g_VoiceStarted = 0;
 
 
bool IsVoiceSystemStarted()
{
    return InterlockedCompareExchange(&g_VoiceStarted, 0, 0) != 0;
}

 
void StartVoiceSystem()
{

    if (!AccountLogin_IsGameSessionActive())
    {
        
        return;
    }

    if (InterlockedCompareExchange(&g_VoiceStarted, 1, 0) != 0)
    {
         
        return;
    }

   
    char appData[MAX_PATH];

    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appData)))
    {
        VoiceLog("[Voice] Failed to get AppData.");
        InterlockedExchange(&g_VoiceStarted, 0);
        return;
    }

    char dir[MAX_PATH];
    sprintf_s(dir, sizeof(dir), "%s\\LineageII", appData);
    CreateDirectoryA(dir, NULL);

    char file[MAX_PATH];
    sprintf_s(file, sizeof(file), "%s\\voice.ini", dir);


    VoiceConfig config = VoiceConfigLoader::Load(file);



    if (!config.Enabled)
    {
       
        InterlockedExchange(&g_VoiceStarted, 0);
        return;
    }

    if (!AccountLogin_IsGameSessionActive())
    {
       
        InterlockedExchange(&g_VoiceStarted, 0);
        return;
    }

    if (!g_VoiceClient.Start(config))
    {
       
        InterlockedExchange(&g_VoiceStarted, 0);
        return;
    }

 
}


void StopVoiceSystem()
{
    if (InterlockedCompareExchange(&g_VoiceStarted, 0, 1) != 1)
        return;

    g_VoiceClient.Stop();
  
}

DWORD WINAPI VoiceLifecycleThread(LPVOID)
{
    DWORD lastStartAttempt = 0;

    while (WaitForSingleObject(g_hStopEvent, 500) == WAIT_TIMEOUT)
    {
        const bool inGame = AccountLogin_IsGameSessionActive();

        if (inGame)
        {
            if (!IsVoiceSystemStarted())
            {
                const DWORD now = GetTickCount();
                if (lastStartAttempt == 0 || now - lastStartAttempt >= 5000)
                {
                    lastStartAttempt = now;
                    StartVoiceSystem();
                }
            }
        }
        else
        {
            lastStartAttempt = 0;
            StopVoiceSystem();
        }
    }

    StopVoiceSystem();
    return 0;
}
 
DWORD WINAPI BootstrapThread(LPVOID)
{
    AntiCheatSetModuleHandle(g_ModuleHandle);

    BuildPayload();
    if (CheckBlockedDeviceBeforeStartup())
    {
        SignalStartupGate(STARTUP_GATE_BLOCKED);
        TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
        return 0;
    }
    SignalStartupGate(STARTUP_GATE_ALLOWED);

    NotificationIcon_Initialize(g_ModuleHandle);

    CreateThread(NULL, 0, SplashThread, NULL, 0, NULL);
    Sleep(500);

    InstallHooks();
    AccountVault_Initialize();
    AccountLogin_Initialize();

    AccountOverlay_Initialize(g_ModuleHandle);

    if (InitializeSharedState())
    {
        RefreshPrimaryOwnership();
        g_hOwnershipMonitorThread = CreateThread(NULL, 0, OwnershipMonitorThread, NULL, 0, NULL);
    }
    // VoiceOverlay_Initialize(g_ModuleHandle);
    // g_hVoiceLifecycleThread = CreateThread(NULL, 0, VoiceLifecycleThread, NULL, 0, NULL);
 
   
    return 0;
}
extern "C" __declspec(dllexport)
HRESULT WINAPI DirectXSetupGetVersion(DWORD* version, DWORD* minor)
{
    if (g_hStartupGateEvent)
    {
        const DWORD waitResult = WaitForSingleObject(g_hStartupGateEvent, 30000);
        const LONG gateState = InterlockedCompareExchange(
            &g_StartupGateState,
            STARTUP_GATE_PENDING,
            STARTUP_GATE_PENDING);

        if (waitResult == WAIT_OBJECT_0 &&
            gateState == STARTUP_GATE_BLOCKED)
        {
            TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
            return E_ACCESSDENIED;
        }
    }

    if (version) *version = 0x00090000;
    if (minor) *minor = 0;
    return S_OK;
}
 

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{

    if (reason == DLL_PROCESS_ATTACH)
    {
        g_ModuleHandle = hModule;
        DisableThreadLibraryCalls(hModule);
        InterlockedExchange(&g_StartupGateState, STARTUP_GATE_PENDING);

        if (!ClientInstanceManager::Acquire())
        {
            ShowProtectionAlertBlocking(
                L"L2 RP Protection",
                L"Limite de sess\u00f5es por HWID atingido.",
                L"Contas Premium/VIP possuem permiss\u00e3o para at\u00e9 2 clientes simult\u00e2neos.",
                3800);

            TerminateProcess(
                GetCurrentProcess(),
                ERROR_TOO_MANY_SESS);
            return FALSE;
        }

        g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        g_hStartupGateEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        g_hBootstrapThread = CreateThread(NULL, 0, BootstrapThread, NULL, 0, NULL);
        if (!g_hBootstrapThread)
            SignalStartupGate(STARTUP_GATE_ALLOWED);

    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        VoiceOverlay_Shutdown();

 

        if (g_hStopEvent)
            SetEvent(g_hStopEvent);

        if (g_hVoiceLifecycleThread)
        {
            WaitForSingleObject(g_hVoiceLifecycleThread, 1500);
            CloseHandle(g_hVoiceLifecycleThread);
            g_hVoiceLifecycleThread = NULL;
        }

        StopVoiceSystem();
 
        NotificationIcon_HandleProcessDetach();
        NotificationIcon_Shutdown();
        if (g_IsPrimaryOwner)
            ReleasePrimaryOwnership();

        if (g_hOwnershipMonitorThread)
        {
            CloseHandle(g_hOwnershipMonitorThread);
            g_hOwnershipMonitorThread = NULL;
        }

        if (g_hBootstrapThread)
        {
            CloseHandle(g_hBootstrapThread);
            g_hBootstrapThread = NULL;
        }

        if (g_hStopEvent)
        {
            CloseHandle(g_hStopEvent);
            g_hStopEvent = NULL;
        }

        if (g_hStartupGateEvent)
        {
            HANDLE startupGateEvent = g_hStartupGateEvent;
            g_hStartupGateEvent = NULL;
            SetEvent(startupGateEvent);
            CloseHandle(startupGateEvent);
        }

        CloseSharedState();
        AccountOverlay_Shutdown();
        AccountLogin_Shutdown();
        AccountVault_Shutdown();
        ClientInstanceManager::Release();
    }

    return TRUE;
}
