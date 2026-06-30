#include "ClientInstanceManager.h"

#include <string>

HANDLE ClientInstanceManager::_slotMutex = NULL;
LONG ClientInstanceManager::_slotIndex = -1;
bool ClientInstanceManager::_hasSlot = false;
bool ClientInstanceManager::_isOwner = false;

std::wstring ClientInstanceManager::GetSlotMutexName(LONG slot)
{
    return L"Global\\L2RP_CLIENT_SLOT_" + std::to_wstring(slot);
}

bool ClientInstanceManager::Acquire()
{
    if (_hasSlot)
        return true;

    for (LONG slot = 0; slot < MAX_CLIENTS; ++slot)
    {
        const std::wstring name = GetSlotMutexName(slot);
        HANDLE slotMutex = CreateMutexW(NULL, FALSE, name.c_str());
        if (!slotMutex)
            continue;

        const DWORD waitResult = WaitForSingleObject(slotMutex, 0);
        if (waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED)
        {
            _slotMutex = slotMutex;
            _slotIndex = slot;
            _hasSlot = true;
            _isOwner = true;
            return true;
        }

        CloseHandle(slotMutex);
    }

    return false;
}

void ClientInstanceManager::Release()
{
    if (_slotMutex)
    {
        ReleaseMutex(_slotMutex);
        CloseHandle(_slotMutex);
    }

    Cleanup();
}

void ClientInstanceManager::Cleanup()
{
    _slotMutex = NULL;
    _slotIndex = -1;
    _hasSlot = false;
    _isOwner = false;
}

bool ClientInstanceManager::IsOwner()
{
    return _isOwner;
}

LONG ClientInstanceManager::GetCurrentCount()
{
    LONG count = 0;

    for (LONG slot = 0; slot < MAX_CLIENTS; ++slot)
    {
        if (_hasSlot && slot == _slotIndex)
        {
            ++count;
            continue;
        }

        const std::wstring name = GetSlotMutexName(slot);
        HANDLE slotMutex = CreateMutexW(NULL, FALSE, name.c_str());
        if (!slotMutex)
            continue;

        const DWORD waitResult = WaitForSingleObject(slotMutex, 0);
        if (waitResult == WAIT_TIMEOUT)
        {
            ++count;
        }
        else if (
            waitResult == WAIT_OBJECT_0 ||
            waitResult == WAIT_ABANDONED)
        {
            ReleaseMutex(slotMutex);
        }

        CloseHandle(slotMutex);
    }

    return count;
}

LONG ClientInstanceManager::GetMaxClients()
{
    return MAX_CLIENTS;
}
