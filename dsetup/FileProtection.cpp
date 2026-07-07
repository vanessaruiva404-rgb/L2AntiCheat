#include "FileProtection.h"
#include <cstdio>
#include <cstring>

#include <windows.h>
#include <wincrypt.h>
#include <fstream>

#pragma comment(lib, "Advapi32.lib")

static const wchar_t* FILE_INTERFACE_U = L"interface.u";
static const wchar_t* FILE_INTERFACE_XDAT = L"interface.xdat";

//  HASHES ORIGINAIS (VOCÊ VAI GERAR)
static const char* HASH_INTERFACE_U = "623A25FC61D8386D93E2058F9A96FD4D506ED81C17301D03E1777959357FAA57";
static const char* HASH_INTERFACE_XDAT = "DF290CD38059BF72ABAF919A8AD12ECD34488B155D6E0B9455944BA968D17891";

bool GetFileHash(const wchar_t* file, std::string& outHash)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool success = false;
    std::ifstream input;

    do
    {
        if (!CryptAcquireContext(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            break;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            break;

        input.open(file, std::ios::binary);
        if (!input.is_open())
            break;

        char buffer[4096];
        bool hashDataOk = true;

        while (input.read(buffer, sizeof(buffer)) || input.gcount())
        {
            DWORD bytesRead = (DWORD)input.gcount();
            if (!CryptHashData(hHash, (BYTE*)buffer, bytesRead, 0))
            {
                hashDataOk = false;
                break;
            }
        }

        if (!hashDataOk)
            break;

        BYTE hash[32];
        DWORD len = 32;

        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0))
            break;

        char hex[65] = { 0 };
        for (int i = 0; i < 32; i++)
            sprintf_s(hex + i * 2, 3, "%02X", hash[i]);

        outHash = hex;
        success = true;
    } while (false);

    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return success;
}

FileCheckResult VerifyProtectedFiles()
{
    FileCheckResult result = {};
    result.allOk = true;
    result.fileChanged = false;
    result.fileMissing = false;
    result.errorCode = ERROR_SUCCESS;

    std::string hash;

    // =====================
    // interface.u
    // =====================
    if (!GetFileHash(FILE_INTERFACE_U, hash))
    {
        result.allOk = false;
        result.fileMissing = true;
        result.fileChanged = false;
        result.fileName = FILE_INTERFACE_U;
        result.fullPath = FILE_INTERFACE_U;
        result.hash.clear();
        result.expectedHash = HASH_INTERFACE_U;
        result.errorCode = GetLastError();
        return result;
    }

    if (_stricmp(hash.c_str(), HASH_INTERFACE_U) != 0)
    {
        result.allOk = false;
        result.fileMissing = false;
        result.fileChanged = true;
        result.fileName = FILE_INTERFACE_U;
        result.fullPath = FILE_INTERFACE_U;
        result.hash = hash;
        result.expectedHash = HASH_INTERFACE_U;
        result.errorCode = ERROR_SUCCESS;
        return result;
    }

    // =====================
    // interface.xdat
    // =====================
    hash.clear();

    if (!GetFileHash(FILE_INTERFACE_XDAT, hash))
    {
        result.allOk = false;
        result.fileMissing = true;
        result.fileChanged = false;
        result.fileName = FILE_INTERFACE_XDAT;
        result.fullPath = FILE_INTERFACE_XDAT;
        result.hash.clear();
        result.expectedHash = HASH_INTERFACE_XDAT;
        result.errorCode = GetLastError();
        return result;
    }

    if (_stricmp(hash.c_str(), HASH_INTERFACE_XDAT) != 0)
    {
        result.allOk = false;
        result.fileMissing = false;
        result.fileChanged = true;
        result.fileName = FILE_INTERFACE_XDAT;
        result.fullPath = FILE_INTERFACE_XDAT;
        result.hash = hash;
        result.expectedHash = HASH_INTERFACE_XDAT;
        result.errorCode = ERROR_SUCCESS;
        return result;
    }

    return result;
}
