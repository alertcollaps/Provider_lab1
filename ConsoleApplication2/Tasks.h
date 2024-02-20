#pragma once
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

void Task1();
LPTSTR Task2(DWORD type);
HCRYPTPROV Task3(LPTSTR pszName, DWORD type);
void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);
void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);

void printNamesContFromProv(HCRYPTPROV hCryptProv);
int cin(std::string str);
PROV_ENUMALGS parse(BYTE* data);
void printInfo(PROV_ENUMALGS info);

void Task1() {
    std::cout << "\n-----Task 1-----" << std::endl;
    printf("Listing Available Provider Types:\n");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;

    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;
        if (!CryptEnumProviderTypes(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProvidersTypes" << std::endl;
            return;
        }

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());

        std::cout << "--------------------------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }
}

LPTSTR Task2(DWORD type) {
    std::cout << "\n-----Task 2-----" << std::endl;
    printf("Listing Available Providers:\n");
    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;
    LPTSTR pszNameOut;
    
    int i = 1;
    std::vector<LPTSTR> listNamesProviders;
    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (dwType != type) {
            ++dwIndex;
            continue;
        }
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;
        if (!(pszNameOut = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;
       
        if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProviders" << std::endl;
            return NULL;
        }
        lstrcpy(pszNameOut, pszName);

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());
        listNamesProviders.push_back(pszNameOut);

        std::cout << "----------------" << i++ <<  "----------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }

    i = cin("Choose provider name: ");
    for (int a = 0; a < listNamesProviders.size(); a++) {
        if (i - 1 == a) {
            continue;
        }
        LocalFree(listNamesProviders[a]);
    }

    return listNamesProviders[i-1];
}

HCRYPTPROV Task3(LPTSTR pszName, DWORD type) {
    
   

    HCRYPTPROV hCryptProv;
    BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    if (CryptAcquireContext(&hCryptProv, NULL, pszName, type, 0)) {
        printf("Context has been poluchen\n");
        
    }
    else {
        printf("Context don't recived\n");
        return NULL;
    }

    DWORD cbData;

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_NAME,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Provider name: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP name. \n");
        exit(1);
    }
    
    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_UNIQUE_CONTAINER,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Uniqe name of container: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP admin pin. \n");
        exit(1);
    }

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_ENUMALGS,
        pbData,
        &cbData,
        CRYPT_FIRST))
    {
        
        PROV_ENUMALGS info_algo = parse(pbData);
        printInfo(info_algo);
    }
    else
    {
        printf("Error reading CSP admin pin. \n");
        exit(1);
    }

    
     
    while (CryptGetProvParam(
        hCryptProv,
        PP_ENUMALGS,
        pbData,
        &cbData,
        CRYPT_NEXT))
    {
        PROV_ENUMALGS info_algo = parse(pbData);
        printInfo(info_algo);
    }
   



    

    return hCryptProv;
}

void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {  // handle for a cryptographic
                                     // provider context

    
    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        CRYPT_NEWKEYSET))
    {
        printf("A new key container has been created.\n");
    }
    else
    {
        printf("Could not create a new key container.\n");
        return;
    }

    
}

void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {  // handle for a cryptographic
                                     // provider context


    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        CRYPT_DELETEKEYSET))
    {
        wprintf(L"A exist key container {%s} has been deleted.\n", nameContainer);
    }
    else
    {
        printf("Could not delete a exist key container.\n");
        exit(1);
    }
}

void printNamesContFromProv(HCRYPTPROV hCryptProv) {
    BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.

    DWORD cbData;

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_ENUMCONTAINERS   ,
        pbData,
        &cbData,
        CRYPT_FIRST))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Name container: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP name. \n");
        exit(1);
    }

    cbData = 1000;
    while (CryptGetProvParam(
        hCryptProv,
        PP_ENUMCONTAINERS,
        pbData,
        &cbData,
        CRYPT_NEXT))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Name container next: %s\n", pbData);
    }
    
}


int cin(std::string str) {
    std::cout << str;
    int type = 1;
    std::cin >> type;

    return type;
}

PROV_ENUMALGS parse(BYTE* data) {
    PROV_ENUMALGS out;
    ALG_ID id;
    id = data[0] | 8 << data[1] | 16 << data[2] | 24 << data[3];
    out.aiAlgid = id;
    out.dwBitLen = data[4];
    out.dwNameLen = data[8];
    
    BYTE* ptr = &data[9];
    while (!(*ptr)) {
        ++ptr;
    }

    //CHAR* szName = new CHAR[out.dwNameLen]{0};
    for (int i = 0; i < out.dwNameLen - 1; i++) {
        out.szName[i] = *ptr;
        
        ++ptr;
    }
    out.szName[out.dwNameLen - 1] = 0;


    return out;
}

void printInfo(PROV_ENUMALGS info) {
    printf("---------------------\n");
    printf("algo_id: %d\nlen key: %d\nlen name: %d\nname algo: %s\n", 
        info.aiAlgid, info.dwBitLen, info.dwNameLen, info.szName);
    printf("---------------------\n");
}   