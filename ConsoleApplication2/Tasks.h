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
    
    LPCWSTR UserName = L"LexaBank";

    HCRYPTPROV hCryptProv;
    BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    if (CryptAcquireContext(&hCryptProv, NULL, pszName, type, 0)) {
        printf("Context has been poluchen\n");
        
    }
    else {
        if (CryptAcquireContext(
            &hCryptProv,
            NULL,
            pszName,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))
        {
            printf("A new key container has been created.\n");
        }
        else
        {
            printf("Could not create a new key container.\n");
            exit(1);
        }
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
    LPSTR pszUserName;
    DWORD dwUserNameLen;
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


    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKey = 0;
    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_SIGNATURE,                   // Спецификация ключа
        &hKey))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }
            

        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_SIGNATURE,
            0,
            &hKey))
        {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");

    }

    // Получение ключа обмена: AT_KEYEXCHANGE
    if (CryptGetUserKey(
        hCryptProv,
        AT_KEYEXCHANGE,
        &hKey))
    {
        printf("An exchange key exists. \n");
    }
    else
    {
        printf("No exchange key is available.\n");
    }

    

    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    wprintf(L"the %s key container.\n", nameContainer);

    
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
    //BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    DWORD dwFlags = CRYPT_FIRST;
    DWORD cbData;

    cbData = 1000;
    CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &cbData, dwFlags);
    PBYTE pbData = new BYTE[cbData];
    if (CryptGetProvParam(
        hCryptProv,
        PP_ENUMCONTAINERS   ,
        pbData,
        &cbData,
        dwFlags))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Name container: %s\n", pbData);
    }
    else
    {
        printf("ERROR_INVALID_HANDLE %d\n", ERROR_INVALID_HANDLE);
        printf("ERROR_INVALID_PARAMETER %d\n", ERROR_INVALID_PARAMETER);
        printf("ERROR_MORE_DATA %d\n", ERROR_MORE_DATA);
        printf("ERROR_NO_MORE_ITEMS %d\n", ERROR_NO_MORE_ITEMS);
        printf("NTE_BAD_FLAGS %d\n", NTE_BAD_FLAGS);
        printf("NTE_BAD_TYPE %d\n", NTE_BAD_TYPE);
        printf("NTE_BAD_UID %d\n", NTE_BAD_UID);
        printf("Error %d\n", GetLastError());
        printf("Error reading CSP name. \n");
        //exit(1);
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
    id = *(ALG_ID*)data;
    BYTE* ptr = &data[0];

    ptr += sizeof(ALG_ID);
    
    //id = data[0] | 8 << data[1] | 16 << data[2] | 24 << data[3];
    out.aiAlgid = id;
    out.dwBitLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);
    out.dwNameLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);
    /*
    while (!(*ptr)) {
        ++ptr;
    }
    */
    strncpy_s(out.szName, sizeof(out.szName), (char*)ptr, out.dwNameLen);
    //CHAR* szName = new CHAR[out.dwNameLen]{0};
    /*
    for (int i = 0; i < out.dwNameLen - 1; i++) {
        out.szName[i] = *ptr;
        
        ++ptr;
    }
    out.szName[out.dwNameLen - 1] = 0;
    */

    return out;
}

void printInfo(PROV_ENUMALGS info) {
    printf("---------------------\n");
    printf("algo_id: %d\nlen key: %d\nlen name: %d\nname algo: %s\n", 
        info.aiAlgid, info.dwBitLen, info.dwNameLen, info.szName);
    printf("---------------------\n");
}   