#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <iostream>
#include <string>
#include "Tasks.h"



int main() {
    Task1();
    int type = cin("Enter type: "); //Ввод с cmd

    LPTSTR psName = Task2(type);
    
    HCRYPTPROV hCryptProv = Task3(psName, type);
    
    LPCWSTR nameContainer = L"LexaBank";
    Task4(hCryptProv, psName, type, nameContainer); //Создали контейнер с именем {nameContainer}
    printNamesContFromProv(hCryptProv); //Выводим все контейнеры нашего выбранного провайдера {hCryptProv}

    Task5(hCryptProv, psName, type, nameContainer); //Удаляем контейнер с именем {nameContainer} из провайдера {hCryptProv}
    
    LocalFree(psName);
    if (CryptReleaseContext(hCryptProv, 0)) {
        printf("Context successfull deleted\n");
    }
    else {
        printf("Context doesn't delete\n");
    }
    return 0;
}