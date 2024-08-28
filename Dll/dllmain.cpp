// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include<tchar.h>
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::MessageBox(NULL, _T("成功注入目标程序"), _T("标题"), NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


void Sub_1()
{

    HANDLE ProcessIdentify = (HANDLE)GetCurrentProcessId();

    TCHAR v1[MAX_PATH] = { 0 };

    _stprintf_s(v1, _T("%d  Sub_1()"), ProcessIdentify);
    MessageBox(NULL, v1, _T("Injection"), 0);
}
