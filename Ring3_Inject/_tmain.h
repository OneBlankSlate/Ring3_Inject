#pragma once
#include<iostream>
#include<tchar.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<vector> 
#include"PeHelper.h"
#include"ThreadHelper.h"
#include"Common.h"
#include"ProcessHelper.h"
#include"MemoryHelper.h"
#include"RegisterHelper.h"

/*
远程线程注入
APC注入
Hook Eip注入
SetWindowHookEx注入
注册表注入
修改导入表注入
*/


#define BUFFER_SIZE 0x30000

/* Alignment Macros */
#define ALIGN_DOWN_BY(size, align) \
    ((ULONG_PTR)(size) & ~((ULONG_PTR)(align) - 1))

#define ALIGN_UP_BY(size, align) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(size) + align - 1), align))

#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
#define STATUS_SUCCESS                  (NTSTATUS)0x00000000



#define REMOTE_THREAD 0
#define APC_INJECOT   1
#define HOOK_EIP      2
#define SETWINDOWHOOKEX  3
#define REGISTER_INJECT  4
#define MODIFY_IMPORT_TABLE_INJECT 5
void inject(char* ImageName, char* flag, const wchar_t* DllPath);

void create_remote_thread(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath);
void apc_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath);
void hook_eip_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath);
void set_window_hookex_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath);
BOOL register_inject(const wchar_t* DllPath);          //系统范围内的注入，无需进程句柄与ID
NTSTATUS modify_import_table_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath, const TCHAR* DLLExportFunc);
ULONG  find_image_base_address_by_peb(HANDLE ProcessHandle);
void release(PVOID lpAddress, HANDLE ThreadHandle, HANDLE ProcessHandle);












