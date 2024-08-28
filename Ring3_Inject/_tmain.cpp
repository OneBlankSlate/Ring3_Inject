#include"_tmain.h"

#ifdef UNICODE
LPFN_LOADLIBRARYW LoadLibrary_Pointer = NULL;
#else
LPFN_LOADLIBRARYA LoadLibrary_Pointer = NULL;
#endif
int _tmain(int argc,char* argv[],char* envp[])
{
	inject(argv[1], argv[2], L"E:\\VS_Code\\Ring3_Inject\\Debug\\Dll.dll");
	return 0;
}
void inject(char* ImageName,char* flag,const wchar_t* DllPath)
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
	{
		register_inject(DllPath);     //��ò�Ҫ���Ը÷���
		break;
	}
	}
}

void apc_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath)
{
	LPVOID virtual_address = NULL;
	int last_error = 0;
	std::vector<DWORD> thread_identity{};
	HMODULE  kernel32_module_base = NULL;
	HANDLE thread_handle = INVALID_HANDLE_VALUE;
	virtual_address = VirtualAllocEx(ProcessHandle, NULL, (_tcslen(DllPath)+1)*2, MEM_COMMIT, PAGE_READWRITE);
	if (virtual_address == NULL){
		last_error = GetLastError();
		goto Exit;
	}
	if (WriteProcessMemory(ProcessHandle, virtual_address, DllPath, (_tcslen(DllPath) + 1) * 2, NULL) == FALSE){
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
#ifdef UNICODE
	LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryW");
#else
	LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryA");
#endif
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

void create_remote_thread(HANDLE ProcessHandle,DWORD ProcessIdentity, const wchar_t* DllPath){
	void* _LoadLibrary_= _PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, (char*)"kernel32.dll", (char*)"LoadLibraryW");
	//2.��Ŀ�����������ռ�
	LPVOID base_address = VirtualAllocEx(ProcessHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//3.д��DLL·��
	SIZE_T write_length = 0;
	BOOL ret = WriteProcessMemory(ProcessHandle, base_address, DllPath, ((wcslen(DllPath) + 1) * 2), &write_length);
	if (ret == FALSE){
		MessageBox(NULL, _T("WriteProcessMemory failed!"), _T("Error"), MB_OK);
		return;
	}
	HANDLE thread_handle=CreateRemoteThread(ProcessHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)_LoadLibrary_, (LPVOID)base_address, NULL, NULL);

}
void hook_eip_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath){
	CONTEXT	thread_context = { 0 };
	int     last_error = 0;
	PVOID   virtual_address = NULL;
	std::vector<DWORD> thread_identity{};
	HANDLE  thread_handle = NULL;
	PUINT8	dll_address_in_shell = NULL;
	_THREAD_HELPER_::get_thread_id(ProcessIdentity, thread_identity);   //�õ�Ŀ����̵������߳�ID
	if (_MEMORY_HELPER_::IsBadReadPtr(DllPath, (_tcslen(DllPath)+1)*2)){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	virtual_address = VirtualAllocEx(ProcessHandle, NULL,sizeof(__ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);  //Ŀ����̿ռ������ڴ�
	if (virtual_address == NULL){
		release(virtual_address, thread_handle, ProcessHandle);
	}
	dll_address_in_shell = __ShellCode + 29;
	memcpy(dll_address_in_shell, DllPath, (_tcslen(DllPath) + 1) * 2);  //��Dll����·������Ŀ����̿ռ���   
	*(PULONG)(__ShellCode + 3) = (ULONG_PTR)virtual_address + 29;     	//Push Address 
#ifdef UNICODE
	LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryW");
#else
	LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)_PE_HELPER_::get_remote_proc_address(ProcessIdentity, ProcessHandle, "kernel32.dll", "LoadLibraryA");
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

void set_window_hookex_inject(HANDLE ProcessHandle, DWORD ProcessIdentity, const wchar_t* DllPath)
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
	module_base = LoadLibrary(DllPath);
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

BOOL register_inject(const wchar_t* DllPath)
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
	isok = RegSetValueEx(key_handle, _T("AppInit_DLLs"), 0, REG_SZ, bufferdata, (_tcslen(DllPath) + 1));	//д���ֵ
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