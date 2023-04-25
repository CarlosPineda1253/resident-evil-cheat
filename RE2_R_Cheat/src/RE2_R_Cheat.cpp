//============================================================================
// Name        : RE4_cheat.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "RE2_R_Cheat.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
// Command to compile for cython with "H:\Python27\python setup.py build_ext --inplace"
unsigned long PrintProcessNameAndID(unsigned long processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	TCHAR resident_name[MAX_PATH] = TEXT("re2.exe");

	// Get a handle to the process.
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	// Get the process name.
	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded, 0x03))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// Print the process name and identifier.
	if (_tcscmp(szProcessName, resident_name) == 0) {
		CloseHandle(hProcess);
		return processID;
	}
	else {
		CloseHandle(hProcess);
		return 0;
	}

	// Release the handle to the process.

	CloseHandle(hProcess);
}

Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find)
{
    HANDLE hProcess;
	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = 0;
	Addr_Info addr_find = {}, null_addr_find = {};

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (NULL == hProcess){
		addr_find.Addr_Find = 0;
		return addr_find;
	}

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS || mbi.State == MEM_MAPPED) {
			unsigned char* d_array = (unsigned char*) malloc(mbi.RegionSize);
			int res = ReadProcessMemory(hProcess, addr, d_array, mbi.RegionSize, NULL);
			if (res != 0) {
				std::vector<unsigned char> buffer (d_array, d_array + mbi.RegionSize);
				free(d_array);
				for (UINT64 i = 0; i < mbi.RegionSize; i++){
					 if (buffer.at(i) == to_find.at(0)){
						for (unsigned int z = 1; z < to_find.size(); z++){
							if (buffer.at(i+z) != to_find.at(z))
								break;
							if (z == (to_find.size() - 1)){
								addr_find.Addr = (unsigned long long)addr;
								addr_find.Index = i;
								addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
								std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
								CloseHandle(hProcess);
								return addr_find;
							}
						}
					 }
				}
			}
		}
		addr += mbi.RegionSize;
	}
	CloseHandle(hProcess);
	return null_addr_find;
}

Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, unsigned long long offset)
{
    HANDLE hProcess;
	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = 0;
	Addr_Info addr_find = {}, null_addr_find = {};
	BOOL flag_first_time = true;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (NULL == hProcess){
		return null_addr_find;
	}

    addr = (unsigned char *) offset;

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS || mbi.State == MEM_MAPPED) {
			unsigned char* d_array = (unsigned char*) malloc(mbi.RegionSize);
			int res = ReadProcessMemory(hProcess, addr, d_array, mbi.RegionSize, NULL);
			if (res != 0) {
				std::vector<unsigned char> buffer (d_array, d_array + mbi.RegionSize);
				free(d_array);
                for (UINT64 i = 0; i < mbi.RegionSize; i++){
                	 if (buffer.at(i) == to_find.at(0)){
						for (unsigned int z = 1; z < to_find.size(); z++){
							if (buffer.at(i+z) != to_find.at(z)){
								break;
							}
							if (z == (to_find.size() - 1)){
								addr_find.Addr = (unsigned long long)addr;
								addr_find.Index = i;
								addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
								std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
								CloseHandle(hProcess);
								return addr_find;
							}
						}
                	 }
                }
			}
		}
		if (flag_first_time){
			addr = (unsigned char*)mbi.BaseAddress;
			flag_first_time = false;
		}
		addr += mbi.RegionSize;
	}
	CloseHandle(hProcess);
	return null_addr_find;
}

Addr_Info PCmain()
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	DWORD resident_evil_id, null_id = 0;
	unsigned int i;
	LPVOID addr_program;
	Addr_Info addr_health_info;
	addr_health_info.Addr = 0;
	addr_health_info.Index = 0;
	addr_health_info.Addr_Find = 0;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return addr_health_info;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			resident_evil_id = PrintProcessNameAndID(aProcesses[i]);
			if (null_id != resident_evil_id) {
				HMODULE hMod[250];
				DWORD cbNeeded1;
				LPSTR szModuleName = (LPSTR) malloc(MAX_PATH);
				BOOL flag_addr_program = false;

				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
				if (EnumProcessModulesEx(hProcess, hMod, sizeof(hMod), &cbNeeded1, LIST_MODULES_ALL))
				{
					for (unsigned int z = 0; z < (cbNeeded / sizeof(HMODULE)); z++ ){
						GetModuleFileNameExA(hProcess, hMod[z], szModuleName, MAX_PATH);
						std::string s2 = szModuleName;
						if ((s2 == "H:\\SteamLibrary\\steamapps\\common\\RESIDENT EVIL 2  BIOHAZARD RE2\\re2.exe") && (!flag_addr_program)) {
							addr_program = hMod[z];
							flag_addr_program = true;
						}
					}
				}
				free(szModuleName);
				CloseHandle(hProcess);

                //EB 0A 8B 51 58 EB 05 BA 01 00 00 00 48 8B
			    static const unsigned char arr[] = { (unsigned char)0xEB, (unsigned char)0x0A, (unsigned char)0x8B,
			                                        (unsigned char)0x51, (unsigned char)0x58, (unsigned char)0xEB,
			                                        (unsigned char)0x05, (unsigned char)0xBA, (unsigned char)0x01,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
													(unsigned char)0x48, (unsigned char)0x8B};
				std::vector<unsigned char> to_find (arr, arr + sizeof(arr) / sizeof(arr[0]) );
			    Addr_Info addr_r = Search_Memory(aProcesses[i], to_find, (unsigned long long)addr_program);
				if (addr_r.Addr_Find)
				    return addr_r;
			}
		}
	}

	return addr_health_info;
}

Addr_Info PCmain_Ammo_Matilda()
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	DWORD resident_evil_id, null_id = 0;
	LPVOID addr_program;
	unsigned int i;
	Addr_Info addr_ammo_info;
	addr_ammo_info.Addr = 0;
	addr_ammo_info.Addr_Find = 0;
	addr_ammo_info.Index = 0;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return addr_ammo_info;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			resident_evil_id = PrintProcessNameAndID(aProcesses[i]);
			if (null_id != resident_evil_id) {
				HMODULE hMod[250];
				DWORD cbNeeded1;
				LPSTR szModuleName = (LPSTR) malloc(MAX_PATH);
				BOOL flag_addr_program = false;

				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
				if (EnumProcessModulesEx(hProcess, hMod, sizeof(hMod), &cbNeeded1, LIST_MODULES_ALL))
				{
					for (unsigned int z = 0; z < (cbNeeded / sizeof(HMODULE)); z++ ){
						GetModuleFileNameExA(hProcess, hMod[z], szModuleName, MAX_PATH);
						std::string s2 = szModuleName;
						if ((s2 == "H:\\SteamLibrary\\steamapps\\common\\RESIDENT EVIL 2  BIOHAZARD RE2\\re2.exe") && (!flag_addr_program)) {
							addr_program = hMod[z];
							flag_addr_program = true;
						}
					}
				}
				free(szModuleName);
				CloseHandle(hProcess);

			    // 8B 41 20 EB 02 8B C2 89 44 24 50 48 8D
			    unsigned char arr[] = { (unsigned char)0x8B, (unsigned char)0x41, (unsigned char)0x20,
			                                        (unsigned char)0xEB, (unsigned char)0x02, (unsigned char)0x8B,
			                                        (unsigned char)0xC2, (unsigned char)0x89, (unsigned char)0x44,
			                                        (unsigned char)0x24, (unsigned char)0x50, (unsigned char)0x48,
													(unsigned char)0x8D};
			    std::vector<unsigned char> to_find (std::begin(arr), std::end(arr));
			    //std::vector<unsigned char> to_find = { (unsigned char)0x8B, (unsigned char)0x41, (unsigned char)0x20, (unsigned char)0xEB, (unsigned char)0x02, (unsigned char)0x33, (unsigned char)0xC0, (unsigned char)0x48, (unsigned char)0x85, (unsigned char)0xD2 };
				Addr_Info addr_r = Search_Memory(aProcesses[i], to_find, (unsigned long long) addr_program);
				if (addr_r.Addr_Find)
					return addr_r;
			}
		}
	}

	return addr_ammo_info;
}

Addr_Info Search_Memory_Wildcard(DWORD process_id, std::vector<unsigned char> to_find, unsigned long long Start_Addr){
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;
    Addr_Info addr_find = {};
    BOOL flag_first_time = true;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);

    if (NULL == hProcess){
        return addr_find;
    }

    addr = (unsigned char*) Start_Addr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS || mbi.State == MEM_MAPPED) {
            unsigned char* d_array = (unsigned char*) malloc(mbi.RegionSize);
            int res = ReadProcessMemory(hProcess, mbi.BaseAddress, d_array, mbi.RegionSize, NULL);
            if (res != 0) {
            	std::vector<unsigned char> buffer (d_array, d_array + mbi.RegionSize);
            	free(d_array);
                for (UINT64 i = 0; i < mbi.RegionSize; i++){
                    if ((buffer.at(i) == to_find.at(0)) || (to_find.at(0) == '*')){
                        for (unsigned long long int z = 1; z < to_find.size(); z++){
                            if (buffer.at(z+i) != to_find.at(z)){
                                if (to_find.at(z) != '*'){
                                    break;
                                }
                            }
                            if (z == (to_find.size() - 1)){
                                addr_find.Addr = (unsigned long long)mbi.BaseAddress;
                                addr_find.Index = i;
                                addr_find.Addr_Find = ((unsigned long long)mbi.BaseAddress) + ((unsigned long long)addr_find.Index);
                                std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
                                return addr_find;
                            }
                        }
                    }
                }
            }
        }
        if (flag_first_time){
        	addr = (unsigned char*)mbi.BaseAddress;
        	flag_first_time = false;
        }
        addr += mbi.RegionSize;
    }
    CloseHandle(hProcess);
    return addr_find;
}

Addr_Info PCmain_Ammo_Shotgun(unsigned long long offset_addr, DWORD aProcesses)
{
	// Get the list of process identifiers.
	Addr_Info addr_info = {}, null_addr_info = {};

	unsigned char arr1[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFB, '*', '*', '*', '*',
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x0B, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0xFB, '*', '*', '*', '*', 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			'*', 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4B,
			'*', '*', '*', '*', 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			'*', '*', '*', '*', '*', '*', 0x00, 0x00, '*', '*', '*', '*', '*', '*',
			0x00, 0x00};

	std::vector<unsigned char> to_find (std::begin(arr1), std::end(arr1));
	addr_info = Search_Memory_Wildcard(aProcesses, to_find, offset_addr);
	if (addr_info.Addr_Find){
		return addr_info;
	}
	return null_addr_info;
}

Addr_Info PCmain_Ammo_M19(unsigned long long offset_addr, DWORD aProcesses)
{
	// Get the list of process identifiers.
	Addr_Info addr_info = {}, null_addr_info = {};

	//TODO find the third number in array for this item
	unsigned char arr1[] = {0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFB, '*', '*', '*', '*',
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0xFB, '*', '*', '*', '*', 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			'*', 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4B,
			'*', '*', '*', '*', 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			'*', '*', '*', '*', '*', '*', 0x00, 0x00, '*', '*', '*', '*', '*', '*',
			0x00, 0x00};

	std::vector<unsigned char> to_find1 (std::begin(arr1), std::end(arr1));
	addr_info = Search_Memory_Wildcard(aProcesses, to_find1, offset_addr);
	if (addr_info.Addr_Find){
		return addr_info;
	}
	return null_addr_info;
}

Addr_Info PCmain_Ammo_Lightning_Hawk(unsigned long long offset_addr, DWORD aProcesses)
{
	// Get the list of process identifiers.
	Addr_Info addr_info = {}, null_addr_info = {};

	unsigned char arr1[] = {0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFB, '*', '*', '*', '*',
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x1F, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0xFB, '*', '*', '*', '*', 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			'*', 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4B,
			'*', '*', '*', '*', 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			'*', '*', '*', '*', '*', '*', 0x00, 0x00, '*', '*', '*', '*', '*', '*',
			0x00, 0x00};

	std::vector<unsigned char> to_find (std::begin(arr1), std::end(arr1));
	addr_info = Search_Memory_Wildcard(aProcesses, to_find, offset_addr);
	if (addr_info.Addr_Find){
		return addr_info;
	}
	return null_addr_info;
}

Addr_Info PCmain_Grenade(unsigned long long offset_addr, DWORD aProcesses)
{
	// Get the list of process identifiers.
	Addr_Info addr_info = {}, null_addr_info = {};

	unsigned char arr1[] = {0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFB, '*', '*', '*', '*',
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0xFB, '*', '*', '*', '*', 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			'*', 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4B,
			'*', '*', '*', '*', 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			'*', '*', '*', '*', '*', '*', 0x00, 0x00, '*', '*', '*', '*', '*', '*',
			0x00, 0x00};

	std::vector<unsigned char> to_find1 (std::begin(arr1), std::end(arr1));
	addr_info = Search_Memory_Wildcard(aProcesses, to_find1, offset_addr);
	if (addr_info.Addr_Find){
		return addr_info;
	}
	return null_addr_info;
}

Addr_Info PCmain_Flash_Grenade(unsigned long long offset_addr, DWORD aProcesses)
{
	// Get the list of process identifiers.
	Addr_Info addr_info = {}, null_addr_info = {};

	unsigned char arr1[] = {0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFB, '*', '*', '*', '*',
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00,
			0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 0xFB, '*', '*', '*', '*', 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			'*', 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xCB, '*', '*', '*', '*', 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4B,
			'*', '*', '*', '*', 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, '*', 0x00,
			'*', '*', '*', '*', '*', '*', 0x00, 0x00, '*', '*', '*', '*', '*', '*',
			0x00, 0x00};

	std::vector<unsigned char> to_find1 (std::begin(arr1), std::end(arr1));
	addr_info = Search_Memory_Wildcard(aProcesses, to_find1, offset_addr);
	if (addr_info.Addr_Find){
		return addr_info;
	}
	return null_addr_info;
}


int loop_health(Addr_Info addr_health, DWORD resident_evil_id){
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, resident_evil_id);
	DWORD Bytes_Health = 2;
	DWORD Value_Health = 0x04B0;
	while(true){
		sleep(10);
		WriteProcessMemory(hProcess, (void*)addr_health.Addr_Context, &Value_Health, Bytes_Health, nullptr);
	}

	return 0;
}

int loop_inv(DWORD resident_evil_id, Addr_Info addr_matilda, Addr_Info addr_shotgun, Addr_Info addr_m19, Addr_Info addr_hawk, Addr_Info addr_grenade_hand, Addr_Info addr_grenade_flash){
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, resident_evil_id);
	DWORD Bytes_Ammo = 1;
	DWORD Value_Ammo_Matilda = 0x14;
	DWORD Value_Ammo_Guns = 0x07;
	DWORD Value_Grenade = 0x04;
	DWORD Offset_ammo = 0x5A;

	unsigned long long ammo_shotgun = addr_shotgun.Addr_Find+Offset_ammo;
	unsigned long long ammo_m19 = addr_m19.Addr_Find+Offset_ammo;
	unsigned long long ammo_hawk = addr_hawk.Addr_Find+Offset_ammo;
	unsigned long long ammo_grenade = addr_grenade_hand.Addr_Find+Offset_ammo;
	unsigned long long ammo_flash_grenade = addr_grenade_hand.Addr_Find+Offset_ammo;

	while(true){
		if (addr_shotgun.Addr_Find){
			WriteProcessMemory(hProcess, (void*)addr_matilda.Addr_Context, &Value_Ammo_Matilda, Bytes_Ammo, nullptr);
		}
		if (addr_shotgun.Addr_Find){
			WriteProcessMemory(hProcess, (void*)ammo_shotgun, &Value_Ammo_Guns, Bytes_Ammo, nullptr);
		}
		if (addr_m19.Addr_Find){
			WriteProcessMemory(hProcess, (void*)ammo_m19, &Value_Ammo_Guns, Bytes_Ammo, nullptr);
		}
		if (addr_hawk.Addr_Find){
			WriteProcessMemory(hProcess, (void*)ammo_hawk, &Value_Ammo_Guns, Bytes_Ammo, nullptr);
		}
		if (addr_grenade_hand.Addr_Find){
			WriteProcessMemory(hProcess, (void*)ammo_grenade, &Value_Grenade, Bytes_Ammo, nullptr);
		}
		if (addr_grenade_flash.Addr_Find){
			WriteProcessMemory(hProcess, (void*)ammo_flash_grenade, &Value_Grenade, Bytes_Ammo, nullptr);
		}
	}
	return 0;
}

BOOL write_mem_custom(LPVOID address_write, BYTE values_buff[], int size, HANDLE hProcess){
	_MEMORY_BASIC_INFORMATION mbi;
	BOOL ret = false;

	VirtualQueryEx(hProcess, address_write, &mbi, sizeof(mbi));
	if (WriteProcessMemory(hProcess, address_write, &values_buff[0], size, nullptr)){
		ret = true;
	}
	FlushInstructionCache(hProcess, (void*)address_write, size);
	return ret;
}

int main(){
	/*
	//Convert string to hex buffer
	unsigned int a;
	std::string convert_s = "** ** ** ** ** ** 00 00 11 00 00 00 00 00 00 00 58 CB ** ** ** ** 00 00 00 00 00 00 00 00 ** 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 FB ** ** ** ** 00 00 01 00 00 00 00 00 ** 00 00 00 00 00 41 00 00 00 00 00 00 00 00 00 00 00 ** 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 FB ** ** ** ** 00 00 01 00 00 00 00 00 ** 00 00 00 00 00 FF FF FF FF 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 58 CB ** ** ** ** 00 00 01 00 00 00 00 00 ** 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 4B ** ** ** ** 00 00 02 00 00 00 00 00 ** 00 ** ** ** ** ** ** 00 00 ** ** ** ** ** ** 00 00";
	for(a = 0; a < convert_s.size(); a += 3){
		std::string sub_s = "";
		sub_s.clear();
		sub_s = convert_s.substr(a, 3);
		sub_s.erase(2, 1);
		std::cout << "0x" << sub_s << ", ";
	}

	return 0;
	*/

	Addr_Info addr_health = PCmain();
	addr_health.Addr_Find += 2;
	Addr_Info addr_matilda = PCmain_Ammo_Matilda();
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for ( i = 0; i < cProcesses; i++ )
	{
		if( aProcesses[i] != 0 )
		{
			resident_evil_id = PrintProcessNameAndID( aProcesses[i] );
			if (null_id != resident_evil_id){
				BYTE cInstruction[] = {0xCC};
				SIZE_T dwReadBytes;
				BYTE m_OriginalInstruction[sizeof(cInstruction)];
				BYTE m_OriginalInstruction_ammo[sizeof(cInstruction)];

				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, resident_evil_id);
				ReadProcessMemory(hProcess, (void*)addr_health.Addr_Find, &m_OriginalInstruction, sizeof(m_OriginalInstruction), &dwReadBytes);
				ReadProcessMemory(hProcess, (void*)addr_matilda.Addr_Find, &m_OriginalInstruction_ammo, sizeof(m_OriginalInstruction_ammo), &dwReadBytes);

				if (DebugActiveProcess(resident_evil_id)){
					DEBUG_EVENT DebugEvent;
					NTSTATUS ContinueStatus = DBG_CONTINUE;
					DWORD ExceptionCode;
					HANDLE hThread;
					BOOL flag_event_ammo = false;
					BOOL flag_event_health = false;

					DebugSetProcessKillOnExit(false);
					if (!write_mem_custom((LPVOID)addr_health.Addr_Find, cInstruction, sizeof(cInstruction), hProcess)){
						return 0;
					}

					while(true){
						if(flag_event_health && flag_event_ammo){
							DebugActiveProcessStop(resident_evil_id);
							std::thread t1(loop_health, addr_health, resident_evil_id);
							unsigned long long address_inventory = addr_matilda.Addr_Context - 0x1F40;
							Addr_Info addr_flash_grenade = PCmain_Flash_Grenade(address_inventory, resident_evil_id);
							Addr_Info addr_m19 = PCmain_Ammo_M19(address_inventory, resident_evil_id);
							Addr_Info addr_hawk = PCmain_Ammo_Lightning_Hawk(address_inventory, resident_evil_id);
							Addr_Info addr_shotgun = PCmain_Ammo_Shotgun(address_inventory, resident_evil_id);
							Addr_Info addr_hand_grenade = PCmain_Grenade(address_inventory, resident_evil_id);
							std::thread t2(loop_inv, resident_evil_id, addr_matilda, addr_shotgun, addr_m19, addr_hawk, addr_hand_grenade, addr_flash_grenade);
							while(true);
						}

						if (WaitForDebugEvent(&DebugEvent, INFINITE)){
							ContinueStatus = DBG_CONTINUE;
							switch( DebugEvent.dwDebugEventCode ){
								case EXCEPTION_DEBUG_EVENT:
									ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
									switch(ExceptionCode){

										case EXCEPTION_BREAKPOINT:
										{
											hThread = OpenThread(THREAD_ALL_ACCESS, false, DebugEvent.dwThreadId);
											CONTEXT lcContext = {};
											lcContext.ContextFlags = CONTEXT_ALL;

											if (GetThreadContext(hThread, &lcContext)){
												lcContext.EFlags |= RESUME_FLAG;
												SetThreadContext(hThread, &lcContext);
											}
											ContinueStatus = DBG_CONTINUE;

											if((lcContext.Rip == (addr_health.Addr_Find + 1)) && (!flag_event_health)){

												if (!write_mem_custom((LPVOID)addr_health.Addr_Find, m_OriginalInstruction, sizeof(m_OriginalInstruction), hProcess))
													return 0;
												addr_health.Addr_Context = lcContext.Rcx + 0x58;
												flag_event_health = true;
												if (GetThreadContext(hThread, &lcContext)){
													lcContext.Rip--;
													lcContext.EFlags |= RESUME_FLAG;
													SetThreadContext(hThread, &lcContext);
												}
												if (!write_mem_custom((LPVOID)addr_matilda.Addr_Find, cInstruction, sizeof(cInstruction), hProcess))
													return 0;

											}else if ((lcContext.Rip == (addr_matilda.Addr_Find + 1)) && (!flag_event_ammo)){

												//Write original instruction
												if (!write_mem_custom((LPVOID)addr_matilda.Addr_Find, m_OriginalInstruction_ammo, sizeof(m_OriginalInstruction_ammo), hProcess))
													return 0;
												addr_matilda.Addr_Context = lcContext.Rcx + 0x20;
												flag_event_ammo = true;
												if (GetThreadContext(hThread, &lcContext)){
													lcContext.Rip--;
													lcContext.EFlags |= RESUME_FLAG;
													SetThreadContext(hThread, &lcContext);
												}
												std::cout << "Addr_Register_Rcx: " << addr_matilda.Addr_Context << std::endl;

											}
											CloseHandle(hThread);
											break;
										}
										case EXCEPTION_ACCESS_VIOLATION:
											std::cout << "Error Access Violation: " << GetLastError() << std::endl;
											break;
										}
									break;

								case CREATE_PROCESS_DEBUG_EVENT:
									CloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
									DebugEvent.u.CreateThread.hThread = DebugEvent.u.CreateProcessInfo.hThread;
									break;

								case CREATE_THREAD_DEBUG_EVENT:
									break;

								case EXIT_THREAD_DEBUG_EVENT:
									break;

								case LOAD_DLL_DEBUG_EVENT:
									CloseHandle(DebugEvent.u.LoadDll.hFile);
									break;

								case EXIT_PROCESS_DEBUG_EVENT:
									break;

								case OUTPUT_DEBUG_STRING_EVENT:
								case UNLOAD_DLL_DEBUG_EVENT:
									break;
								default:
									break;
							}
						}
					if( !ContinueDebugEvent( DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus ) )
						return false;
					}
				}
			}
		}
	}
	return 0;
}
