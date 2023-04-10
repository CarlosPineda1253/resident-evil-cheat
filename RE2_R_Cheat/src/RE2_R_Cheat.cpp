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

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

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
		//_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);
		CloseHandle(hProcess);
		return processID;
	}
	else {
	    //_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);
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
	Addr_Info addr_find;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (NULL == hProcess){
		addr_find.Addr_Find = 0;
		return addr_find;
	}

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS) {
			unsigned char* buffer = new unsigned char[mbi.RegionSize];
			int res = ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, NULL);
			if (res != 0) {
                std::vector<unsigned char> vec;
                vec.assign(buffer, buffer + mbi.RegionSize);

                std::vector<unsigned char>::iterator res_s = std::search(vec.begin(), vec.end(), to_find.begin(), to_find.end());
                if (res_s != vec.end()){
                	delete buffer;

                	addr_find.Addr = (unsigned long long)addr;
					addr_find.Index = std::distance( vec.begin(), res_s );
					addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
					std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
					return addr_find;
                }
			}
			delete buffer;
		}
		addr += mbi.RegionSize;
	}
	CloseHandle(hProcess);
	addr_find.Addr_Find = 0;
	return addr_find;
}

Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, unsigned long long offset)
{
    HANDLE hProcess;
	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = 0;
	Addr_Info addr_find;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (NULL == hProcess){
		addr_find.Addr_Find = 0;
		return addr_find;
	}

	addr = (unsigned char *) offset;

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS) {
			unsigned char* buffer = new unsigned char[mbi.RegionSize];
			int res = ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, NULL);
			if (res != 0) {
                std::vector<unsigned char> vec;
                vec.assign(buffer, buffer + mbi.RegionSize);
                std::vector<unsigned char>::iterator res_s = std::search(vec.begin(), vec.end(), to_find.begin(), to_find.end());
                if (res_s != vec.end()){
                	delete buffer;
					addr_find.Addr = (unsigned long long)addr;
					addr_find.Index = std::distance( vec.begin(), res_s );
					addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
					std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
					return addr_find;
                }
			}
			delete buffer;
		}
		addr += mbi.RegionSize;
	}
	CloseHandle(hProcess);
	addr_find.Addr_Find = 0;
	return addr_find;
}

unsigned long long PCmain()
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    static const unsigned char arr[] = { (unsigned char)0x52, (unsigned char)0x01, (unsigned char)0x8B,
			                                        (unsigned char)0xD7, (unsigned char)0xEB, (unsigned char)0x0A,
			                                        (unsigned char)0x8B, (unsigned char)0x51, (unsigned char)0x58,
			                                        (unsigned char)0xEB, (unsigned char)0x05};
				std::vector<unsigned char> to_find (arr, arr + sizeof(arr) / sizeof(arr[0]) );
			    Addr_Info addr_r = Search_Memory(aProcesses[i], to_find);
				if (addr_r.Addr_Find)
				    return addr_r.Addr_Find;
			}
		}
	}

	return 0;
}

unsigned long long PCmain_ammo_Matilda()
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    static const unsigned char arr[] = { (unsigned char)0x8B, (unsigned char)0x41, (unsigned char)0x20,
			                                        (unsigned char)0xEB, (unsigned char)0x02, (unsigned char)0x33,
			                                        (unsigned char)0xC0, (unsigned char)0x48, (unsigned char)0x85,
			                                        (unsigned char)0xD2 };
			    std::vector<unsigned char> to_find (arr, arr + sizeof(arr) / sizeof(arr[0]) );
			    //std::vector<unsigned char> to_find = { (unsigned char)0x8B, (unsigned char)0x41, (unsigned char)0x20, (unsigned char)0xEB, (unsigned char)0x02, (unsigned char)0x33, (unsigned char)0xC0, (unsigned char)0x48, (unsigned char)0x85, (unsigned char)0xD2 };
				Addr_Info addr_r = Search_Memory(aProcesses[i], to_find);
				if (addr_r.Addr_Find)
					return addr_r.Addr_Find;
			}
		}
	}

	return 0;
}

unsigned long long Search_Memory_Wildcard(DWORD process_id, std::vector<unsigned char> to_find1, std::vector<unsigned char> to_find2, unsigned long long Start_Addr){
    HANDLE hProcess;
    Addr_Info addr_r1;
    Addr_Info addr_r2;
    unsigned char buffer[Size_Buff_Items];

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    int res = ReadProcessMemory(hProcess, (unsigned char*) Start_Addr, buffer, Size_Buff_Items, NULL);
    if (res != 0) {
        std::vector<unsigned char> vec;
        vec.assign(buffer, buffer + Size_Buff_Items);
        std::vector<unsigned char>::iterator res_s = std::search(vec.begin(), vec.end(), to_find1.begin(), to_find1.end());
        if (res_s != vec.end()){
            addr_r1.Index = std::distance( vec.begin(), res_s );
            res_s = std::search(vec.begin() + addr_r1.Index, vec.end(), to_find2.begin(), to_find2.end());
            if (res_s != vec.end()){
                addr_r2.Index = std::distance( vec.begin(), res_s );
                if ((addr_r2.Index - addr_r1.Index) == 18){
                    return Start_Addr + ((unsigned long long)addr_r1.Index);
                }
            }
        }
    }
    return 0;
}

unsigned long long PCmain_Ammo_Shotgun(unsigned long long Start_Addr)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;


	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    //00 00 00 00 00 0B 00 00 00 03 00 00 00 00 00 00 00
			    static const unsigned char arr1[] = { (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x0B,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x03, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00};
				//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F7
				static const unsigned char arr2[] = {(unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0xB8, (unsigned char)0xF7};

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );
				return Search_Memory_Wildcard(aProcesses[i], to_find1, to_find2, Start_Addr);
			}
		}
	}
	return 0;
}

unsigned long long PCmain_Ammo_M19(unsigned long long Start_Addr)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    //00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00
			    static const unsigned char arr1[] = { (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x02,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00};
				//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F7
				static const unsigned char arr2[] = {(unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0xB8, (unsigned char)0xF7};

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );
				return Search_Memory_Wildcard(aProcesses[i], to_find1, to_find2, Start_Addr);
			}
		}
	}
	return 0;
}

unsigned long long PCmain_Ammo_Lightning_Hawk(unsigned long long Start_Addr)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    //00 00 00 00 00 1F 00 00 00 03 00 00 00 00 00 00 00
			    static const unsigned char arr1[] = { (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x1F,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x03, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00};
				//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F7
				static const unsigned char arr2[] = {(unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0xB8, (unsigned char)0xF7};

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );
				return Search_Memory_Wildcard(aProcesses[i], to_find1, to_find2, Start_Addr);
			}
		}
	}
	return 0;
}

unsigned long long PCmain_Hand_Grenade(unsigned long long Start_Addr)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    //00 00 00 00 00 41 00 00 00 00 00 00 00 00 00 00 00
			    static const unsigned char arr1[] = { (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x41,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00};
				//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F7
				static const unsigned char arr2[] = {(unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0xB8, (unsigned char)0xF7};

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );
				return Search_Memory_Wildcard(aProcesses[i], to_find1, to_find2, Start_Addr);
			}
		}
	}
	return 0;
}

unsigned long long PCmain_Flash_Grenade(unsigned long long Start_Addr)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
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
			    //00 00 00 00 00 42 00 00 00 00 00 00 00 00 00 00 00
			    static const unsigned char arr1[] = { (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x42,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
			                                        (unsigned char)0x00, (unsigned char)0x00};
				//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F7
				static const unsigned char arr2[] = {(unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0x00, (unsigned char)0x00, (unsigned char)0x00,
				                                    (unsigned char)0xB8, (unsigned char)0xF7};

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );
				return Search_Memory_Wildcard(aProcesses[i], to_find1, to_find2, Start_Addr);
			}
		}
	}
	return 0;
}
