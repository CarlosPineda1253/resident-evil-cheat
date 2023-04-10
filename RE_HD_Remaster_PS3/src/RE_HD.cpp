//============================================================================
// Name        : RE4_cheat.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "RE_HD.h"

clock_t start;

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
// Command to compile for cython with "H:\Python27\python setup.py build_ext --inplace"
unsigned long PrintProcessNameAndID(unsigned long processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	TCHAR resident_name[MAX_PATH] = TEXT("rpcs3.exe");

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

Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, int count_to_find)
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
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS || mbi.State == MEM_MAPPED) {
			unsigned char* buffer = new unsigned char[mbi.RegionSize];
			int res = ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, NULL);
			if (res != 0) {
                std::vector<unsigned char> vec;
                vec.assign(buffer, buffer + mbi.RegionSize);

                for (UINT64 i = 0; i < mbi.RegionSize; i++){
                	 if (buffer[i] == to_find[0]){
						for (int z = 1; z < count_to_find; z++){
							if (buffer[i+z] != to_find[z]){
								break;
							}
							if (z == (count_to_find - 1)){
								addr_find.Addr = (unsigned long long)addr;
								addr_find.Index = i;
								addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
								std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
								clock_t end = clock();
								std::cout << "Tardo: " << ((float) end - start)/CLOCKS_PER_SEC << std::endl;
								return addr_find;
							}
						}
                	 }
                }

                /*
                std::vector<unsigned char>::iterator res_s = std::search(vec.begin(), vec.end(), to_find.begin(), to_find.end() );
                if (res_s != vec.end()){
                	delete buffer;

                	addr_find.Addr = (unsigned long long)addr;
					addr_find.Index = std::distance( vec.begin(), res_s );
					addr_find.Addr_Find = ((unsigned long long)addr) + ((unsigned long long)addr_find.Index);
					std::cout << "Index: " << (unsigned long long)addr_find.Index << " Addr: " << (unsigned long long)addr << " Addr_find: " << addr_find.Addr_Find << std::endl;
					clock_t end = clock();
					std::cout << "Tardo: " << ((float) end - start)/CLOCKS_PER_SEC << std::endl;
					return addr_find;
                }
				*/
			}
			delete buffer;
		}
		addr += mbi.RegionSize;
	}
	CloseHandle(hProcess);
	addr_find.Addr_Find = 0;
	return addr_find;
}

void write_healt (void* ptr, Addr_Info ptr2){
	HANDLE* hProcess = (HANDLE*) ptr;
	Addr_Info addr_healt_info = (Addr_Info) ptr2;
	INT16 health = 0xC03;
	UINT8 Mem_Read_Health[2];
	UINT8 Mem_Read_Health_NULL[2];
	memset(Mem_Read_Health_NULL, 0x00, sizeof(Mem_Read_Health_NULL));
	DWORD lpExitCode;
	while (TRUE){
		GetExitCodeProcess(hProcess, &lpExitCode);
		if (lpExitCode != STILL_ACTIVE){
			return;
		}
		ReadProcessMemory(hProcess, (void*)addr_healt_info.Addr_Find, Mem_Read_Health, sizeof(health), nullptr);
		if (true == memcmp(Mem_Read_Health, Mem_Read_Health_NULL, sizeof(Mem_Read_Health))){
			WriteProcessMemory(hProcess, (void*)addr_healt_info.Addr_Find, &health, sizeof(health), nullptr);
			Sleep(20000);
		}
		else{
			Sleep(20000);
		}
	}
}

void write_ammo (void* ptr, Addr_Info ptr2){
	HANDLE* hProcess = (HANDLE*) ptr;
	Addr_Info addr_ammo_info = (Addr_Info) ptr2;
	item_struct items[Number_items];
	item_struct items_null[Number_items];
	memset(items_null, 0x00, sizeof(items_null));
	unsigned long long addr_init = addr_ammo_info.Addr_Find;
	DWORD lpExitCode;
	DWORD addr;
	while (TRUE){
		GetExitCodeProcess(hProcess, &lpExitCode);
		if (lpExitCode != STILL_ACTIVE){
			return;
		}
		ReadProcessMemory(hProcess, (void*)addr_init, items, Inventory_Bytes, nullptr);
		if (true == memcmp(items, items_null, sizeof(items))){
			for(int a = 0; a < Number_items; a++){
				if (items[a].item == Magnum){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == handgun){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 15;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == first_aid_spray_box){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Shotgun){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 8;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
			}
			Sleep(800);
		}else{
			Sleep(5000);
		}
	}
}


int main(void)
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;	DWORD resident_evil_id, null_id = 0;
	unsigned int i;
	HANDLE hProcess;

	/* Convert string to hex buffer
	std::string convert_s = "00 00 00 00 00 00 00 01 00 00 00 01 01 01 00 01 AF F7 8B 4F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF CF 9E 35 37 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF 7A 8C C8 63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF 7D 16 DF 52 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF E3 5F C3 A8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF B4 0F BF E7 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF C9 E7 73 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF 6F D4 7A 9F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AA C1 38 FF FF FF FF 00 00 FF FF 35 61 7D 4A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 44 7A 00 00 32 86 92 40 68 77 B5 CF 80 00 00 02 00 00 00 00 80 00 00 02 00 00";
	for(i = 0; i < convert_s.size(); i += 3){
		std::string sub_s = "";
		sub_s.clear();
		sub_s = convert_s.substr(i, 3);
		sub_s.erase(2, 1);
		std::cout << "0x" << sub_s << ", ";
	}
	*/

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
			    static const unsigned char arr1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0xAF, 0xF7, 0x8B, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xCF, 0x9E, 0x35, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x7A, 0x8C, 0xC8, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x7D, 0x16, 0xDF, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xE3, 0x5F, 0xC3, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xB4, 0x0F, 0xBF, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xC9, 0xE7, 0x73, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x6F, 0xD4, 0x7A, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xC1, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x35, 0x61, 0x7D, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x7A, 0x00, 0x00, 0x32, 0x86, 0x92, 0x40, 0x68, 0x77, 0xB5, 0xCF, 0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x02, 0x00, 0x00 };
				static const unsigned char arr2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xE4, 0x4E, 0xD0, 0x31, 0xD5, 0xFD, 0xA0, 0x80, 0x00, 0xE4, 0x82, 0x82, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xD6, 0x06, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xD5, 0xFD, 0xD0, 0x31, 0xE4, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0xE4, 0x7F, 0x42, 0x00, 0x00, 0x02, 0x00, 0x0E, 0x47, 0xA0, 0x00, 0x00, 0x00, 0x30, 0x00, 0xAB, 0x19, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x95, 0x02, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			    std::vector<unsigned char> to_find1 (arr1, arr1 + sizeof(arr1) / sizeof(arr1[0]) );
				std::vector<unsigned char> to_find2 (arr2, arr2 + sizeof(arr2) / sizeof(arr2[0]) );

				start = clock();
				Addr_Info add_health = Search_Memory(aProcesses[i], to_find1, Bytes_offset_health);
				start = clock();
				add_health.Addr_Find += Bytes_offset_health;
				Addr_Info add_inventory = Search_Memory(aProcesses[i], to_find2, Bytes_offset_inventory);
				add_inventory.Addr_Find += Bytes_offset_inventory + 12;

				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
				std::thread th1(write_healt, (void *) hProcess, add_health);
				std::thread th2(write_ammo, (void *) hProcess, add_inventory);
				HWND myConsole = GetConsoleWindow();
				ShowWindow(myConsole, 0);
				DWORD lpExitCode;

				while(TRUE){
					GetExitCodeProcess(hProcess, &lpExitCode);
					if (lpExitCode != STILL_ACTIVE){
						return 0;
					}
					Sleep(1000);
				}
			}
		}
	}
	return 0;
}
