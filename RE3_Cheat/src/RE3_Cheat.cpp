//============================================================================
// Name        : RE4_cheat.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "RE3_Cheat.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

inline void SwapEndian(UINT16 &val)
{
    val = (val<<8) | (val>>8);
}

DWORD PrintProcessNameAndID( DWORD processID )
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR resident_name[MAX_PATH] = TEXT("BIOHAZARD(R) 3 PC.exe");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID );

    // Get the process name.

    if (NULL != hProcess )
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if ( EnumProcessModulesEx( hProcess, &hMod, sizeof(hMod), &cbNeeded, 0x03 ))
        {
            GetModuleBaseName( hProcess, hMod, szProcessName,
                               sizeof(szProcessName)/sizeof(TCHAR) );
        }
    }

    // Print the process name and identifier.
    if (strcmp(szProcessName, resident_name) == 0){
    	//_tprintf( TEXT("%s  (PID: %u)\n"), szProcessName, processID );
    	CloseHandle( hProcess );
    	return processID;
    }else{
    	CloseHandle( hProcess );
    	return 0;
    }

    // Release the handle to the process.

    CloseHandle( hProcess );
}

void PrintMemoryInfo( DWORD processID )
{
    HANDLE hProcess;
    PROCESS_MEMORY_COUNTERS pmc;

    // Print the process identifier.

    //printf( "\nProcess ID: %u\n", processID );

    // Print information about the memory usage of the process.

    hProcess = OpenProcess(  PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, processID );
    if (NULL == hProcess)
        return;

    if ( GetProcessMemoryInfo( hProcess, &pmc, sizeof(pmc)) )
    {

    	/*
        printf( "\tPageFaultCount: 0x%08X\n", pmc.PageFaultCount );
        printf( "\tPeakWorkingSetSize: 0x%08X\n",
                  pmc.PeakWorkingSetSize );
        printf( "\tWorkingSetSize: 0x%08X\n", pmc.WorkingSetSize );
        printf( "\tQuotaPeakPagedPoolUsage: 0x%08X\n",
                  pmc.QuotaPeakPagedPoolUsage );
        printf( "\tQuotaPagedPoolUsage: 0x%08X\n",
                  pmc.QuotaPagedPoolUsage );
        printf( "\tQuotaPeakNonPagedPoolUsage: 0x%08X\n",
                  pmc.QuotaPeakNonPagedPoolUsage );
        printf( "\tQuotaNonPagedPoolUsage: 0x%08X\n",
                  pmc.QuotaNonPagedPoolUsage );
        printf( "\tPagefileUsage: 0x%08X\n", pmc.PagefileUsage );
        printf( "\tPeakPagefileUsage: 0x%08X\n",
                  pmc.PeakPagefileUsage );
        */
    }

    CloseHandle( hProcess );
}

void write_healt (MODULEINFO ptr, void* ptr2){
	HANDLE* hProcess = (HANDLE*) ptr2;
	MODULEINFO modInfo = (MODULEINFO) ptr;
	INT16 health = 200;
	UINT8 Mem_Read_Health[10];
	UINT8 Mem_Read_Health_NULL[10];
	memset(Mem_Read_Health_NULL, 0x00, sizeof(Mem_Read_Health_NULL));
	unsigned long long init_health = (unsigned long long)modInfo.lpBaseOfDll + Memory_hp;
	DWORD lpExitCode;
	while (TRUE){
		GetExitCodeProcess(hProcess, &lpExitCode);
		if (lpExitCode != STILL_ACTIVE){
			return;
		}
		ReadProcessMemory(hProcess, (void*)init_health, Mem_Read_Health, sizeof(Mem_Read_Health), nullptr);
		if (true == memcmp(Mem_Read_Health, Mem_Read_Health_NULL, sizeof(Mem_Read_Health))){
			WriteProcessMemory(hProcess, (void*)init_health, &health, 1, nullptr);
			Sleep(20000);
		}
		else{
			Sleep(20000);
		}
	}
}

void write_ammo (MODULEINFO ptr, void* ptr2){
	HANDLE* hProcess = (HANDLE*) ptr2;
	MODULEINFO modInfo = (MODULEINFO) ptr;
	item_struct items[Number_items];
	item_struct items_null[Number_items];
	memset(items_null, 0x00, sizeof(items_null));
	unsigned long long addr_init = ((unsigned long long)modInfo.lpBaseOfDll + Init_Inventory) - 17;
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
				if (items[a].item == Assault_Rifle_Auto){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 90;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == handgun){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 15;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Magnum){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 8;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Shotgun){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 25;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == first_aid_spray_box){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Eagle_6){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 8;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == R_Laucher){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == R_Laucher){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == G_Laucher_Grenade){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == G_Laucher_Flame){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == G_Laucher_Acid){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == G_Laucher_Freeze){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Gatling_Gun){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Mine_Thrower){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == M92F_E){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == Benelli_M3S_E){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
				else if (items[a].item == M_Thrower_E){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 5;
					WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
				}
			}
			Sleep(800);
		}else{
			Sleep(5000);
		}
	}
}

void PrintMemory( DWORD processID ){
	HANDLE hProcess;

	// Print information about the memory usage of the process.

	hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, processID );

	if (NULL == hProcess)
	        return;

	HMODULE hMods[1024];
	DWORD cbNeeded;
	MODULEINFO lpmodinfo1;

	if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for ( int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				//_tprintf( TEXT("\t%s (0x%08X)\n"), szModName, hMods[i] );
			}

			if (strcmp(szModName, "H:\\Carlos\\Juegos\\BH3 SOURCENEXT (Pre-installed) - PC\\BIOHAZARD 3 PC\\BIOHAZARD(R) 3 PC.exe") == 0){
				GetModuleInformation(hProcess, hMods[i], &lpmodinfo1, sizeof(lpmodinfo1));
			};
		}
	}

	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = 0;
	unsigned char to_find[Inventory_Size_Array] = {00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
										00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
										00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
										00, 00, 00, 00, 00, 00, 00, 00, 0x80, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 00, 00, 00, 00,
										00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
	item_struct items[Number_items];

	std::thread th1(write_healt, lpmodinfo1, (void *) hProcess);
	std::thread th2(write_ammo, lpmodinfo1, (void *) hProcess);
	HWND myConsole = GetConsoleWindow();
	ShowWindow(myConsole, 0);
	DWORD lpExitCode;

	while(TRUE){
		GetExitCodeProcess(hProcess, &lpExitCode);
		if (lpExitCode != STILL_ACTIVE){
			return;
		}
		Sleep(1000);
	}

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS){
			char* buffer = new char[mbi.RegionSize];

			int res = ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, nullptr);
			if (res != 0){
				for (UINT64 i = 0; i < mbi.RegionSize; i++){
					if (buffer[i] == to_find[0]){
						for (int z = 1; z < Inventory_Size_Array; z++){
							if (buffer[i+z] != to_find[z]){
								break;
							}
							if (z == (Inventory_Size_Array - 1)){
								UINT64 init_mem_items = i+z+1;
								UINT64 addr_items = 1;
								addr += init_mem_items + 1;
								for (int a = 0; a < Number_items; a++){
									memcpy (&items[a], &buffer[init_mem_items+addr_items], sizeof(item_struct));
									addr_items += sizeof(item_struct);
								}
								unsigned char* addr_init = addr;
								while(TRUE){
									Sleep(700);
									ReadProcessMemory(hProcess, (void*)addr_init, &items[0], sizeof(item_struct) * Number_items, nullptr);
									for (int a = 0; a < Number_items; a++){
										if (items[a].item == Assault_Rifle_Auto){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 90;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == handgun){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 15;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == Magnum){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 15;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == Shotgun){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 6;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == first_aid_spray_box){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 5;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == Red_Herb){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 5;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == Blue_Herb){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 5;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
									}
								}
							}
						}
					}
				}
			}
		}
		addr += mbi.RegionSize;
	}
	CloseHandle( hProcess );
}

int main( void )
{
    // Get the list of process identifiers.

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
        		PrintMemoryInfo( aProcesses[i] );
        		PrintMemory( aProcesses[i] );
        	}
        }
    }

    return 0;
}
