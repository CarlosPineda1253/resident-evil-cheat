//============================================================================
// Name        : RE4_cheat.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <winbase.h>
#include <basetsd.h>
#include <thread>
#include "RE4_cheat.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

inline void SwapEndian(UINT16 &val)
{
    val = (val<<8) | (val>>8);
}

DWORD PrintProcessNameAndID( DWORD processID )
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR resident_name[MAX_PATH] = TEXT("bio4.exe");

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
    	_tprintf( TEXT("%s  (PID: %u)\n"), szProcessName, processID );
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

    printf( "\nProcess ID: %u\n", processID );

    // Print information about the memory usage of the process.

    hProcess = OpenProcess(  PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, processID );
    if (NULL == hProcess)
        return;

    if ( GetProcessMemoryInfo( hProcess, &pmc, sizeof(pmc)) )
    {
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
    }

    CloseHandle( hProcess );
}

void write_healt (HMODULE ptr, void* ptr2){
	while (TRUE){
		HANDLE* hProcess = (HANDLE*) ptr2;
		UINT16 health = 2380;
		UINT16 max_health = 2430;
		WriteProcessMemory(hProcess, (void*)ptr + Memory_hp, &health, 2, nullptr);
		WriteProcessMemory(hProcess, (void*)ptr + Memory_hp_max, &max_health, 2, nullptr);
		Sleep(30000);
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
	HMODULE Base_Game;

	if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for ( int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				_tprintf( TEXT("\t%s (0x%08X)\n"), szModName, hMods[i] );
			}

			if (strcmp(szModName, "H:\\SteamLibrary\\steamapps\\common\\Resident Evil 4\\Bin32\\bio4.exe") == 0){
				Base_Game = hMods[i];
			};
		}
	}


	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = 0;
	char to_find[Bytes_Case] = {0x7F, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	item_struct items[Number_items];

	while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT || mbi.Protect != PAGE_NOACCESS){
			char* buffer = new char[mbi.RegionSize];

			int res = ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, nullptr);
			if (res != 0){
				for (UINT64 i = 0; i < mbi.RegionSize; i++){
					if (buffer[i] == to_find[0]){
						for (int z = 1; z < Bytes_Case; z++){
							if (buffer[i+z] != to_find[z]){
								break;
							}
							if (z == (Bytes_Case - 1)){
								UINT64 init_mem_items = i+z+1;
								UINT64 addr_items = 1;
								addr += init_mem_items + 1;
								for (int a = 0; a < Number_items; a++){
									memcpy (&items[a], &buffer[init_mem_items+addr_items], sizeof(item_struct));
									addr_items += sizeof(item_struct);
								}
								unsigned char* addr_init = addr;
								std::thread th1(write_healt, Base_Game, (void *) hProcess);
								while(TRUE){
									Sleep(9000);
									ReadProcessMemory(hProcess, (void*)addr_init, &items[0], sizeof(item_struct) * Number_items, nullptr);
									for (int a = 0; a < Number_items; a++){
										if (items[a].item == killer7){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].carga = 50000;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == handgun){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].carga = 50000;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == flash_grenade){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 250;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == hand_grenade){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 250;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == first_aid_spray){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 20;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == incendiary_grenade){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].cantidad = 250;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == rifle_semi_auto){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].carga = 50000;
											WriteProcessMemory(hProcess, (void*)addr, &items[a], sizeof(item_struct), nullptr);
										}
										else if (items[a].item == riot_gun){
											addr = addr_init + (sizeof(item_struct) * a);
											items[a].carga = 50000;
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
