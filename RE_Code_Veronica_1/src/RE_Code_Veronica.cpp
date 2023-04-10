//============================================================================
// Name        : RE4_cheat.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "RE_Code_Veronica.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

inline void SwapEndian(UINT16 &val)
{
    val = (val<<8) | (val>>8);
}

DWORD PrintProcessNameAndID( DWORD processID )
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR resident_name[MAX_PATH] = TEXT("pcsx2-qt.exe");

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

void write_healt (void* ptr){
	HANDLE* hProcess = (HANDLE*) ptr;
	INT16 health = 160;
	UINT8 Mem_Read_Health[2];
	UINT8 Mem_Read_Health_NULL[2];
	memset(Mem_Read_Health_NULL, 0x00, sizeof(Mem_Read_Health_NULL));
	DWORD lpExitCode;
	while (TRUE){
		GetExitCodeProcess(hProcess, &lpExitCode);
		if (lpExitCode != STILL_ACTIVE){
			return;
		}
		ReadProcessMemory(hProcess, (void*)Memory_hp, Mem_Read_Health, sizeof(Mem_Read_Health), nullptr);
		if (true == memcmp(Mem_Read_Health, Mem_Read_Health_NULL, sizeof(Mem_Read_Health))){
			WriteProcessMemory(hProcess, (void*)Memory_hp, &health, 1, nullptr);
			Sleep(20000);
		}
		else{
			Sleep(20000);
		}
	}
}

void write_ammo (void* ptr){
	HANDLE* hProcess = (HANDLE*) ptr;
	item_struct items[Number_items];
	item_struct items_null[Number_items];
	memset(items_null, 0x00, sizeof(items_null));
	unsigned long long addr_init = Init_Inventory;
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
				if (items[a].item == Rifle){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 6;
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
				else if (items[a].item == Calico_M_100P){
					addr = addr_init + (sizeof(item_struct) * a);
					items[a].cantidad = 90;
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
		}
	}

	std::thread th1(write_healt, (void *) hProcess);
	std::thread th2(write_ammo, (void *) hProcess);
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
        		PrintMemory( aProcesses[i] );
        	}
        }
    }

    return 0;
}
