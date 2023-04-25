/*
 * RE4_cheat.h
 *
 *  Created on: Mar 21, 2023
 *      Author: car_1
 */

#ifndef RE_2R_CHEAT_H_
#define RE_2R_CHEAT_H_

#include <windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <unistd.h>
#include <thread>
#include <memoryapi.h>
#include <fstream>
#include <iomanip>

#define Instructions_Number 6
#define Size_Buff_Items 4034
#define RESUME_FLAG 0x10000
#define Item_Size 0xF0

class Addr_Info{
	public:
		unsigned long long Addr;
		unsigned long long Addr_Find;
		unsigned long long Index;
		unsigned long long Addr_Context;
};

unsigned long PrintProcessNameAndID(unsigned long processID);
Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find);
Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, unsigned long long offset);
Addr_Info PCmain();
Addr_Info PCmain_Ammo_Matilda();
Addr_Info Search_Memory_Wildcard(DWORD process_id, std::vector<unsigned char> to_find1, unsigned long long Start_Addr);
Addr_Info PCmain_Ammo_Shotgun(unsigned long long offset_addr, DWORD aProcesses);
Addr_Info PCmain_Ammo_M19(unsigned long long offset_addr, DWORD aProcesses);
Addr_Info PCmain_Ammo_Lightning_Hawk(unsigned long long offset_addr, DWORD aProcesses);
Addr_Info PCmain_Grenade(unsigned long long offset_addr, DWORD aProcesses);
Addr_Info PCmain_Flash_Grenade(unsigned long long offset_addr, DWORD aProcesses);
int loop_health(Addr_Info addr_health, DWORD resident_evil_id);
int loop_inv(DWORD resident_evil_id, Addr_Info addr_matilda, Addr_Info addr_shotgun, Addr_Info addr_m19, Addr_Info addr_hawk, Addr_Info addr_grenade_hand, Addr_Info addr_grenade_flash);
BOOL write_mem_custom(LPVOID address_write, BYTE values_buff[], int size, HANDLE hProcess);
int main();

#endif /* RE2R_CHEAT_H_ */
