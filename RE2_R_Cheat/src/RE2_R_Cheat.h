/*
 * RE4_cheat.h
 *
 *  Created on: Mar 21, 2023
 *      Author: car_1
 */

#ifndef RE_2R_CHEAT_H_
#define RE_2R_CHEAT_H_

#pragma comment(lib, "psapi.lib")
#include <windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <iterator>

#define Instructions_Number 6
#define Size_Buff_Items 4034

class Addr_Info{
	public:
		unsigned long long Addr;
		unsigned long long Addr_Find;
		unsigned long long Index;
};

unsigned long PrintProcessNameAndID(unsigned long processID);
Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, int size);
Addr_Info Search_Memory(unsigned long processID, std::vector<unsigned char> to_find, unsigned long long offset);
unsigned long long PCmain();
unsigned long long PCmain_ammo_Matilda();
unsigned long long Search_Memory_Wildcard(DWORD process_id, std::vector<unsigned char> to_find1, std::vector<unsigned char> to_find2, unsigned long long Start_Addr);
unsigned long long PCmain_Ammo_Shotgun(unsigned long long Start_Addr);
unsigned long long PCmain_Ammo_M19(unsigned long long Start_Addr);
unsigned long long PCmain_Ammo_Lightning_Hawk(unsigned long long Start_Addr);
unsigned long long PCmain_Hand_Grenade(unsigned long long Start_Addr);
unsigned long long PCmain_Flash_Grenade(unsigned long long Start_Addr);

#endif /* RE2R_CHEAT_H_ */
