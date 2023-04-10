/*
 * RE3_Cheat.h
 *
 *  Created on: Apr 7, 2023
 *      Author: car_1
 */

#ifndef RE3_CHEAT_H_
#define RE3_CHEAT_H_

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <winbase.h>
#include <basetsd.h>
#include <thread>
#include <iostream>

int main( void );

typedef struct item_struct{
	UINT16 cantidad;
	UINT16 item;
};

#define Memory_hp 0x20448F2C
#define Init_Inventory 0x20449BA8
#define Inventory_Bytes 32
#define Number_items 8

#define first_aid_spray_box 0x14
#define green_herb 0x15
#define Blue_Herb 0x17
#define Red_Herb 0x16
#define handgun 0x09
#define Calico_M_100P 0x8E //0x64 = 100 %
#define Shotgun
#define Rifle 0x03
#define G_Laucher_Grenade 0x06
#define Grenade_Acid_Inf 0x06
#define G_Laucher_Fire
#define G_Laucher_Freeze

#endif /* RE3_CHEAT_H_ */
