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

int main( void );

typedef struct item_struct{
	UINT8 item;
	UINT8 cantidad;
	UINT8 existe;
	UINT8 mejora_arma;
};

#define Memory_hp 0x6620E0
#define Init_Inventory 0x667595
#define Inventory_Bytes 40
#define Number_items 10
#define Inventory_Size_Array 185

#define first_aid_spray_box 0x2A
#define green_herb 0x21
#define Blue_Herb 0x22
#define Red_Herb 0x23
#define handgun 0x03
#define Magnum 0x05
#define Shotgun 0x04
#define Assault_Rifle_Auto 0x0F
#define Eagle_6 0x0D
#define R_Laucher 0x0A
#define G_Laucher_Grenade 0x06
#define G_Laucher_Flame 0x07
#define G_Laucher_Acid 0x08
#define G_Laucher_Freeze 0x09
#define Gatling_Gun 0x0B
#define Mine_Thrower 0x0C
#define M92F_E 0x12
#define Benelli_M3S_E 0x13
#define M_Thrower_E 0x14



#endif /* RE3_CHEAT_H_ */
