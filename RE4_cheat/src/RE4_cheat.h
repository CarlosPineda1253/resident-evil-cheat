/*
 * RE4_cheat.h
 *
 *  Created on: Mar 21, 2023
 *      Author: car_1
 */

#ifndef RE4_CHEAT_H_
#define RE4_CHEAT_H_

typedef struct item_struct{
	UINT16 item;
	UINT16 cantidad;
	UINT16 existe;
	UINT16 mejora_arma;
	UINT16 carga;
	UINT16 posicion;
	UINT16 orientacion;
};

#define Bytes_Case 13
#define Number_items 200
#define Memory_money 0x85F708
#define Memory_hp 0x85F714
#define Memory_hp_max 0x85F716

#define killer7 42
#define hand_grenade 1
#define incendiary_grenade 2
#define first_aid_spray 5
#define green_herb 6
#define flash_grenade 14
#define chicago_typewriter 52
#define handgun 35
#define rifle_semi_auto 47
#define rifle_semi_auto_scope 108
#define rifle_semi_auto_infrared_scope 153
#define riot_gun 148

/*
<Description>"hp"</Description>
<VariableType>2 Bytes</VariableType>
<Address>bio4.exe+85F714</Address>

<Description>"max hp"</Description>
<VariableType>2 Bytes</VariableType>
<Address>bio4.exe+85F716</Address>

<Description>"money"</Description>
<VariableType>4 Bytes</VariableType>
<Address>bio4.exe+85F708</Address>
*/

#endif /* RE4_CHEAT_H_ */
