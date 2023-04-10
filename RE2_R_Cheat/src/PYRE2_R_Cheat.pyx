from libcpp.vector cimport vector


cdef extern from "RE2_R_Cheat.h":
    unsigned long long PCmain()
    unsigned long long PCmain_ammo_Matilda()
    unsigned long long PCmain_Ammo_Shotgun(unsigned long long Start_Addr)
    unsigned long long PCmain_Ammo_M19(unsigned long long Start_Addr)
    unsigned long long PCmain_Ammo_Lightning_Hawk(unsigned long long Start_Addr)
    unsigned long long PCmain_Hand_Grenade(unsigned long long Start_Addr)
    unsigned long long PCmain_Flash_Grenade(unsigned long long Start_Addr)

cpdef Pmain():
    cdef unsigned long long a
    a = PCmain()
    return a

cpdef Pmain_ammo_Matilda():
    cdef unsigned long long b
    b = PCmain_ammo_Matilda()
    return b

cpdef Pmain_ammo_Shotgun(unsigned long long i):
    cdef unsigned long long c
    c = PCmain_Ammo_Shotgun(i)
    return c

cpdef Pmain_ammo_M19(unsigned long long i1):
    cdef unsigned long long d
    d = PCmain_Ammo_M19(i1)
    return d

cpdef Pmain_Ammo_Lightning_Hawk(unsigned long long i2):
    cdef unsigned long long e
    e = PCmain_Ammo_Lightning_Hawk(i2)
    return e

cpdef Pmain_Hand_Grenade(unsigned long long i3):
    cdef unsigned long long f
    f = PCmain_Hand_Grenade(i3)
    return f

cpdef Pmain_Flash_Grenade(unsigned long long i4):
    cdef unsigned long long g
    g = PCmain_Flash_Grenade(i4)
    return g