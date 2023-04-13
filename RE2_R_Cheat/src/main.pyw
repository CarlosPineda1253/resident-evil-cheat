# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import multiprocessing

from winappdbg import System, Process, Debug, win32, HexDump
import threading
import time
import psutil
import PYRE2_R_Cheat


class Sup_Game:
    Flag_Event_Health = True
    Flag_Event_Ammo_Matilda = True
    Flag_Event_Ammo_Shotgun = True
    Flag_Event_Ammo_M19 = True
    Flag_Event_Ammo_Lightning_Hawk = True
    Flag_Event_Hand_Grenade = True
    Flag_Event_Flash_Grenade = True
    Addr_Health = 0
    Addr_Ammo_Matilda = 0
    Addr_Ammo_Shotgun = 0
    Addr_Ammo_M19 = 0
    Addr_Ammo_Lightning_Hawk = 0
    Addr_Hand_Grenade = 0
    Addr_Flash_Grenade = 0
    Addr_Items = 0
    Inst_Health = 0
    Inst_Ammo_Matilda = 0
    Inst_Ammo_Shotgun = 0
    Inst_Ammo_M19 = 0
    Inst_Ammo_Lightning_Hawk = 0
    Inst_Hand_Grenade= 0
    Inst_Flash_Grenade = 0

    def __init__(self):
        pass


def Loop_Game_Health(process):
    while True:
        time.sleep(15)
        if Sup_Game.Flag_Event_Health is False:
            process.write_char(Sup_Game.Addr_Health, 176)
            process.write_char(Sup_Game.Addr_Health+1, 4)


def Loop_Game_Ammo(process):
    while True:
        time.sleep(3)
        if Sup_Game.Flag_Event_Ammo_Matilda is False:
            Sup_Game.Addr_Items = (48 * process.read_char(Sup_Game.Addr_Ammo_Matilda - 18)) / 3
            Sup_Game.Addr_Items = (Sup_Game.Addr_Ammo_Matilda - Sup_Game.Addr_Items) + 46
            process.write_char(Sup_Game.Addr_Ammo_Matilda, 100)
            process.write_char(Sup_Game.Addr_Ammo_Matilda + 1, 0)

            if Sup_Game.Flag_Event_Ammo_Shotgun is True:
                Sup_Game.Addr_Ammo_Shotgun = PYRE2_R_Cheat.Pmain_ammo_Shotgun()
                if Sup_Game.Addr_Ammo_Shotgun:
                    Sup_Game.Addr_Ammo_Shotgun += 32
                    Sup_Game.Flag_Event_Ammo_Shotgun = False
                    print ("Done Shotgun")

            if Sup_Game.Flag_Event_Ammo_M19 is True:
                Sup_Game.Addr_Ammo_M19 = PYRE2_R_Cheat.Pmain_ammo_M19()
                if Sup_Game.Addr_Ammo_M19:
                    Sup_Game.Addr_Ammo_M19 += 32
                    Sup_Game.Flag_Event_Ammo_M19 = False
                    print ("Done M19")

            if Sup_Game.Flag_Event_Ammo_Lightning_Hawk is True:
                Sup_Game.Addr_Ammo_Lightning_Hawk = PYRE2_R_Cheat.Pmain_Ammo_Lightning_Hawk()
                if Sup_Game.Addr_Ammo_Lightning_Hawk:
                    Sup_Game.Addr_Ammo_Lightning_Hawk += 32
                    Sup_Game.Flag_Event_Ammo_Lightning_Hawk = False
                    print ("Done Hawk")

            if Sup_Game.Flag_Event_Hand_Grenade is True:
                Sup_Game.Addr_Hand_Grenade = PYRE2_R_Cheat.Pmain_Hand_Grenade()
                if Sup_Game.Addr_Hand_Grenade:
                    Sup_Game.Addr_Hand_Grenade += 32
                    Sup_Game.Flag_Event_Hand_Grenade = False
                    print ("Done Granade")

            if Sup_Game.Flag_Event_Flash_Grenade is True:
                Sup_Game.Addr_Flash_Grenade = PYRE2_R_Cheat.Pmain_Flash_Grenade()
                if Sup_Game.Addr_Flash_Grenade:
                    Sup_Game.Addr_Flash_Grenade += 32
                    Sup_Game.Flag_Event_Flash_Grenade = False
                    print ("Done")

        if Sup_Game.Flag_Event_Ammo_Shotgun is False and Sup_Game.Addr_Ammo_Shotgun != 0:
            process.write_char(Sup_Game.Addr_Ammo_Shotgun, 8)

        if Sup_Game.Flag_Event_Ammo_M19 is False and Sup_Game.Addr_Ammo_M19 != 0:
            process.write_char(Sup_Game.Addr_Ammo_M19, 7)

        if Sup_Game.Flag_Event_Ammo_Lightning_Hawk is False and Sup_Game.Addr_Ammo_Lightning_Hawk != 0:
            process.write_char(Sup_Game.Addr_Ammo_Lightning_Hawk, 7)

        if Sup_Game.Flag_Event_Hand_Grenade is False and Sup_Game.Addr_Hand_Grenade != 0:
            process.write_char(Sup_Game.Addr_Hand_Grenade, 4)

        if Sup_Game.Flag_Event_Flash_Grenade is False and Sup_Game.Addr_Flash_Grenade != 0:
            process.write_char(Sup_Game.Addr_Flash_Grenade, 4)


def Loop_Process(process, debug):
    try:
        debug.attach(process.get_pid())
        debug.loop()
    finally:
        debug.stop()


def action_callback_health(event):
    System.request_debug_privileges()
    thread = event.get_thread()
    context = thread.get_context()
    Sup_Game.Addr_Health = context["Rcx"] + 0x58
    Sup_Game.Flag_Event_Health = False


def action_callback_ammo(event):
    System.request_debug_privileges()
    thread = event.get_thread()
    context = thread.get_context()
    Sup_Game.Addr_Ammo_Matilda = context["Rcx"] + 0x20
    Sup_Game.Flag_Event_Ammo_Matilda = False
    print ("Done Event Ammo")
    print Sup_Game.Addr_Ammo_Matilda


def action_callback_test(event):
    System.request_debug_privileges()
    thread = event.get_thread()
    context = thread.get_context()
    print context


def my_event_handler(event):
    # Get the process ID where the event occured.
    pid = event.get_pid()
    # Get the thread ID where the event occured.
    # tid = event.get_tid()

    # Find out if it's a 32 or 64 bit process.
    # bits = event.get_process().get_bits()

    # Get the value of EIP at the thread.
    # address = event.get_thread().get_pc()

    # Get the event name.
    # name = event.get_event_name()

    # Get the event code.
    # code = event.get_event_code()

    if Sup_Game.Flag_Event_Health and Sup_Game.Inst_Health != 0:
        event.debug.stalk_at(pid, Sup_Game.Inst_Health+6, action_callback_health)

    if Sup_Game.Flag_Event_Ammo_Matilda and Sup_Game.Inst_Ammo_Matilda != 0:
        event.debug.stalk_at(pid, Sup_Game.Inst_Ammo_Matilda, action_callback_ammo)

    # event.debug.watch_variable(tid, 0x1F8FF2FE080, 1, action_callback_test)
    # print "-" * 79
    # format_string = "%s (0x%s) at address 0x%s, process %d, thread %d"
    # message = format_string % (name, HexDump.integer(code, bits), HexDump.address(address, bits), pid, tid)
    # print message


def print_hi():
    # Create a system snaphot.
    system = System()

    # Now we can enumerate the running processes.
    for process in system:
        if "H:\\SteamLibrary\\steamapps\\common\\RESIDENT EVIL 2  BIOHAZARD RE2\\re2.exe" == process.get_filename():
            # Instance a Process object.
            process = Process(process.get_pid())
            print ("Process %d" % process.get_pid())
            time.sleep(30)
            debug = Debug(my_event_handler, bKillOnExit=False)
            # debug.attach(process.get_pid())
            # debug.loop()
            # Search for the array in the process memory.
            Sup_Game.Inst_Ammo_Matilda = PYRE2_R_Cheat.Pmain_ammo_Matilda()
            print ("Done Ammo")
            Sup_Game.Inst_Health = PYRE2_R_Cheat.Pmain()
            print ("Done Health")
            x = threading.Thread(target=Loop_Process, args=(process, debug,))
            x.start()
            x = threading.Thread(target=Loop_Game_Health, args=(process,))
            x.start()
            x = threading.Thread(target=Loop_Game_Ammo, args=(process,))
            x.start()
            pid = process.get_pid()
            pre_util = psutil.Process(pid)
            while True:
                try:
                    time.sleep(1)
                    if pre_util.status() == psutil.STATUS_STOPPED:
                        return
                except:
                    return


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    time.sleep(10)
    print_hi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
