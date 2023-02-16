#!/usr/local/bin/python3.9
from common.layout import *
import sys
import readline
# ------------------------ Interaction Model ------------------------


class Interaction:
    RE_MATH_EVAL = '(0x)?[0-9a-z]{4,16}(\+|\-)\d'
    LOGO = RED("\nYJ ➤ ")

    def __init__(self, device, script, spawn_model, pid):
        self.device = device
        self.script = script
        self.spawn_model = spawn_model
        self.pid = pid

    def start(self):
        while True:
            cmd = input(Interaction.LOGO)
            if (cmd == "" or cmd.isspace()):
                continue
            elif (cmd == "help" or cmd == "h"):
                print(self.MENU)
                continue
            argv = cmd.split()
            cmd = argv[0]
# -------------------- Shell command --------------------
            if (cmd == "quit" or cmd == "q"):
                sys.exit(0)
            elif (cmd == "clear" or cmd == "cl"):
                os.system("clear")
            elif (cmd == "ls"):
                os.system("ls --color")
            elif (cmd == "pwd"):
                os.system("pwd")
# -------------------- Frida command --------------------
            elif (cmd == "run" or cmd == "r"):
                self.resume_process()
            elif (cmd == "main" or cmd == "m"):
                self.show_all_view()
            elif (cmd == "lib" or cmd == "so"):
                self.libc_base_address()
            elif (cmd == "trace" or cmd == "t"):
                self.trace(argv)
            elif (cmd == "print" or cmd == "p"):
                self.print_address(argv, 10)
            elif (cmd == "hex" or cmd == "x"):
                self.print_address(argv, 16)
            elif (cmd == "telescope" or cmd == "tele"):
                self.telescope(argv)
            elif (cmd == "string" or cmd == "s"):
                self.read_String(argv)
            elif (cmd == "breakpoints" or cmd == "b"):
                self.set_breakpoint(argv)
            elif (cmd == "delete" or cmd == "d"):
                self.delete_breakpoint(argv)
            elif (cmd == "info" or cmd == "i"):
                self.display_info_list_type(argv)
            elif (cmd == "watch" or cmd == "w"):
                self.watch_memory(argv)
            elif (cmd == "unwatch" or cmd == "uw"):
                self.un_watch_memory()
            elif (cmd == "hexdump" or cmd == "hd"):
                self.hexdump(argv)
            elif (cmd == "writefile" or cmd == "wf"):
                self.write_file(argv)
            elif (cmd == "hookfunction" or cmd == "hf"):
                self.hook_function(argv)
            else:
                print("Option does not exist : \"%s\".  Try \"help\"" % cmd)


# -------------------- Call JavaScript function --------------------


    def resume_process(self):
        if self.spawn_model == True:
            self.device.resume(self.pid)  # 对应挂起函数调用
            # process.detach()
            self.spawn_model = False

    def telescope(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        if (not re.match(Interaction.RE_MATH_EVAL, address) is None):
            address = str(hex(eval(address)))
        self.script.exports.telescope(address)

    def print_address(self, argv, carry=10):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        if (not re.match(Interaction.RE_MATH_EVAL, address) is None):
            address = str(hex(eval(address)))
        value = self.script.exports.read_pointer(address)
        if value == 0:
            return
        if carry == 16:
            print(address + " -> " + value)
        else:
            print(str(int(value, 16)))

    def set_breakpoint(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        if (not re.match(Interaction.RE_MATH_EVAL, address) is None):
            address = str(hex(eval(address)))
        if len(argv) > 2:
            targetLibName = argv[2]
            self.script.exports.set_breakpoint(address, targetLibName)
        else:
            self.script.exports.set_breakpoint(address)

    def watch_memory(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        targetLibName = argv[1]
        length = None
        lib = None
        if len(argv) == 3:
            length = argv[2]
        self.script.exports.watch_memory(targetLibName, length)

    def un_watch_memory(self):
        self.script.exports.un_watch_memory()

    def write_file(self, argv):
        if len(argv) < 3:
            print(
                "Need [content] and [filename](output file default in /sdcard/xxx)")
            return
        content = argv[1]
        fileName = argv[2]
        self.script.exports.write_file(content, fileName)

    def hook_function(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        pack = argv[1]
        self.script.exports.java_hook_class_all_functions(pack)

    def display_info_list_type(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        show_type = argv[1]
        if show_type == "b" or show_type == "breakpoints":
            breakpoints = self.script.exports.get_breakpoints()
            breakpoints = breakpoints.split()
            print("{0:^5s} {1:^16s} {2:^16s} {3:^16s}".format(
                "Num", "Type", "Address", "What"))
            print("{0:^5s} {1:^16s} {2:^25s} {3:^25s}".format(
                "1", "breakpoint", BLUE(breakpoints[0]), GREEN(breakpoints[1])))
        elif show_type == "so" or show_type == "lib":
            # Parameter 1 : whether just display user lib library
            # Parameter 2 : whether print detail info
            string = self.script.exports.show_allso(True, False)
            list_name = sorted(string.split(','))
            for i in range(len(list_name)):
                print(f"{GREEN(list_name[i]):<30s}")
        elif show_type == "f" or show_type == "fun" \
                or show_type == "func" or show_type == "function":
            if len(argv) < 3:
                print("Need [targetLibName]")
                return
            libName = argv[2]
            self.script.exports.get_export_func(libName)
            self.script.exports.get_import_func(libName)
        elif show_type == "jni":
            self.script.exports.get_j_n_i_func()
        else:
            print("Don't found \"info " + show_type + "\"")

    def delete_breakpoint(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        self.script.exports.delete_breakpoint(address)
        print(GREEN("Cleaed all breakPointer"))

    def read_String(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        coding = "utf8"
        if (not re.match(Interaction.RE_MATH_EVAL, address) is None):
            address = str(hex(eval(address)))
        if len(argv) > 2:
            coding = argv[2]
        string = self.script.exports.read_string(address, coding)
        if string.find("Error") != -1:
            print(RED(string))
        else:
            print(YELLOW("\"" + string + "\""))

    def show_all_view(self):
        self.script.exports.show_all_view()

    def libc_base_address(self):
        address = self.script.exports.libc_base_address()
        print(BLUE("libc :") + WHITE(" %s") % address)

    def trace(self, argv):
        if (len(argv) == 2) and \
                (argv[1] == "f" or argv[1] == "fuzzy"):
            self.script.exports.trace("FUZZY")
        else:
            self.script.exports.trace()

    def hexdump(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        size = 0x30
        if (not re.match(Interaction.RE_MATH_EVAL, address) is None):
            address = str(hex(eval(address)))
        if (len(argv) > 2):
            size = argv[2]
            try:
                size = int(size, 10)
            except:
                size = int(size, 16)

        value = self.script.exports.hexdump(address, size)

    MENU = '''
    Usage : [options] [value] [--]

        Options:

------- SHELL ------
        h|help                                  Display this message
        v|version                               Display script version
        q|quit                                  Exit frida
        cl|clear                                Clean screen
        ls                                      Display current list

------- YJ ---------
        r|run                                   Continue spawn model attach
        m|main                                  Display all view
        p [pointer]                             Display pointer value
        x [pointer]                             Display pointer hexadecimal value
        b|breakpoint [address] [targetLibName]  Add target lib and break point
        t|trace [accurate/fuzzy]                Display called function list(default fuzzy)
        so|lib                                  Print current target dynamic library base address
        i|info [b|breakpoints]                  Print current all break pointer
        i|info [so|lib]                         Print all loaded dynamic library
        i|info [f|fun] [lib name]               Print target lib all functions
        i|info [jni]                            Print all jni functions
        d|delete [breakpoint]                   Delete break pointer
        w|watch [pointer]                       Monitor target memory space. callback snooping exists
        uw|unwatch                              Disable monitor target memory space(default disable all monitor)
        hd|hexdump [pointer]                    Display target memory space
        tele|telescope [pointer]                Display multiple line memory space
        wf|writefile [content] [filename]       Display multiple line memory space
        s|string [pointer]                      Print target address character(default utf-8)
        hf|hookfunction                         Hook all functions of a single class in the java level
    '''
