#!/usr/local/bin/python3.9
from common.layout import *
import sys
import readline
# ------------------------ Interaction Model ------------------------


class Interaction:
    #EVAL_MTH = '(0x)?[0-9A-Fa-f]{1,16}(\+|\-)\d'
    EVAL_MTH = '(0x)?[0-9A-Fa-f]{1,16}(\+|\-)\d'
    #TODO  error -> 0xff+0xzxdqwwq ???

    LOGO = RED("\nYJ ➤ ")

    def __init__(self, device, script, spawn_model, pid):
        self.device = device
        self.script = script
        self.spawn_model = spawn_model
        self.pid = pid
        self.cache_all_so_json_fmt = None

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
#            elif (cmd == "mfind" or cmd == "mf"):
#                self.script.exports.mfind(argv[1])
            elif (cmd == "run" or cmd == "r"):
                self.resume_process()
            elif (cmd == "main" or cmd == "m"):
                self.show_all_view()
            elif (cmd == "kill" or cmd == "k"):
                self.stop_auto_show_view()
            elif (cmd == "lib" or cmd == "so"):
                self.libc_base_address()
            elif (cmd == "trace" or cmd == "t"):
                self.trace(argv)
            elif (cmd == "expr"):
                self.into_expr(argv)
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
            elif (re.match("!.*", cmd)):
                try:
                    exec(cmd.replace("!", ""))
                except Exception as e:
                    print(e)
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
        if re.match(Interaction.EVAL_MTH, address):
            address = str(hex(eval(address)))
        self.script.exports.telescope(address)

    def into_expr(self, argv):
        if len(argv) < 4:
            print(argv[0] + " format error, try exec \"help\"")
            return
        try:
            # print(argv[1] + argv[2] + argv[3])
            address = eval(argv[1] + argv[2] + argv[3])
            print(address)
        except Exception as e:
            print(e)

    def print_address(self, argv, carry=10):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        if re.match(Interaction.EVAL_MTH, address):
            address = str(hex(eval(address)))
        value = self.script.exports.read_pointer(address)
        if value == 0:
            return
        if carry == 16:
            print(address + " -> " + value)
        else:
            print(str(int(value, 16)))

#    def check_is_live_so_info_cache(self, address):
#        if not self.cache_all_so_json_fmt:
#            return None
#
#        # 这里有性能问题，以后改,现在要吃饭了2023-02-16 18:06
#        min = 0xffffffffffffffff  # max value
#        targetLibName = None
#        for j in self.cache_all_so_json_fmt:
#            it = json.loads(j)
#            n = abs(self.toAddress(address) - self.toAddress("0x"+it["base"]))
#            if n <= min:
#                min = n
#                targetLibName = it["name"]
#        return targetLibName

    def set_breakpoint(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return

        address = argv[1]
        targetLibName = None
        if len(argv) == 2:
            # Check it belong to match , Fetch address
            if re.match(Interaction.EVAL_MTH, address):
                address = str(hex(eval(address)))
            targetLibName = self.script.exports.is_live_cache_map_s_o(address)
        if len(argv) > 2:
            targetLibName = argv[2]
            #if targetLibName == "*":
                # Check it belong to match , Fetch address
            #    targetLibName = self.check_is_live_so_info_cache(address)
        self.script.exports.set_breakpoint(address, targetLibName)

    # Just only one argument -> as much as possible more memory
    # Live two arguments -> [libName] [start-end] #start > 0 , end<size
    # Live three arguments -> [libName] [start] [end] #start > 0 , end<size

    def watch_memory(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        elif len(argv) == 2:
            targetLibName = argv[1]
            self.script.exports.watch_memory(targetLibName, None)
        elif len(argv) == 3:
            targetLibName = argv[1]
            HEX_OR_DEC_MATH = '(0x)?[0-9A-Fa-f]{1,16}-(0x)?[0-9A-Fa-f]{1,16}'
            if (not re.match(HEX_OR_DEC_MATH, argv[2])):
                print("Format error as -> [start]-[end]")
                return
            sp = argv[2].split('-')
            offset = self.toAddress(sp[0])
            length = self.toAddress(sp[1]) - offset
            if (offset < 0 or length <= 0):
                print("Format error")
                return
            self.script.exports.watch_memory(
                targetLibName, str(length), str(offset))
        elif len(argv) == 4:
            targetLibName = argv[1]
            offset = self.toAddress(argv[2])
            length = self.toAddress(argv[3]) - offset
            if (offset < 0 or length <= 0):
                print("Format error")
                return
            self.script.exports.watch_memory(
                targetLibName, str(length), str(offset))

    def toAddress(self, string):
        HEX_MATH = '0x[0-9A-Fa-f]{1,16}$'
        DEC_MATH = '\d{1,16}$'
        if (re.match(HEX_MATH, string)):
            int_type = 16
        elif (re.match(DEC_MATH, string)):
            int_type = 10
        else:
            print("Format error as -> 0-0xfxxxx")
            return -1
        return int(string, int_type)

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

    def show_breakpoints(self):
        breakpoints = self.script.exports.get_breakpoints()
        breakpoints = breakpoints.split()
        print("{0:^5s} {1:^16s} {2:^16s} {3:^16s}".format(
            "Num", "Type", "Address", "What"))
        print("{0:^5s} {1:^16s} {2:^25s} {3:^25s}".format(
            "1", "breakpoint", BLUE(breakpoints[0]), GREEN(breakpoints[1])))

    def show_so_bck(self):
        # Parameter 1 : whether just display user lib library
        # Parameter 2 : whether print detail info
        isDetail = True
        string = self.script.exports.show_allso(True, isDetail)
        list_name = sorted(string.split(','))
        for i in range(len(list_name)):
            print(f"{GREEN(list_name[i]):<30s}")

    def show_so(self):
        # Parameter 1 : whether just display user lib library
        # Parameter 2 : whether print detail info
        isDetail = False
        json_str = self.script.exports.show_allso(True, isDetail)
        if isDetail:
            _json = sorted(json_str.split())
            for it in _json:
                print(it)
            return

        _json = sorted(json_str.split())
        self.cache_all_so_json_fmt = _json
        for j in _json:
            it = json.loads(j)
            print(
                GREEN(it["name"] + " -> {size: 0x"+it["size"] + " ,base: 0x"+it["base"] + "}"))

    def show_watchs(self):
        watch_info = self.script.exports.get_watchs()
        if not watch_info is None:
            print(GREEN("watch info -> " + watch_info))

    def show_function(self, argv):
        libName = argv[2]
        self.script.exports.get_export_func(libName)
        self.script.exports.get_import_func(libName)

    def display_info_list_type(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        show_type = argv[1]
        if show_type == "b" or show_type == "breakpoints":
            self.show_breakpoints()
        elif show_type == "so" or show_type == "lib":
            self.show_so()
        elif show_type == "w" or show_type == "watch":
            self.show_watchs()
        elif show_type == "f" or show_type == "function":
            if len(argv) < 3:
                print("Need [targetLibName]")
                return
            self.show_function(argv)
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
        if re.match(Interaction.EVAL_MTH, address):
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

    def stop_auto_show_view(self):
        self.script.exports.stop_auto_show_view()
        print(GREEN("Kill Success"))

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
        if re.match(Interaction.EVAL_MTH, address):
            address = str(hex(eval(address)))
        if len(argv) > 2:
            size = argv[2]
            size = self.toAddress(size)
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
        ![python]                               Exec python code

------- YJ ---------
        r|run                                   Continue spawn model attach
        m|main                                  Display all view
        k|kill                                  Disable auto display all view
        p [pointer]                             Display pointer value
        x [pointer]                             Display pointer hexadecimal value
        expr [calculation expression]           Calculation expression result
        b|breakpoint [address] [targetLibName]  Add target lib and break point
        b|breakpoint [address]                  Add target lib and break point(Attach last time add target lib)
        b|breakpoint [address] *                Add target lib and break point(Automatic detection)
        t|trace [accurate/fuzzy]                Display called function list(default fuzzy)
        so|lib                                  Print current target dynamic library base address
        i|info [b|breakpoints]                  Print current all break pointer
        i|info [w|watch]                        Print all watch target
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
