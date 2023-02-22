#!/usr/local/bin/python3.9
from common.layout import *
import sys
import readline
from cmd import Cmd
# ------------------------ Interaction Model ------------------------
RE_EVAL_EXPRESS = '(0x)?[0-9A-Fa-f]{1,16}(-|\+)(0x)?[0-9A-Fa-f]{1,16}$'
RE_FUNCTION_EXPRESS = '(\*)?[a-zA-Z]+'

#YJ_HISTORY_FILE = ".YJ_history"
YJ_HISTORY_FILE = os.path.dirname(os.path.abspath(__file__)) + "/../.YJ_history"


class Interaction(Cmd):

    prompt = RED("\nYJ ➤ ")

    def __init__(self, device, script, spawn_model, pid):
        self.device = device
        self.script = script
        self.spawn_model = spawn_model
        self.pid = pid
        # self.cache_all_so_json_fmt = None
        Cmd.__init__(self)
        self.read_history()

    def default(self, cmd):
        print("Option does not exist : \"%s\".  Try \"help\"" % cmd)

    def emptyline(self):
        print("", end='')

    def do_EOF(self, cmd):
        self.safe_exit()

    def do_help(self, cmd):
        print(MENU)
    do_h = do_help

    def do_version(self, cmd):
        print("Current version -> " + GREEN("YJ-3"))
    do_v = do_version

# -------------------- Shell command --------------------
    def do_quit(self, cmd):
        self.safe_exit()
    do_q = do_quit

    def do_clear(self, cmd):
        os.system("clear")
    do_cl = do_clear

    def do_ls(self, cmd):
        os.system("ls --color")

    def do_pwd(self, cmd):
        os.system("pwd")
# -------------------- Frida command --------------------

#    def do_c(self, cmd):
#        self.script.exports.c(self.lastcmd.split()[1])
#    do_cc = do_c

    def do_run(self, cmd):
        self.resume_process()
    do_r = do_run

    def do_main(self, cmd):
        self.show_all_view()
    do_m = do_main

    def do_kill(self, cmd):
        self.stop_auto_show_view()
    do_k = do_kill

    def do_trace(self, cmd):
        self.trace(self.lastcmd.split())
    do_t = do_trace

    def do_print(self, cmd):
        self.print_address(self.lastcmd.split(), 10)
    do_p = do_print

    def do_hex(self, cmd):
        self.print_address(self.lastcmd.split(), 16)
    do_x = do_hex

    def do_string(self, cmd):
        self.read_String(self.lastcmd.split())
    do_s = do_string

    def do_hexdump(self, cmd):
        self.hexdump(self.lastcmd.split())
    do_hd = do_hexdump

    def do_telescope(self, cmd):
        self.telescope(self.lastcmd.split())
    do_tele = do_telescope

    def do_lib(self, cmd):
        self.libc_base_address()
    do_so = do_lib

    def do_find(self, cmd):
        self.find_api_by_func(self.lastcmd.split())
    do_f = do_find

    def do_breakpoints(self, cmd):
        self.set_breakpoint(self.lastcmd.split())
    do_b = do_breakpoints

    def do_info(self, cmd):
        self.display_info_list_type(self.lastcmd.split())
    do_i = do_info

    def do_delete(self, cmd):
        self.delete_breakpoint(self.lastcmd.split())
    do_d = do_delete

    def do_watch(self, cmd):
        self.watch_memory(self.lastcmd.split())
    do_w = do_watch

    def do_unwatch(self, cmd):
        self.un_watch_memory()
    do_uw = do_unwatch

    def do_writefile(self, cmd):
        self.write_file(self.lastcmd.split())
    do_wf = do_writefile

    def do_hookfunction(self, cmd):
        self.hook_function(self.lastcmd.split())
    do_hf = do_hookfunction

    def do_expr(self, cmd):
        self.into_expr(self.lastcmd.split())

#    def do_history(self, cmd):
#        with open(YJ_HISTORY_FILE, 'r') as f:
#            content = f.read()
#        print(content)

    # ----- record and playback -----
#    def do_record(self, arg):
#        self.file = open(YJ_HISTORY_FILE, 'w')
#
#    def do_playback(self, arg):
#        self.close()
#        with open(YJ_HISTORY_FILE) as f:
#            self.cmdqueue.extend(f.read().splitlines())

#    def do_shell(self,cmd):
#        print(cmd)

    def precmd(self, cmd):
        if (re.match("!.*", cmd)):
            self.exec_python(cmd)
            return ""
        elif (re.match("%.*", cmd)):
            self.exec_shell(cmd)
            return ""
        return cmd

    def safe_exit(self):
        self.write_history()
        print("See you ~")
        sys.exit(0)

    def read_history(self):
        try:
            readline.read_history_file(YJ_HISTORY_FILE)
        except:
            pass

    def write_history(self):
        try:
            readline.write_history_file(YJ_HISTORY_FILE)
        except Exception as e:
            print(e)

# -------------------- Call JavaScript function --------------------
    def exec_python(self, cmd):
        try:
            exec(cmd.replace("!", ""))
        except Exception as e:
            print(e)

    def exec_shell(self, cmd):
        try:
            os.system(cmd.replace("%", ""))
        except Exception as e:
            print(e)

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
        if re.match(RE_EVAL_EXPRESS, address):
            address = str(hex(eval(address)))
        self.script.exports.telescope(address)

    def into_expr(self, argv):
        if len(argv) < 4:
            print(argv[0] + " format error, try exec \"help\"")
            return
        try:
            address = eval(argv[1] + argv[2] + argv[3])
            print(address)
        except Exception as e:
            print(e)

    def print_address(self, argv, carry=10):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        if re.match(RE_EVAL_EXPRESS, address):
            address = str(hex(eval(address)))
        value = self.script.exports.read_pointer(address)
        if value == 0:
            return
        if carry == 16:
            print(address + " -> " + value)
        else:
            print(str(int(value, 16)))

    def find_api_by_func(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        reName = argv[1]
        funcType = "exports"
        self.script.exports.find_api_by_func(reName, funcType)

    def find_address_by_func(self, reName):
        funcType = "exports"
        self.script.exports.update_map_s_o()  # Update Cache Map so
        address = self.script.exports.find_api_by_func(reName, funcType, True)
        return address


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

        address = None
        targetLibName = None
        if len(argv) == 2:
            # Check it belong to eval expression -> Calculate address
            if re.match(RE_EVAL_EXPRESS, argv[1]):
                # address = str(hex(eval(argv[1])))
                address = str(eval(argv[1]))
            # Check it belong to function name -> Fetch address
            elif re.match(RE_FUNCTION_EXPRESS, argv[1]):
                address = self.find_address_by_func(argv[1])
            else:
                address = argv[1]

            if address is None or address == 0:
                print("Address fotmat error")
                return

            targetLibName = self.script.exports.is_live_cache_map_s_o(address)

        if len(argv) > 2:
            address = argv[1]
            targetLibName = argv[2]

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
            HEX_OR_RE_DEC_EXPRESS = '(0x)?[0-9A-Fa-f]{1,16}-(0x)?[0-9A-Fa-f]{1,16}'
            if (not re.match(HEX_OR_RE_DEC_EXPRESS, argv[2])):
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

    def toAddress(self, string, isprint=True):
        RE_HEX_EXPRESS = '0x[0-9A-Fa-f]{1,16}$'
        RE_DEC_EXPRESS = '\d{1,16}$'
        if (re.match(RE_HEX_EXPRESS, string)):
            int_type = 16
        elif (re.match(RE_DEC_EXPRESS, string)):
            int_type = 10
        else:
            if isprint:
                print("Format error as -> 0-0xfxxxx")
            return -1
        return int(string, int_type)

    def un_watch_memory(self):
        self.script.exports.un_watch_memory()

    def write_file(self, argv):
        if len(argv) < 3:
            print(argv[0] + " format error, try exec \"help\"")
            return
        startAddress = argv[1]
        byteSize = argv[2]
        fileName = None
        if len(argv) > 3:
            fileName = argv[3]
        if self.toAddress(startAddress) == -1 or \
                self.toAddress(byteSize) == -1:
            print("such as -> writefile [startAddress] [buffSize]")
            return
        self.script.exports.write_file(startAddress, byteSize, fileName)

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
        # self.cache_all_so_json_fmt = _json
        print("User lib.so ->")
        for j in _json:
            it = json.loads(j)
            print(
                GREEN(it["name"] + " -> {size: 0x"+it["size"] + " ,base: 0x"+it["base"] + "}"))

    def show_watchs(self):
        watch_info = self.script.exports.get_watchs()
        if not watch_info is None:
            print(GREEN("watch info -> " + str(watch_info)))

    def show_function(self, argv):
        if len(argv) < 3:
            print("Need [targetLibName]")
            return
        libName = argv[2]
        self.script.exports.get_import_func(libName)
        self.script.exports.get_export_func(libName)

    def show_debug_symbol(self, argv):
        if len(argv) < 3:
            print("Need [targetLibName|targetAddress]")
            return
        name = None
        address = None
        if self.toAddress(argv[2], False) == -1:
            name = argv[2]
        else:
            address = argv[2]
        self.script.exports.show_debuf_symbol(address, name)

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
            self.show_function(argv)
        elif show_type == "d" or show_type == "debugsymbol":
            self.show_debug_symbol(argv)
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
        print(GREEN("Cleared all breakPointer"))

    def read_String(self, argv):
        if len(argv) == 1:
            print(argv[0] + " format error, try exec \"help\"")
            return
        address = argv[1]
        coding = "utf8"
        if re.match(RE_EVAL_EXPRESS, address):
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
        if self.script.exports.stop_auto_show_view():
            print(GREEN("Open Success"))
        else:
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
        if re.match(RE_EVAL_EXPRESS, address):
            address = str(hex(eval(address)))
        if len(argv) > 2:
            size = argv[2]
            size = self.toAddress(size)
        value = self.script.exports.hexdump(address, size)


MENU = '''
    Usage : [options] [value] [--]

        Options:

-------------------------------- SHELL -------------------------------
        h|help                                  Display this message
        v|version                               Display script version
        q|quit                                  Exit YJ
        cl|clear                                Clean screen
        ls                                      Display current list
        pwd                                     Display current path
        ![python]                               Exec python code
        %[shell]                                Exec shell code

-------------------------------- YJ ----------------------------------
        r|run                                   Continue spawn model attach
        m|main                                  Display all view
        k|kill                                  Disable auto display all view
        t|trace [accurate/fuzzy]                Display called function list view(default accurate)
        p|print [pointer]                       Display pointer value
        x|hex [pointer]                         Display pointer hexadecimal value
        s|string [pointer]                      Print target address character(default utf-8)
        hd|hexdump [pointer]                    Display target memory space
        tele|telescope [pointer]                Display multiple line memory space
        lib|so                                  Print current target dynamic library base address
        f|find [functionName]                   Find function source information by function name(support "*" wildcard character)
        b|breakpoint [offset]                   Attach break point by lib offset address , must exist cache(default is the last used lib)
        b|breakpoint [address]                  Attach break point by real address
        b|breakpoint [functionName]             Attach break point by unique funcation name,support "*" wildcard character
        b|breakpoint [offset] [targetLibName]   Attach break point by lib offset and libName
        b|breakpoint [address] [targetLibName]  Attach break point by real address and libName
        i|info [b|breakpoints]                  Print current all break address
        i|info [w|watch]                        Print all watch target
        i|info [so|lib]                         Print all loaded dynamic library
        i|info [f|fun] [lib name]               Print target lib all functions
        i|info [d|debugsymbol] [name|address]   Print target debug symbol info
        i|info [jni]                            Print all jni functions
        d|delete [breakpoint]                   Delete break address
        w|watch [address]                       Monitor target memory space. callback snooping exists
        uw|unwatch [address]                    Disable monitor target memory space(default disable all monitor)
        wf|writefile [pointer] [size] [name]    Write memory data to a file(default output file in phone -> /sdcard/yj-[%time].dat , ensure that the process has permissions)
        hf|hookfunction                         Hook all functions of a single class in the java level
        expr [calculation expression]           Calculation expression result
    '''
