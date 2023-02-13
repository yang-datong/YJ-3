#!/usr/local/bin/python3.9
# -*- coding: UTF-8 -*-
from common.layout import *
import frida
import sys
import re
import argparse
import readline

MAIN_SCRIPT_FILE = "model/main.js"
LAYOUT_SCRIPT_FILE = "common/layout.js"
UTILITY_SCRIPT_FILE = "common/utility.js"

parser = argparse.ArgumentParser()
parser.add_argument('-n', '--app-name', help='set target application')
parser.add_argument('-s', '--script', default=MAIN_SCRIPT_FILE,
                    help='load custom script file')

args = parser.parse_args()
MAIN_SCRIPT_FILE = args.script
HOOK_TARGET_APP_NAME = args.app_name

if HOOK_TARGET_APP_NAME is None:
    print("Try exec -> \"python3 " + sys.argv[0] + " -h\"")
    exit(0)

# -------------------------- Main --------------------------
layout = LayoutView()  # Initialization style theme


def on_message(message, data):
    if message['type'] == 'send':
        layout.check_is_view_tag(message)
        if (layout.check_is_need_clear_view() == True):
            return
        if (layout.check_is_init_segment_address() == True):
            return
        layout.show_line_view()
        layout.reset_send_payload(message)
        if LayoutView.tele_tag in layout.payload:
            layout.show_tele_view()
        elif LayoutView.register_tag in layout.payload:
            layout.show_registers_view()
        elif LayoutView.code_tag in layout.payload:
            layout.show_code_view()
        elif LayoutView.trace_tag in layout.payload:
            layout.show_trace_view()
        else:
            layout.payload = str(message['payload'])  # 还原数组
            print("\033[31m{0}\033[0m".format(layout.payload))
    else:
        print(message)


device = frida.get_usb_device()
process = device.attach(HOOK_TARGET_APP_NAME)
process.enable_debugger()
# pid = device.spawn("com.android.providers.downloads.ui", activity="com.android.providers.downloads.ui.DownloadList") #使用挂起调试时才用

with open(MAIN_SCRIPT_FILE) as jscode:
    foot = jscode.read()
with open(LAYOUT_SCRIPT_FILE) as jscode:
    foot += jscode.read()
with open(UTILITY_SCRIPT_FILE) as jscode:
    foot += jscode.read()

script = process.create_script(foot, runtime='v8')
script.on('message', on_message)
script.load()
show_head_view_tips_info_color()
script.exports.init(LayoutView.mjson)  # 对应js脚本的hook函数init()
# device.resume(pid)  #对应挂起函数调用

chose = '''
Usage : [options] [value] [--]

    Options:
    h|help                      Display this message
    v|version                   Display script version
    q|quit                      Exit frida
    cl|clear                    Clean screen
    ls                          Display current list
    m|main                      Display all view
    lib                         Print current target dynamic library base address
    b [address] [targetLibName] Set target lib and break point
    t|trace [accurate/fuzzy]    Display called function list(default fuzzy)
    p [pointer]                 Display pointer value
    x [pointer]                 Display pointer hexadecimal value
    b|breakpoints               Add break pointer
    i|info [b|breakpoints]      Print current all break pointer
    d|delete [breakpoint]       Delete break pointer
    hd|hexdump [pointer]        Display target memory space
    tele|telescope [pointer]    Display multiple line memory space
    s|string [pointer]          Print target address character(default utf-8)
'''

# -------------------- Call JavaScript function --------------------
RE_MATH_EVAL = '(0x)?[0-9a-z]{4,16}(\+|\-)\d'


def telescope(argv):
    address = argv[0]
    if (not re.match(RE_MATH_EVAL, address) is None):
        address = str(hex(eval(address)))
    script.exports.telescope(address)


def print_address(argv, carry=10):
    address = argv[0]
    if (not re.match(RE_MATH_EVAL, address) is None):
        address = str(hex(eval(address)))
    value = script.exports.read_pointer(address)
    if carry == 16:
        print(address + " -> " + value)
    else:
        print(str(int(value, 16)))


def set_breakpoint(argv):
    address = argv[0]
    targetLibName = None
    if len(argv) > 1:
        targetLibName = argv[1]
    script.exports.set_breakpoint(address, targetLibName)


def display_breakpoints_info(argv):
    show_type = argv[0]
    if show_type == "b" or show_type == "breakpoints":
        breakpoints = script.exports.get_breakpoints()
        breakpoints = breakpoints.split()
        print("{0:^5s} {1:^16s} {2:^16s} {3:^16s}".format(
            "Num", "Type", "Address", "What"))
        print("{0:^5s} {1:^16s} {2:^25s} {3:^25s}".format(
            "1", "breakpoint", BLUE(breakpoints[0]), GREEN(breakpoints[1])))


def delete_breakpoint(argv):
    address = argv[0]
    script.exports.delete_breakpoint(address)
    print(GREEN("Cleaed all breakPointer"))


def read_String(argv):
    address = argv[0]
    coding = "utf8"
    if (not re.match(RE_MATH_EVAL, address) is None):
        address = str(hex(eval(address)))
    if len(argv) > 1:
        coding = argv[1]
    string = script.exports.read_string(address, coding)
    if string.find("Error") != -1:
        print(RED(string))
    else:
        print(YELLOW("\"" + string + "\""))


def show_all_view():
    script.exports.show_all_view()


def libc_base_address():
    address = script.exports.libc_base_address()
    print(BLUE("libc :") + WHITE(" %s") % address)


def trace(argv):
    if argv is None:
        script.exports.trace()
    elif ((not argv[0] is None) and (argv[0] == "f" or argv[0] == "fuzzy")):
        script.exports.trace("FUZZY")


def hexdump(argv):
    address = argv[0]
    size = 0x30
    if (not re.match(RE_MATH_EVAL, address) is None):
        address = str(hex(eval(address)))
    if (len(argv) > 1):
        size = argv[1]
        try:
            size = int(size, 10)
        except:
            size = int(size, 16)

    value = script.exports.phexdump(address, size)


# ------------------------ Interaction Model ------------------------
LOGO = RED("\nYJ ➤ ")

while True:
    cmd = input(LOGO)
    if (cmd == "" or cmd.isspace()):
        continue
    argv = cmd.split()

    if len(argv) > 1:
        cmd = argv[0]
        del (argv[0])
    else:
        argv = None

    if (cmd == "help" or cmd == "h"):
        print(chose)
        continue
    # -------------------- Shell command --------------------
    if (cmd == "quit" or cmd == "q"):
        sys.exit(0)
    elif (cmd == "clear" or cmd == "cl"):
        os.system("clear")
    elif (cmd == "ls"):
        os.system("ls --color")
    # -------------------- Frida command --------------------
    elif (cmd == "main" or cmd == "m"):
        show_all_view()
    elif (cmd == "lib"):
        libc_base_address()
    elif (cmd == "trace" or cmd == "t"):
        trace(argv)
    elif (cmd == "p" and (not argv is None)):
        print_address(argv, 10)
    elif (cmd == "x" and (not argv is None)):
        print_address(argv, 16)
    elif ((cmd == "b" or cmd == "breakpoints")
          and (not argv is None)):
        set_breakpoint(argv)
    elif ((cmd == "i" or cmd == "info")
          and (not argv is None)):
        display_breakpoints_info(argv)
    elif ((cmd == "d" or cmd == "delete")
          and (not argv is None)):
        delete_breakpoint(argv)
    elif ((cmd == "hexdump" or cmd == "hd") and (not argv is None)):
        hexdump(argv)
    elif ((cmd == "telescope" or cmd == "tele") and (not argv is None)):
        telescope(argv)
    elif ((cmd == "string" or cmd == "s") and (not argv is None)):
        read_String(argv)
    else:
        print("Option does not exist : \"%s\".  Try \"help\"" % cmd)
