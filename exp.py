#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from style.layout import *
import frida,sys


if (len(sys.argv) < 3):
    print("\033[31mPlease input script\033[0m, such as ->\033[32m python3 exp.py script.js\033[0m")
    exit(0)

HOOK_TARGET_APP_NAME = sys.argv[1]
MAIN_File = sys.argv[2]

layout = LayoutView() #Init Sytle Theme

def on_message(message,data):
    if message['type'] == 'send':
        layout.check_is_view_tag(message)
        if(layout.check_is_need_clear_view()==True):
            return
        if(layout.check_is_init_segment_address() == True):
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
            layout.payload = str(message['payload']) #还原数组
            print("\033[31m{0}\033[0m".format(layout.payload))
    else:
        print(message)

device = frida.get_usb_device()
process = device.attach(HOOK_TARGET_APP_NAME)
process.enable_debugger()
#pid = device.spawn("com.android.providers.downloads.ui", activity="com.android.providers.downloads.ui.DownloadList") #使用挂起调试时才用

foot = ""
with open(MAIN_File) as jscode:
    foot += jscode.read()
with open("./commond/util.js") as jscode:
    foot += jscode.read()

script = process.create_script(foot,runtime='v8')
script.on('message',on_message)
script.load()
show_head_view_tips_info_color()
script.exports.init(LayoutView.mjson) #对应js脚本的hook函数init()
#device.resume(pid)  #对应挂起函数调用
#sys.stdin.read()

chose='''
Usage : [options] [value] [--]

    Options:
    h|help          Display this message
    v|version       Display script version
    q|quit          Exit frida
    cl|clear        Clean screen
    ls              Display current list
    p               Display pointer value
    x               Display pointer hexadecimal value
    tele|telescope  Display multiple line memory space
'''

#====================Call JavaScript function====================
def telescope(argv):
    script.exports.telescope(argv[0])

def print_address(argv,carry=10):
    value = script.exports.readpointer(argv[0])
    if carry == 16:
        print(str(argv[0]) + " -> " + value)
    else:
        print(str(int(value,16)))
#========================= End =========================

LOGO = "\033[31mYJ ➤ \033[0m"

while True:
    cmd = input(LOGO)
    if (cmd == "" or cmd.isspace()):
        continue
    argv = cmd.split()

    if len(argv) > 1:
        cmd = argv[0]
        del(argv[0])
    else:
        argv = None

    if (cmd == "help" or cmd == "h"):
        print(chose)
        continue
    #==================== Shell command ====================
    if (cmd == "quit" or cmd == "q"):
        break
    elif(cmd == "clear" or cmd == "cl"):
        os.system("clear")
    elif(cmd == "ls"):
        os.system(cmd)
    #==================== Frida command ====================
    elif(cmd == "p" and (not argv is None)):
        print_address(argv,10)
    elif(cmd == "x" and (not argv is None)):
        print_address(argv,16)
    elif((cmd == "telescope" or cmd == "tele") and (not argv is None)):
        telescope(argv)
    else:
        print("Option does not exist : \"%s\".  Try \"help\"" % cmd)


