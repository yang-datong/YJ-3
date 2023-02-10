#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from style.layout import *
import frida,sys


if (len(sys.argv) < 2):
    print("\033[31mPlease input script\033[0m, such as ->\033[32m python3 exp.py script.js\033[0m")
    exit(0)

mainFile = sys.argv[1]

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
process = device.attach('抖音')
process.enable_debugger()
#pid = device.spawn("com.android.providers.downloads.ui", activity="com.android.providers.downloads.ui.DownloadList") #使用挂起调试时才用

foot = ""
with open(mainFile) as jscode:
    foot += jscode.read()
with open("./commond/util.js") as jscode:
    foot += jscode.read()

script = process.create_script(foot,runtime='v8')
script.on('message',on_message)
script.load()
show_head_view_tips_info_color()
script.exports.init(LayoutView.mjson) #对应js脚本的hook函数init()
#device.resume(pid)  #对应挂起函数调用
sys.stdin.read()

