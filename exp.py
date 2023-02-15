#!/usr/local/bin/python3.9
# -*- coding: UTF-8 -*-
from common.cmd import *
import frida
import argparse

MAIN_SCRIPT_FILE = "model/main.js"
LAYOUT_SCRIPT_FILE = "common/layout.js"
UTILITY_SCRIPT_FILE = "common/utility.js"

parser = argparse.ArgumentParser()
parser.add_argument('app', help='target application')
parser.add_argument('-b', '--breakpoint', help='set breakpoint')
parser.add_argument('-s', '--spawn-model',
                    action='store_true', help='launch spawn model')
parser.add_argument('-l', '--load', default=MAIN_SCRIPT_FILE,
                    help='load custom script')

args = parser.parse_args()

if not args.breakpoint is None:
    if len(format_breakpoint(args.breakpoint)) == 0:
        print(RED("set breakpoint parameter type mismatch, ") +
              GREEN("E.g -> '-b lib**.so!0x***'"))
        exit(0)

MAIN_SCRIPT_FILE = args.load
HOOK_TARGET_APP = args.app

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

# Get all process
# print(device.enumerate_processes())

# open -spawn_model use spawn attach application
if args.spawn_model:
    pid = device.get_process(HOOK_TARGET_APP).pid
    pack = os.popen(
        "adb shell \"ps -p %s -w | grep %s | awk '{print \$NF}'\"" % (pid, pid)).readlines()[0]
    HOOK_TARGET_APP = device.spawn(pack.replace('\n', ''))

process = device.attach(HOOK_TARGET_APP)
process.enable_debugger()

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

# Whether need to set pre-breakpoint
if not args.breakpoint is None:
    info = format_breakpoint(args.breakpoint)
    script.exports.set_breakpoint(info[1], info[0])

# Into Interaction Model
it = Interaction(device, script, args.spawn_model, HOOK_TARGET_APP)
it.start()
