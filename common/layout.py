#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import json
import os
import traceback
import re


class LayoutView:
    def __init__(self):
        get_config_info()
        self.payload = ""
        self.width = int(os.get_terminal_size().columns)
        self.stack_base = 0
        self.code_base = 0
        self.step = 4

    # 显示一条分割线
    def show_line_view(self):
        print("\n"+"─"*int(self.width - LayoutView.end_line_len - int(len(LayoutView.message_tag))
                      ) + CYAN(LayoutView.message_tag) + "─"*LayoutView.end_line_len+"\n")

    def check_is_need_clear_view(self):
        if LayoutView.clear_tag in self.payload:
            print("\n"*100)
            print(GREEN(LayoutView.wecome))
            show_head_view_tips_info_color()
            return True
        else:
            return False

    # 检查是否需要改变分割线的标签
    def check_is_view_tag(self, message):
        self.payload
        mtype = type(message['payload'])
        if (mtype == list):
            self.payload = str(message['payload'][1])  # [1]有值则表示需要改变tag名
        elif (mtype == str):
            self.payload = message['payload']
        elif (mtype == dict):
            self.payload = message['payload']
        else:
            self.payload = message['payload']
        self.update_is_view_tag()

    # 改变分割线的标签
    def update_is_view_tag(self):
        if LayoutView.view_registers in self.payload:
            LayoutView.message_tag = LayoutView.view_registers
        elif LayoutView.view_stack in self.payload:
            LayoutView.message_tag = LayoutView.view_stack
        elif LayoutView.view_code in self.payload:
            LayoutView.message_tag = LayoutView.view_code
        elif LayoutView.view_trace in self.payload:
            LayoutView.message_tag = LayoutView.view_trace
        elif LayoutView.view_telescope in self.payload:
            LayoutView.message_tag = LayoutView.view_telescope
        else:
            LayoutView.message_tag = " send "

    # 重置数据索引
    def reset_send_payload(self, message):
        mtype = type(message['payload'])
        if (mtype == list):
            self.payload = str(message['payload'][0])  # 这里使用数组的数据块
        elif (mtype == str):
            self.payload = message['payload']
        elif (mtype == dict):
            self.payload = message['payload']
        else:
            self.payload = message['payload']

    # 格式化显示tele格式的地址内存信息
    def show_tele_view(self):
        split = self.payload.split(LayoutView.tele_tag)
        for i in range(len(split)-1):
            data = split[i].split("│")
            # isPointer = False
            isString = False
            # isInstruction = False
            try:
                pointer = int(data[2], 16)
            except:
                # isPointer = False
                isString = True
                # isInstruction = False

            if isString == True:  # 指针为字符串表示不需要进行探测多级指针
                update_show_text_view_style(
                    data, LayoutView.color_format_value_yellow, LayoutView.tele_tag, self.step)
                continue

            if (pointer == 0):  # 值为0 显示灰色
                update_show_text_view_style(
                    data, LayoutView.color_format_value_grey, LayoutView.tele_tag, self.step)
            elif (self.stack_base != 0 and hex(pointer >> 16 << 16) == self.stack_base):
                update_show_text_view_style(
                    data, LayoutView.color_format_value_pink, LayoutView.tele_tag, self.step)
            elif (self.code_base != 0 and hex(pointer >> 16 << 16) == self.code_base):
                update_show_text_view_style(
                    data, LayoutView.color_format_value_red, LayoutView.tele_tag, self.step)
            else:
                update_show_text_view_style(
                    data, LayoutView.color_format_value_bule, LayoutView.tele_tag, self.step)

    # 格式化显示registers内存信息
    def show_registers_view(self):
        split = self.payload.split(LayoutView.register_tag)
        for i in range(len(split)-1):
            data = split[i].split("│")
            # print(data)
            # isPointer = False
            isString = False
            # isInstruction = False
            try:
                int(data[2], 16)
            except:
                # isPointer = False
                isString = True
                # isInstruction = False

            if isString == True:  # 指针为字符串表示不需要进行探测多级指针
                update_show_text_view_style(
                    data, LayoutView.color_format_value_yellow, LayoutView.register_tag, self.step)
                continue

            try:
                pointer = int(data[1], 16)
            except:
                traceback.print_exc()

            if (pointer == 0):
                update_show_text_view_style(
                    data, LayoutView.color_format_value_grey, LayoutView.register_tag, self.step)
            elif (self.stack_base != 0 and hex(pointer >> 16 << 16) == self.stack_base):
                update_show_text_view_style(
                    data, LayoutView.color_format_value_pink, LayoutView.register_tag, self.step)
            elif (self.code_base != 0 and hex(pointer >> 16 << 16) == self.code_base):
                update_show_text_view_style(
                    data, LayoutView.color_format_value_red, LayoutView.register_tag, self.step)
            else:
                update_show_text_view_style(
                    data, LayoutView.color_format_value_bule, LayoutView.register_tag, self.step)

    # 显示函数调用栈视图
    def show_trace_view(self):
        split = self.payload.split(LayoutView.trace_tag)[0].split("\n")
        for i in range(len(split)-1):
            data = split[i].split(" ")
            if ((len(data) >= 2) and (not data[1] is None)):
                print(("[" + PINK("#{0}") + "] " + "{1} → " +
                      GREEN("{2}")).format(i, data[0], data[1]))

    # 格式化代码段视图
    def show_code_view(self):
        split = self.payload.split(LayoutView.code_tag)
        _json = json.loads(split[0])
        offset = str(hex((_json["offset"]))).replace("0x", "")
        result = dump_target_binary(
            _json["path"], _json['name'], LayoutView.code_show_row_number, offset)
        for i in range(len(result)):
            data = result[i].replace(" ", "").replace(
                "\t", " ").replace("\n", "")
            if (i < int(LayoutView.code_show_row_number, 10)):
                print("   0x{0}".format(data))
            elif (i == int(LayoutView.code_show_row_number, 10)):
                print(" → " + GREEN("0x{0}").format(data))
            else:
                print(WHITE("   0x{0}").format(data))

    # 检查是只是初始化值
    def check_is_init_segment_address(self):
        if LayoutView.init_segment_address_tag in self.payload:
            stack = self.payload.split(LayoutView.init_segment_address_tag)[0]
            code = self.payload.split(LayoutView.init_segment_address_tag)[1]
            LayoutView.view_code = self.payload.split(
                LayoutView.init_segment_address_tag)[2]
            self.step = self.payload.split(
                LayoutView.init_segment_address_tag)[3]
            self.stack_base = hex(int(stack, 16) >> 16 << 16)
            self.code_base = hex(int(code, 16) >> 16 << 16)
            return True
        else:
            return False


# --------------------获取配置信息--------------------
def get_config_info():
    with open('./style/config.json', 'r') as file:
        mjson = json.load(file)
    LayoutView.mjson = mjson
    LayoutView.end_line_len = mjson['end_line_len']
    LayoutView.code_show_row_number = mjson['code_show_row_number']
    LayoutView.isAutoShowView = mjson['isAutoShowView']
    LayoutView.view_stack = mjson['view_stack']
    LayoutView.view_code = mjson['view_code']
    LayoutView.view_trace = mjson['view_trace']
    LayoutView.view_registers = mjson['view_registers']
    LayoutView.view_telescope = mjson['view_telescope']

    LayoutView.clear_tag = mjson['clear_tag']
    LayoutView.message_tag = mjson['message_tag']
    LayoutView.tele_tag = mjson['tele_tag']
    LayoutView.register_tag = mjson['register_tag']
    LayoutView.code_tag = mjson['code_tag']
    LayoutView.trace_tag = mjson['trace_tag']
    LayoutView.init_segment_address_tag = mjson['init_segment_address_tag']

    LayoutView.color_format_value_grey = mjson['color_format_value_grey']
    LayoutView.color_format_value_red = mjson['color_format_value_red']
    LayoutView.color_format_value_green = mjson['color_format_value_green']
    LayoutView.color_format_value_yellow = mjson['color_format_value_yellow']
    LayoutView.color_format_value_bule = mjson['color_format_value_bule']
    LayoutView.color_format_value_pink = mjson['color_format_value_pink']
    LayoutView.color_format_value_cyan = mjson['color_format_value_cyan']

    LayoutView.wecome = """
     _      _______________  _  ____  _______  __  __   __
    | | /| / / __/ ___/ __ \/ |/ /  |/  / __/  \ \/ /_ / /
    | |/ |/ / _// /__/ /_/ /    / /|_/ / _/     \  / // /
    |__/|__/___/\___/\____/_/|_/_/  /_/___/     /_/\___/
    """
    LayoutView.banner = """
¦   ¦   ¦   ¦   ¦   ¦   ¦__..--.._
    ¦ .....              .--~  .....  `.
    .":    "`-..  .    .' ..-'"    :". `
    ` `._ ` _.'`"(     `-"'`._ ' _.' '
    ¦   ¦~~~      `.          ~~~
    ¦   ¦   ¦   ¦ .'
    ¦   ¦   ¦   ¦/
    ¦   ¦   ¦   (
    ¦   ¦   ¦   ¦^---'
    """
    print(RED(LayoutView.banner))

# 获取目标源文件，进行反汇编代码获取


def dump_target_binary(path, lib_name, row, offset):
    result = os.popen("./common/get_target_binary.sh " +
                      path + " " + lib_name + " " + row + " " + offset)
    return result.readlines()


# 显示头部颜色代表数据说明信息
def show_head_view_tips_info_color():
    head_tips = "[ Legend: " + RED("%s") + " | " + RED("%s") + \
        " | "+GREEN("%s") + " | "+PINK("%s")+" | "+YELLOW("%s") + " ]"
    print(head_tips % ("Modified register", "Code", "Heap", "Stack", "String"))


def GREY(text):
    return "\033[0m"+str(text)+"\033[0m"


def RED(text):
    return "\033[31m"+str(text)+"\033[0m"


def GREEN(text):
    return "\033[32m"+str(text)+"\033[0m"


def YELLOW(text):
    return "\033[33m"+str(text)+"\033[0m"


def BLUE(text):
    return "\033[34m"+str(text)+"\033[0m"


def PINK(text):
    return "\033[35m"+str(text)+"\033[0m"


def CYAN(text):
    return "\033[36m"+str(text)+"\033[0m"


def WHITE(text):
    return "\033[37m"+str(text)+"\033[0m"


def PURPLE(text):
    return "\033[95m"+str(text)+"\033[0m"


ADDRESS_JUMP_STEP_COUNT_FORMAT = "0x%04x"
BIT_32_COUNT_FORMAT = "0x%08x"
BIT_64_COUNT_FORMAT = "0x%014x"

# 改变文字的颜色


def update_show_text_view_style(data, color, types, step="4"):
    _format = BIT_64_COUNT_FORMAT
    if step == "4":
        _format = BIT_32_COUNT_FORMAT
    one = data[0]  # Could be String($pc) or Interger(0x...)
    two = data[1]  # Could be Address or Step or String
    if len(data) > 2:
        three = data[2]
    if len(data) > 3:
        four = data[3]

    if (types == LayoutView.tele_tag):
        if (color == LayoutView.color_format_value_pink or
           color == LayoutView.color_format_value_red):
            print((CYAN("{0}") + "│+{1}: " + "\033[{3}m{2}\033[0m  →  {4}").format(
                one, ADDRESS_JUMP_STEP_COUNT_FORMAT % int(two, 10), _format % int(three, 16), color, _format % int(four, 16)))
        elif (color == LayoutView.color_format_value_yellow):
            print((CYAN("{0}") + "│+{1}: \033[{3}m{2}\033[0m").format(
                one, ADDRESS_JUMP_STEP_COUNT_FORMAT % int(two, 10), repr(three), color))
        else:
            print((CYAN("{0}") + "│+{1}: \033[{3}m{2}\033[0m").format(
                one, ADDRESS_JUMP_STEP_COUNT_FORMAT % int(two, 10), _format % int(three, 16), color))
    elif (types == LayoutView.register_tag):
        if (color == LayoutView.color_format_value_pink or
           color == LayoutView.color_format_value_red):
            print((RED("${0}") + "  : \033[{2}m{1}\033[0m  →  {3}").format(
                "{:<4s}".format(one), _format % int(two, 16), color, _format % int(three, 16)))
        elif (color == LayoutView.color_format_value_yellow):
            print((RED("${0}") + "  : \033[{2}m{1}\033[0m  →  \033[{2}m{3}\033[0m").format(
                "{:<4s}".format(one), _format % int(two, 16), color, repr(three)))
        else:
            print((RED("${0}") + "  : \033[{2}m{1}\033[0m").format(
                "{:<4s}".format(one), _format % int(two, 16), color))
    else:
        return


def format_breakpoint(content):
    try:
        split = content.split('!')
        lib_name = split[0]
        offset = split[1]
        if (re.match('lib.*\.so', lib_name) is None) or \
                (re.match('0x.*', offset) is None):
            raise Error()
    except:
        return []
    return [lib_name, offset]
